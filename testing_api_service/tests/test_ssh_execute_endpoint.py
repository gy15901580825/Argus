"""L3 tests for `/ssh-config` (HTML) and `/ssh/execute` (SSH + R2 upload).

The `/ssh/execute` endpoint:
  1. Validates remote_ip + username via SSHConfigRequest.
  2. Reads PEM file from upload into memory.
  3. Runs pytest via RemoteExecutor.execute().
  4. Downloads allure-results via SFTP, zips, uploads to R2.
  5. Returns stdout/stderr/exit_code/allure_results_url.

We patch the RemoteExecutor class and CloudflareR2Manager class at the
server module boundary.
"""
from __future__ import annotations

import io
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    import server
    with TestClient(server.app) as c:
        yield c


# ---------------------------------------------------------------------------
# /ssh-config (GET, HTML)
# ---------------------------------------------------------------------------

def test_ssh_config_page_renders_html(client):
    resp = client.get("/ssh-config")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]


# ---------------------------------------------------------------------------
# /ssh/execute: input validation
# ---------------------------------------------------------------------------

def test_ssh_execute_bad_ip_returns_validation_error(client):
    resp = client.post(
        "/ssh/execute",
        data={"remote_ip": "not-an-ip", "username": "ubuntu"},
        files={"pem_file": ("id_rsa", b"-----BEGIN KEY-----\nfake\n", "text/plain")},
    )
    assert resp.status_code == 200  # endpoint returns error in body
    body = resp.json()
    assert body["success"] is False
    assert "Validation error" in body["error"]


def test_ssh_execute_bad_username_returns_validation_error(client):
    resp = client.post(
        "/ssh/execute",
        data={"remote_ip": "10.0.0.1", "username": "user with spaces"},
        files={"pem_file": ("id_rsa", b"x", "text/plain")},
    )
    body = resp.json()
    assert body["success"] is False
    assert "Validation error" in body["error"]


# ---------------------------------------------------------------------------
# /ssh/execute: happy path with SSH + allure upload
# ---------------------------------------------------------------------------

def test_ssh_execute_happy_path_returns_stdout_and_allure_url(client, tmp_path):
    # Fake RemoteExecutor that behaves like a context manager
    fake_exec = MagicMock()
    fake_exec.execute.return_value = {
        "stdout": "=== 3 passed ===", "stderr": "", "exit_code": 0
    }

    def _download(remote, local):
        # Simulate download by creating a file in local
        import os
        os.makedirs(local, exist_ok=True)
        with open(f"{local}/result.json", "w") as f:
            f.write('{"ok": true}')

    fake_exec.download_directory.side_effect = _download
    fake_exec.__enter__ = MagicMock(return_value=fake_exec)
    fake_exec.__exit__ = MagicMock(return_value=False)
    fake_exec_cls = MagicMock(return_value=fake_exec)

    # Fake R2 manager
    fake_r2 = MagicMock()
    fake_r2.upload_file_object.return_value = {
        "success": True,
        "object_key": "allure-results/10.0.0.1/1/allure-results.zip",
        "download_url": "https://pub.invalid/allure.zip",
    }
    fake_r2.generate_presigned_url.return_value = {
        "success": True,
        "presigned_url": "https://pub.invalid/presigned?sig=x",
    }
    fake_r2_cls = MagicMock(return_value=fake_r2)

    with patch("server.RemoteExecutor", fake_exec_cls), \
         patch("server.CloudflareR2Manager", fake_r2_cls):
        resp = client.post(
            "/ssh/execute",
            data={
                "remote_ip": "10.0.0.1",
                "username": "ubuntu",
                "pytest_args": "-v",
            },
            files={
                "pem_file": (
                    "id_rsa",
                    b"-----BEGIN FAKE KEY-----\nPRIVATEDATA\n",
                    "text/plain",
                )
            },
        )

    assert resp.status_code == 200
    body = resp.json()
    assert body["success"] is True
    assert body["stdout"] == "=== 3 passed ==="
    assert body["exit_code"] == 0
    assert body["allure_results_url"] == "https://pub.invalid/presigned?sig=x"

    # RemoteExecutor constructed with decoded PEM (as plain string — raw file bytes)
    ctor_kwargs = fake_exec_cls.call_args.kwargs
    assert ctor_kwargs["host"] == "10.0.0.1"
    assert ctor_kwargs["username"] == "ubuntu"
    assert "-----BEGIN FAKE KEY-----" in ctor_kwargs["pkey_data"]
    # pytest invocation uses -v
    fake_exec.execute.assert_called_with("pytest -v")


def test_ssh_execute_returns_success_true_even_if_allure_download_fails(client):
    """Allure download failures are non-fatal — main result still returned."""
    fake_exec = MagicMock()
    fake_exec.execute.return_value = {
        "stdout": "1 failed", "stderr": "err", "exit_code": 1
    }
    fake_exec.download_directory.side_effect = RuntimeError("SFTP broken")
    fake_exec.__enter__ = MagicMock(return_value=fake_exec)
    fake_exec.__exit__ = MagicMock(return_value=False)
    fake_exec_cls = MagicMock(return_value=fake_exec)

    fake_r2_cls = MagicMock()  # Never called (allure download fails first)

    with patch("server.RemoteExecutor", fake_exec_cls), \
         patch("server.CloudflareR2Manager", fake_r2_cls):
        resp = client.post(
            "/ssh/execute",
            data={"remote_ip": "10.0.0.1", "username": "ubuntu"},
            files={"pem_file": ("id", b"pem", "text/plain")},
        )

    body = resp.json()
    # The try/except around allure download means overall success=True, but
    # allure_results_url is None
    assert body["success"] is True
    assert body["allure_results_url"] is None
    assert body["exit_code"] == 1


def test_ssh_execute_connect_failure_returns_error(client):
    """If RemoteExecutor construction/enter raises, endpoint returns success=False."""
    fake_exec = MagicMock()
    fake_exec.__enter__ = MagicMock(side_effect=RuntimeError("connect refused"))
    fake_exec.__exit__ = MagicMock(return_value=False)
    fake_exec_cls = MagicMock(return_value=fake_exec)

    with patch("server.RemoteExecutor", fake_exec_cls):
        resp = client.post(
            "/ssh/execute",
            data={"remote_ip": "10.0.0.1", "username": "ubuntu"},
            files={"pem_file": ("id", b"pem", "text/plain")},
        )

    body = resp.json()
    assert body["success"] is False
    assert "connect refused" in body["error"]
