"""argus.server: bearer token on /redteam/* and the bind-address startup guard."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(monkeypatch):
    monkeypatch.delenv("ARGUS_SERVER_TOKEN", raising=False)
    from argus.server import app

    return TestClient(app)


def test_no_token_configured_leaves_redteam_open(client):
    resp = client.get("/redteam/probes")
    assert resp.status_code == 200
    assert resp.json()["probe_ids"]


@pytest.mark.parametrize("path", ["/redteam/probes", "/redteam/suites", "/redteam/coverage"])
def test_token_configured_rejects_missing_header(client, monkeypatch, path):
    monkeypatch.setenv("ARGUS_SERVER_TOKEN", "right-token")
    resp = client.get(path)
    assert resp.status_code == 401
    assert resp.headers["www-authenticate"] == "Bearer"


@pytest.mark.parametrize("header", [
    "Bearer wrong-token",
    "Bearer right-token-extra",
    "Basic right-token",
    "right-token",
    "Bearer ",
])
def test_token_configured_rejects_wrong_header(client, monkeypatch, header):
    monkeypatch.setenv("ARGUS_SERVER_TOKEN", "right-token")
    resp = client.get("/redteam/probes", headers={"Authorization": header})
    assert resp.status_code == 401


def test_token_configured_accepts_right_header(client, monkeypatch):
    monkeypatch.setenv("ARGUS_SERVER_TOKEN", "right-token")
    resp = client.get("/redteam/probes", headers={"Authorization": "Bearer right-token"})
    assert resp.status_code == 200
    assert resp.json()["probe_ids"]


def test_bearer_scheme_is_case_insensitive(client, monkeypatch):
    monkeypatch.setenv("ARGUS_SERVER_TOKEN", "right-token")
    resp = client.get("/redteam/probes", headers={"Authorization": "bearer right-token"})
    assert resp.status_code == 200


def test_post_routes_are_guarded_before_body_validation(client, monkeypatch):
    monkeypatch.setenv("ARGUS_SERVER_TOKEN", "right-token")
    assert client.post("/redteam/run", json={}).status_code == 401
    assert client.post("/redteam/run/preflight", json={}).status_code == 401


@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json"])
def test_docs_routes_stay_open(client, monkeypatch, path):
    monkeypatch.setenv("ARGUS_SERVER_TOKEN", "right-token")
    assert client.get(path).status_code == 200


# --------------------------------------------------------------------------
# startup guard
# --------------------------------------------------------------------------

@pytest.mark.parametrize("host", ["127.0.0.1", "127.0.0.2", "::1", "localhost"])
def test_loopback_without_token_may_start(host):
    from argus.server import startup_error

    assert startup_error(host, token="", allow_unauthenticated=False) is None


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "10.0.0.5", "my-host.example"])
def test_non_loopback_without_token_is_refused(host):
    from argus.server import startup_error

    msg = startup_error(host, token="", allow_unauthenticated=False)
    assert msg is not None
    assert host in msg
    assert "ARGUS_SERVER_TOKEN" in msg
    assert "ARGUS_SERVER_ALLOW_UNAUTHENTICATED=1" in msg


def test_non_loopback_with_token_may_start():
    from argus.server import startup_error

    assert startup_error("0.0.0.0", token="t", allow_unauthenticated=False) is None


def test_non_loopback_with_explicit_opt_out_may_start():
    from argus.server import startup_error

    assert startup_error("0.0.0.0", token="", allow_unauthenticated=True) is None


def test_main_exits_nonzero_on_unsafe_bind(monkeypatch, capsys):
    import argus.server as server

    monkeypatch.setenv("ARGUS_SERVER_HOST", "0.0.0.0")
    monkeypatch.delenv("ARGUS_SERVER_TOKEN", raising=False)
    monkeypatch.delenv("ARGUS_SERVER_ALLOW_UNAUTHENTICATED", raising=False)
    started = []
    monkeypatch.setattr("uvicorn.run", lambda *a, **kw: started.append(kw))
    with pytest.raises(SystemExit) as exc:
        server.main()
    assert exc.value.code == 1
    assert "ARGUS_SERVER_TOKEN" in capsys.readouterr().err
    assert started == []


def test_main_binds_loopback_by_default(monkeypatch):
    import argus.server as server

    for name in ("ARGUS_SERVER_HOST", "ARGUS_SERVER_TOKEN", "ARGUS_SERVER_ALLOW_UNAUTHENTICATED", "PORT"):
        monkeypatch.delenv(name, raising=False)
    started = []
    monkeypatch.setattr("uvicorn.run", lambda *a, **kw: started.append(kw))
    server.main()
    assert started[0]["host"] == "127.0.0.1"
    assert started[0]["port"] == 8080


def test_main_binds_configured_host_with_token(monkeypatch):
    import argus.server as server

    monkeypatch.setenv("ARGUS_SERVER_HOST", "0.0.0.0")
    monkeypatch.setenv("ARGUS_SERVER_TOKEN", "t")
    started = []
    monkeypatch.setattr("uvicorn.run", lambda *a, **kw: started.append(kw))
    server.main()
    assert started[0]["host"] == "0.0.0.0"
