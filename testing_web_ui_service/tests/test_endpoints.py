"""
Route-level tests for the FastAPI endpoints on `server.app`.

We swap the in-memory `_tasks` dict for a clean state in each test, and patch
`asyncio.create_task` for /tasks so we don't actually launch `_run_agent` (which
would pull in real browser_use).
"""
from __future__ import annotations

import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def server_mod():
    import server
    # Clear in-memory task state between tests
    server._tasks.clear()
    server._asyncio_tasks.clear()
    return server


@pytest.fixture
def client(server_mod):
    return TestClient(server_mod.app)


# ---------------------------------------------------------------------------
# POST /tasks — create a task; we stub out the background runner
# ---------------------------------------------------------------------------
def test_create_task_returns_pending_task_id(client, server_mod):
    def _fake_create(coro, *a, **kw):
        coro.close()  # avoid "coroutine was never awaited" RuntimeWarning
        return MagicMock()

    with patch.object(server_mod.asyncio, "create_task", side_effect=_fake_create) as mock_bg:
        resp = client.post("/tasks", json={"url": "https://ex.com/"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "pending"
    assert body["task_id"] in server_mod._tasks
    # The background runner was scheduled exactly once
    assert mock_bg.call_count == 1


# ---------------------------------------------------------------------------
# GET /tasks — list
# ---------------------------------------------------------------------------
def test_list_tasks_returns_known_records(client, server_mod):
    rec = server_mod.TaskRecord(
        task_id="t-abc",
        url="https://ex.com/",
        status="completed",
        created_at=time.time(),
        steps_done=10,
        max_steps=100,
    )
    server_mod._tasks["t-abc"] = rec
    resp = client.get("/tasks")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    assert data[0]["task_id"] == "t-abc"
    assert data[0]["status"] == "completed"


# ---------------------------------------------------------------------------
# GET /tasks/{id} — happy + 404
# ---------------------------------------------------------------------------
def test_get_task_404_when_unknown(client):
    resp = client.get("/tasks/does-not-exist")
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


def test_get_task_returns_fields_from_record(client, server_mod):
    rec = server_mod.TaskRecord(
        task_id="t1",
        url="https://ex.com/",
        status="running",
        created_at=100.0,
        started_at=101.0,
        steps_done=3,
        max_steps=50,
    )
    server_mod._tasks["t1"] = rec
    resp = client.get("/tasks/t1")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "running"
    assert body["steps_done"] == 3
    assert body["max_steps"] == 50


# ---------------------------------------------------------------------------
# GET /tasks/{id}/report — 404/409/200
# ---------------------------------------------------------------------------
def test_get_report_409_when_still_running(client, server_mod):
    server_mod._tasks["t-run"] = server_mod.TaskRecord(
        task_id="t-run", url="https://ex.com/", status="running",
    )
    resp = client.get("/tasks/t-run/report")
    assert resp.status_code == 409
    assert "running" in resp.json()["detail"].lower()


def test_get_report_ok_when_completed(client, server_mod):
    payload = {"pages_visited": [{"url": "https://ex.com/", "title": "H"}]}
    server_mod._tasks["t-ok"] = server_mod.TaskRecord(
        task_id="t-ok",
        url="https://ex.com/",
        status="completed",
        result=payload,
    )
    resp = client.get("/tasks/t-ok/report")
    assert resp.status_code == 200
    assert resp.json() == payload


# ---------------------------------------------------------------------------
# GET /tasks/{id}/tests — falls back to disk
# ---------------------------------------------------------------------------
def test_get_tests_returns_file_contents(client, server_mod, tmp_path, monkeypatch):
    # Redirect TESTS_DIR to a tmp directory and seed a test script.
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    monkeypatch.setattr(server_mod, "TESTS_DIR", tests_dir)
    (tests_dir / "test_abc.py").write_text("# generated test\n", encoding="utf-8")
    server_mod._tasks["abc"] = server_mod.TaskRecord(
        task_id="abc", url="u", status="completed",
    )
    resp = client.get("/tasks/abc/tests")
    assert resp.status_code == 200
    assert "# generated test" in resp.text


def test_get_tests_409_when_still_running(client, server_mod):
    server_mod._tasks["z"] = server_mod.TaskRecord(
        task_id="z", url="u", status="running",
    )
    resp = client.get("/tasks/z/tests")
    assert resp.status_code == 409


def test_get_tests_404_when_no_record_and_no_file(client, server_mod, tmp_path, monkeypatch):
    monkeypatch.setattr(server_mod, "TESTS_DIR", tmp_path)
    resp = client.get("/tasks/missing/tests")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# GET /tasks/{id}/features — disk fallback and on-the-fly extraction
# ---------------------------------------------------------------------------
def test_get_features_on_the_fly_extraction(client, server_mod, tmp_path, monkeypatch):
    monkeypatch.setattr(server_mod, "FEATURES_DIR", tmp_path / "no-such-dir")
    server_mod._tasks["xyz"] = server_mod.TaskRecord(
        task_id="xyz",
        url="https://ex.com/",
        status="completed",
        result={"pages_visited": [{"url": "https://ex.com/a", "title": "A"}]},
    )
    resp = client.get("/tasks/xyz/features")
    assert resp.status_code == 200
    body = resp.json()
    assert body["target_url"] == "https://ex.com/"
    assert [p["url"] for p in body["pages"]] == ["https://ex.com/a"]


# ---------------------------------------------------------------------------
# DELETE /tasks/{id} — cancel running task
# ---------------------------------------------------------------------------
def test_cancel_running_task_marks_cancelled(client, server_mod):
    server_mod._tasks["run"] = server_mod.TaskRecord(
        task_id="run", url="u", status="running",
    )
    # Fake a background task that can be cancelled.
    bg = MagicMock()
    bg.done.return_value = False
    server_mod._asyncio_tasks["run"] = bg
    resp = client.delete("/tasks/run")
    assert resp.status_code == 200
    assert resp.json()["status"] == "cancelled"
    bg.cancel.assert_called_once()
    assert server_mod._tasks["run"].status == "cancelled"


def test_cancel_completed_task_is_noop(client, server_mod):
    server_mod._tasks["done"] = server_mod.TaskRecord(
        task_id="done", url="u", status="completed",
    )
    resp = client.delete("/tasks/done")
    assert resp.status_code == 200
    assert resp.json()["detail"].startswith("Already")


def test_cancel_unknown_task_404(client):
    resp = client.delete("/tasks/nope")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# GET /tasks/{id}/videos/{filename} — path traversal protection
# ---------------------------------------------------------------------------
def test_get_video_rejects_path_traversal(client):
    resp = client.get("/tasks/abc/videos/..%2Fetc%2Fpasswd")
    # The validation fires when a ".." or "/" is in the filename.
    # URL-decoded, "..%2F..." becomes "../..." with "/". Check for 400 or 404.
    assert resp.status_code in (400, 404)


def test_get_video_404_when_missing(client):
    resp = client.get("/tasks/abc/videos/missing.webm")
    assert resp.status_code == 404
