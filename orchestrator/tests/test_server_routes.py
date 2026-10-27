"""L3 tests for orchestrator/server.py — routes exercised via TestClient."""
from __future__ import annotations

from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    """TestClient for the orchestrator FastAPI app."""
    import server
    with TestClient(server.app) as c:
        yield c


# ---------------------------------------------------------------------------
# /orchestrator/run_command
# ---------------------------------------------------------------------------

def test_run_command_success(client):
    import server
    server.connection_manager.send_command = AsyncMock(return_value={"echo": 1})

    resp = client.post(
        "/orchestrator/run_command",
        json={"agent_id": "a1", "tool_name": "ping", "arguments": {"x": 1}},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "success"
    assert body["result"] == {"echo": 1}

    server.connection_manager.send_command.assert_awaited_once_with(
        "a1", "tools/call", {"name": "ping", "arguments": {"x": 1}}
    )


def test_run_command_failure_returns_500(client):
    import server
    server.connection_manager.send_command = AsyncMock(
        side_effect=RuntimeError("ws dead")
    )

    resp = client.post(
        "/orchestrator/run_command",
        json={"agent_id": "a1", "tool_name": "ping", "arguments": {}},
    )
    assert resp.status_code == 500
    assert "ws dead" in resp.json()["detail"]


def test_run_command_validation_error(client):
    # Missing required fields
    resp = client.post("/orchestrator/run_command", json={"agent_id": "a1"})
    assert resp.status_code == 422


def _route_paths(routes, prefix=""):
    # FastAPI >=0.14x wraps include_router() entries; their routes carry the full path.
    paths = set()
    for r in routes:
        if hasattr(r, "path"):
            paths.add(prefix + r.path)
        elif hasattr(r, "original_router"):
            paths |= _route_paths(r.original_router.routes, prefix + r.include_context.prefix)
    return paths


def test_only_engine_routes():
    from server import app

    paths = _route_paths(app.routes)
    assert any(p.startswith("/redteam") for p in paths)
    assert "/agent/connect" in paths  # WS hub that browser_use needs
    assert not any("/strategy/" in p or "web-ui" in p for p in paths)
