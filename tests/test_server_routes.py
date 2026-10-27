"""L3 tests for argus/server.py — the mounted route set."""
from __future__ import annotations


def _paths(app):
    # Public surfaces only: the OpenAPI schema plus top-level routes (the WS hub is not in OpenAPI).
    paths = set(app.openapi()["paths"])
    paths |= {r.path for r in app.routes if isinstance(getattr(r, "path", None), str)}
    return paths


def test_only_engine_routes():
    from argus.server import app

    paths = _paths(app)
    assert any(p.startswith("/redteam") for p in paths)
    assert "/agent/connect" in paths  # WS hub that browser_use needs
    assert "/orchestrator/run_command" not in paths
    assert not any("/strategy/" in p or "web-ui" in p for p in paths)


def test_cors_is_off_by_default():
    """No browser UI ships with the engine; cross-origin reads need CORS_ALLOW_ORIGINS."""
    from fastapi.testclient import TestClient
    from argus.server import app

    resp = TestClient(app).get("/redteam/probes", headers={"Origin": "https://evil.example"})
    assert "access-control-allow-origin" not in resp.headers
    assert "access-control-allow-credentials" not in resp.headers
