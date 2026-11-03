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


def _python_bodies(marker_entry):
    python = {"kind": "python", "entry": marker_entry}
    nested = {
        "kind": "payment_agent",
        "testbed_url": "http://127.0.0.1:1",
        "sandbox": True,
        "inner": python,
    }
    return {"top-level": python, "nested": nested}


def test_server_route_rejects_python_and_nested_python_with_422(tmp_path, monkeypatch):
    from pathlib import Path

    from fastapi.testclient import TestClient
    from argus.server import app

    marker = tmp_path / "marker"
    monkeypatch.setenv("ARGUS_TEST_IMPORT_MARKER", str(marker))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "dummy-not-a-key")
    monkeypatch.delenv("ARGUS_SERVER_TOKEN", raising=False)
    entry = f"{Path(__file__).parent / 'fixtures' / 'python_target' / 'import_marker.py'}:call"
    expected = {
        "top-level": "python targets run only on the local machine: use argus-probe run --local",
        "nested": "a python target cannot be nested in inner",
    }
    client = TestClient(app)
    for shape, target in _python_bodies(entry).items():
        for path in ("/redteam/run", "/redteam/run/preflight"):
            resp = client.post(path, json={"target": target, "probe_ids": ["owasp_01_prompt_injection_basic"]})
            assert resp.status_code == 422, (shape, path, resp.text)
            assert resp.json()["detail"] == expected[shape], (shape, path)
    assert not marker.exists()
