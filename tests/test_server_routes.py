"""L3 tests for argus/server.py — the mounted route set."""
from __future__ import annotations

import json
from importlib.metadata import version

import pytest


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


_DUMMY_KEYS = {"ANTHROPIC_API_KEY": "dummy-anthropic-7f3a", "AZURE_API_KEY": "dummy-azure-91c2",
               "OPENAI_API_KEY": "dummy-openai-4be8"}


@pytest.fixture
def health_env(monkeypatch):
    from argus import api
    from argus.cost_meter import CostMeter

    monkeypatch.setattr(api, "_COST_METER", CostMeter(daily_cap_usd=7.0, per_run_cap_usd=0.3,
                                                      deep_per_run_cap_usd=2.0))
    for name, value in _DUMMY_KEYS.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("REDTEAM_MODEL_PROVIDER", "openai")
    monkeypatch.setenv("REDTEAM_FAST_MODEL", "fast-x")
    monkeypatch.setenv("REDTEAM_STRONG_MODEL", "strong-y")
    monkeypatch.setenv("REDTEAM_LLM_API_BASE", "https://user:dummy-base-secret@llm.example/v1")


def _expected_health(judge):
    return {"status": "ok", "version": version("argus-probe"), "judge": judge,
            "per_run_cap_usd": {"static": 0.3, "deep": 2.0}, "daily_cap_usd": 7.0}


def test_healthz_reports_version_judge_and_caps(health_env):
    from fastapi.testclient import TestClient
    from argus.server import app

    resp = TestClient(app).get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == _expected_health({"provider": "openai", "fast_model": "fast-x",
                                            "strong_model": "strong-y"})


def test_healthz_never_contains_a_key_or_base_url(health_env):
    from fastapi.testclient import TestClient
    from argus.server import app

    resp = TestClient(app).get("/healthz")
    assert resp.status_code == 200 and resp.json()["judge"]["provider"] == "openai"
    text = resp.text
    for value in [*_DUMMY_KEYS.values(), "dummy-base-secret", "llm.example"]:
        assert value not in text


def test_healthz_answers_when_the_judge_cannot_resolve(health_env, monkeypatch):
    from fastapi.testclient import TestClient
    from argus.server import app

    monkeypatch.setenv("REDTEAM_MODEL_PROVIDER", "no-such-provider")
    resp = TestClient(app).get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == _expected_health({"error": "ValueError"})
    assert "no-such-provider" not in resp.text


def test_healthz_makes_no_network_connection(health_env, monkeypatch):
    import socket

    from fastapi.testclient import TestClient
    from argus.server import app

    def refuse(*args, **kwargs):
        raise AssertionError("healthz opened a network connection")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    assert TestClient(app).get("/healthz").status_code == 200


def test_startup_logs_the_health_fields_once(health_env, caplog):
    import logging

    from fastapi.testclient import TestClient
    from argus.server import app

    caplog.set_level(logging.INFO, logger="OrchestratorAPI")
    with TestClient(app) as client:
        client.get("/healthz")
    lines = [r.getMessage() for r in caplog.records if r.name == "OrchestratorAPI"
             and r.getMessage().startswith("argus server config ")]
    assert len(lines) == 1
    assert json.loads(lines[0].removeprefix("argus server config ")) == _expected_health(
        {"provider": "openai", "fast_model": "fast-x", "strong_model": "strong-y"})
    for value in [*_DUMMY_KEYS.values(), "dummy-base-secret"]:
        assert value not in caplog.text
