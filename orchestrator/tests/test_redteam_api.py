"""Tests for orchestrator /redteam/run SSE endpoint."""

import json
import pytest
from unittest.mock import AsyncMock, patch
from fastapi.testclient import TestClient

from server import app


def test_redteam_run_endpoint_streams_findings(monkeypatch):
    """POST /redteam/run streams a finding per probe per prompt."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    request_body = {
        "target": {
            "kind": "openai_compat",
            "endpoint_url": "https://api.example.com/v1/chat/completions",
            "model": "gpt-4",
            "api_key": "sk-test",
        },
        "probe_ids": ["owasp_01_prompt_injection_basic"],
    }

    fake_finding = {
        "id": "00000000-0000-0000-0000-000000000001",
        "probe_id": "owasp_01_prompt_injection_basic",
        "verdict": "pass",
        "severity": "info",
        "atlas_id": ["AML.T0051.000"],
    }

    async def _fake_run(*args, **kwargs):
        yield fake_finding

    with patch("orchestrator.redteam.api._run_probes", _fake_run):
        client = TestClient(app)
        with client.stream("POST", "/redteam/run", json=request_body) as resp:
            assert resp.status_code == 200
            chunks = list(resp.iter_lines())
            data_lines = [c for c in chunks if c.startswith("data: ")]
            assert len(data_lines) >= 1
            payload = json.loads(data_lines[0][len("data: "):])
            assert payload["probe_id"] == "owasp_01_prompt_injection_basic"


def test_redteam_run_returns_500_when_anthropic_key_missing(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    client = TestClient(app)
    response = client.post(
        "/redteam/run",
        json={
            "target": {
                "kind": "openai_compat",
                "endpoint_url": "https://api.example.com/v1/chat/completions",
                "model": "gpt-4",
            },
            "probe_ids": ["any"],
        },
    )
    assert response.status_code == 500
    assert "ANTHROPIC_API_KEY" in response.json()["detail"]


def test_list_probes_returns_loaded_ids():
    client = TestClient(app)
    resp = client.get("/redteam/probes")
    assert resp.status_code == 200
    data = resp.json()
    assert "probe_ids" in data
    assert isinstance(data["probe_ids"], list)
    # At least Plan 2's owasp probes should be present
    assert any(pid.startswith("owasp_") for pid in data["probe_ids"])


def test_redteam_run_returns_402_when_cost_exceeded(monkeypatch):
    """If pre-run estimator rejects for cost, /redteam/run returns 402 not 500."""
    from orchestrator.redteam.cost_meter import CostExceededError, CostMeter

    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")

    # Patch CostMeter.check_or_abort_pre_run to always reject
    def reject_pre_run(self, probe_ids, target_kind, iterative_rounds=1, per_run_cap_override=None):
        raise CostExceededError("estimated $1.50 > per_run_cap $0.50")

    monkeypatch.setattr(CostMeter, "check_or_abort_pre_run", reject_pre_run)

    client = TestClient(app)
    body = {
        "target": {
            "kind": "openai_compat",
            "endpoint_url": "https://api.example.com/v1/chat/completions",
            "model": "gpt-4",
            "api_key": "sk-test",
        },
        "probe_ids": ["owasp_07_system_prompt_leakage"],
    }
    resp = client.post("/redteam/run", json=body)
    assert resp.status_code == 402
    assert "estimated" in resp.text or "cost" in resp.text.lower()


def test_preflight_returns_200_on_pass(monkeypatch):
    """POST /redteam/run/preflight returns 200 when cost check passes."""
    client = TestClient(app)
    body = {
        "target": {
            "kind": "openai_compat",
            "endpoint_url": "https://api.example.com/v1/chat/completions",
            "model": "gpt-4",
        },
        "probe_ids": ["owasp_01_prompt_injection_basic"],
    }
    resp = client.post("/redteam/run/preflight", json=body)
    assert resp.status_code == 200


def test_preflight_returns_402_when_cost_exceeded(monkeypatch):
    """POST /redteam/run/preflight returns 402 without starting any probe run."""
    from orchestrator.redteam.cost_meter import CostExceededError, CostMeter

    def reject_pre_run(self, probe_ids, target_kind, iterative_rounds=1, per_run_cap_override=None):
        raise CostExceededError("estimated $2.00 > per_run_cap $0.50")

    monkeypatch.setattr(CostMeter, "check_or_abort_pre_run", reject_pre_run)

    client = TestClient(app)
    body = {
        "target": {
            "kind": "openai_compat",
            "endpoint_url": "https://api.example.com/v1/chat/completions",
            "model": "gpt-4",
        },
        "probe_ids": ["owasp_07_system_prompt_leakage"],
    }
    resp = client.post("/redteam/run/preflight", json=body)
    assert resp.status_code == 402
    assert "estimated" in resp.text or "cost" in resp.text.lower()


def test_redteam_run_routes_through_factory_for_anthropic_native(monkeypatch):
    """Regression for C1: previously the orchestrator's RunRequest only matched
    openai_compat; this test verifies all 5 kinds are accepted by /run/preflight."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")

    client = TestClient(app)
    body = {
        "target": {"kind": "anthropic_native", "model": "claude-haiku-4-5-20251001", "api_key": "k"},
        "probe_ids": ["owasp_07_system_prompt_leakage"],
    }
    resp = client.post("/redteam/run/preflight", json=body)
    # Either 200 (cost passes) or 402 (cost would exceed) — but NOT 422 (schema rejection)
    assert resp.status_code in (200, 402), f"unexpected: {resp.status_code} {resp.text}"


def test_resolve_probe_ids_empty_means_all():
    """Regression: empty probe_ids list must expand to every loaded probe id.

    The CLI sends [] when the user passes --probes all (historical convention).
    Without this expansion every probe gets filtered by the `not in requested`
    set check, and runs silently complete with zero findings.
    """
    from orchestrator.redteam.api import _resolve_probe_ids

    resolved = _resolve_probe_ids([])
    assert len(resolved) > 100, f"expected full library, got {len(resolved)} probes"
    assert all(isinstance(p, str) for p in resolved)
    # Sanity: well-known probes are present
    assert "owasp_07_system_prompt_leakage" in resolved


def test_resolve_probe_ids_passthrough_when_explicit():
    """Explicit probe_ids list is returned unchanged."""
    from orchestrator.redteam.api import _resolve_probe_ids

    explicit = ["owasp_01_prompt_injection_basic", "owasp_07_system_prompt_leakage"]
    assert _resolve_probe_ids(explicit) == explicit


def test_preflight_with_empty_probe_ids_estimates_full_library_cost(monkeypatch):
    """Regression: empty probe_ids must use the full library size for cost
    estimation. Otherwise len([]) * cost_per_call = $0 silently passes any cap,
    and the run starts even when it would massively exceed the cap."""
    from orchestrator.redteam.cost_meter import CostMeter

    captured = {}

    def fake_pre_run(self, probe_ids, target_kind, iterative_rounds=1, per_run_cap_override=None):
        captured["probe_ids"] = probe_ids
        return 0.0

    monkeypatch.setattr(CostMeter, "check_or_abort_pre_run", fake_pre_run)

    client = TestClient(app)
    body = {
        "target": {
            "kind": "openai_compat",
            "endpoint_url": "https://x",
            "model": "y",
            "api_key": "k",
        },
        "probe_ids": [],  # CLI's "all" convention
    }
    resp = client.post("/redteam/run/preflight", json=body)
    assert resp.status_code == 200
    # Cost meter must have been called with the resolved full list, not []
    assert len(captured["probe_ids"]) > 100, (
        f"cost estimator received {len(captured['probe_ids'])} probes, "
        "expected the full library"
    )


def test_per_run_cap_usd_is_honored_at_preflight(monkeypatch):
    """Regression for C2: client-supplied per_run_cap_usd should override the singleton default."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")

    client = TestClient(app)
    body = {
        "target": {
            "kind": "openai_compat",
            "endpoint_url": "https://x",
            "model": "y",
            "api_key": "k",
        },
        "probe_ids": ["owasp_07_system_prompt_leakage"],
        "per_run_cap_usd": 0.000001,  # absurdly low — should reject
    }
    resp = client.post("/redteam/run/preflight", json=body)
    assert resp.status_code == 402, f"expected 402 with tiny cap, got: {resp.status_code} {resp.text}"
