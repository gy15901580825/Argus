"""Tests for orchestrator /redteam/run SSE endpoint."""

import json
import pytest
from unittest.mock import AsyncMock, patch
from fastapi.testclient import TestClient

from argus.server import app
from argus.api import PROBES_DIR
from argus.cost_meter import CostExceededError
from argus.probe import load_probe_library


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

    with patch("argus.api._run_probes", _fake_run):
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
            "probe_ids": ["owasp_01_prompt_injection_basic"],
        },
    )
    assert response.status_code == 500
    assert "ANTHROPIC_API_KEY" in response.json()["detail"]


def test_redteam_run_returns_500_when_openai_key_missing(monkeypatch):
    monkeypatch.setenv("REDTEAM_MODEL_PROVIDER", "openai")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    client = TestClient(app)
    response = client.post(
        "/redteam/run",
        json={
            "target": {
                "kind": "openai_compat",
                "endpoint_url": "https://api.example.com/v1/chat/completions",
                "model": "gpt-4",
            },
            "probe_ids": ["owasp_01_prompt_injection_basic"],
        },
    )
    assert response.status_code == 500
    assert response.json()["detail"].startswith("OPENAI_API_KEY is not set")


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
    from argus.cost_meter import CostExceededError, CostMeter

    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")

    # Patch CostMeter.check_or_abort_pre_run to always reject
    def reject_pre_run(self, probe_ids, target_kind, **kwargs):
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
    from argus.cost_meter import CostExceededError, CostMeter

    def reject_pre_run(self, probe_ids, target_kind, **kwargs):
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


_BROWSER = {"kind": "browser_use", "agent_url": "http://t/agent", "scenario_kind": "dom_injection"}


@pytest.mark.parametrize("trap, match", [
    ({"trap_host": "localhost"}, "IPv4"),
    ({"trap_host": "0.0.0.0", "trap_port": 8765}, "set trap_public_url"),
    ({"trap_public_url": "http://10.0.0.5:8765"}, "fixed trap_port"),
])
def test_preflight_rejects_invalid_browser_trap_options(trap, match):
    resp = TestClient(app).post("/redteam/run/preflight", json={
        "target": {**_BROWSER, **trap}, "probe_ids": ["browser_dom_inject_html_comment"],
    })
    assert resp.status_code == 422, resp.text
    assert match in resp.json()["detail"]


def test_run_rejects_invalid_browser_trap_options(monkeypatch):
    from argus.cost_meter import CostMeter
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.delenv("REDTEAM_MODEL_PROVIDER", raising=False)
    # Validation must stop the run before any cost check or probe.
    monkeypatch.setattr(CostMeter, "check_or_abort_pre_run",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("reached cost check")))
    resp = TestClient(app).post("/redteam/run", json={
        "target": {**_BROWSER, "trap_host": "0.0.0.0", "trap_port": 8765},
        "probe_ids": ["browser_dom_inject_html_comment"],
    })
    assert resp.status_code == 422, resp.text
    assert "set trap_public_url" in resp.json()["detail"]


def test_preflight_accepts_browser_trap_options():
    resp = TestClient(app).post("/redteam/run/preflight", json={
        "target": {**_BROWSER, "trap_host": "0.0.0.0", "trap_port": 8765,
                   "trap_public_url": "http://10.0.0.5:8765"},
        "probe_ids": ["browser_dom_inject_html_comment"],
    })
    assert resp.status_code == 200, resp.text


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
    from argus.api import _resolve_probe_ids

    resolved = _resolve_probe_ids([])
    assert len(resolved) > 100, f"expected full library, got {len(resolved)} probes"
    assert all(isinstance(p, str) for p in resolved)
    # Sanity: well-known probes are present
    assert "owasp_07_system_prompt_leakage" in resolved


def test_resolve_probe_ids_passthrough_when_explicit():
    """Explicit probe_ids list is returned unchanged."""
    from argus.api import _resolve_probe_ids

    explicit = ["owasp_01_prompt_injection_basic", "owasp_07_system_prompt_leakage"]
    assert _resolve_probe_ids(explicit) == explicit


def test_preflight_with_empty_probe_ids_estimates_full_library_cost(monkeypatch):
    """Regression: empty probe_ids must use the full library size for cost
    estimation. Otherwise len([]) * cost_per_call = $0 silently passes any cap,
    and the run starts even when it would massively exceed the cap."""
    from argus.cost_meter import CostMeter

    captured = {}

    def fake_pre_run(self, probe_ids, target_kind, **kwargs):
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
    # Cost meter must have been called with the resolved list, not [] — and only
    # the probes an openai_compat target can run.
    from argus.targets.openai_compat import OpenAICompatTarget
    expected = [p.id for p in load_probe_library(PROBES_DIR)
                if set(p.target_class) & OpenAICompatTarget.compatible_classes]
    assert len(expected) > 100
    assert captured["probe_ids"] == expected


@pytest.mark.parametrize("route", ["/redteam/run", "/redteam/run/preflight"])
def test_all_on_the_server_selects_only_compatible_probes(monkeypatch, route):
    """An mcp_agent target runs only the MCP probes; "all" must not estimate (or send) the whole library."""
    from argus.cost_meter import CostMeter

    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    captured = {}

    def fake_pre_run(self, probe_ids, target_kind, **kwargs):
        captured["probe_ids"] = probe_ids
        captured["total_exchanges"] = kwargs["total_exchanges"]
        raise CostExceededError("stop here")

    monkeypatch.setattr(CostMeter, "check_or_abort_pre_run", fake_pre_run)
    body = {
        "target": {"kind": "mcp_agent", "testbed_url": "http://127.0.0.1:1", "sandbox": True,
                   "inner": {"kind": "openai_compat", "endpoint_url": "http://127.0.0.1:2/v1", "model": "m"}},
        "probe_ids": [],
    }
    resp = TestClient(app).post(route, json=body)
    assert resp.status_code == 402
    assert sorted(captured["probe_ids"]) == sorted(
        p.id for p in load_probe_library(PROBES_DIR) if "mcp_agent" in p.target_class)
    assert 0 < len(captured["probe_ids"]) < len(load_probe_library(PROBES_DIR))
    assert captured["total_exchanges"] == 0  # every MCP probe is assertion-judged


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


@pytest.mark.parametrize("route", ["/redteam/run", "/redteam/run/preflight"])
def test_unknown_probe_ids_are_a_422_naming_them(route):
    client = TestClient(app)
    resp = client.post(route, json={
        "target": {"kind": "openai_compat", "endpoint_url": "http://127.0.0.1:9/v1", "model": "m"},
        "probe_ids": ["owasp_01_prompt_injection_basic", "no_such_probe"],
    })
    assert resp.status_code == 422
    assert "unknown probe id(s): no_such_probe" in resp.json()["detail"]
