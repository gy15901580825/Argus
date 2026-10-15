"""Tests for orchestrator.redteam.local — the in-process entry point the CLI uses."""

import pytest
from unittest.mock import patch

from orchestrator.redteam.cost_meter import CostExceededError
from orchestrator.redteam.local import LocalRunError, run_local

TARGET = {
    "kind": "openai_compat",
    "endpoint_url": "https://api.example.com/v1/chat/completions",
    "model": "gpt-4",
    "api_key": "sk-test",
}

FAKE_FINDING = {
    "id": "00000000-0000-0000-0000-000000000001",
    "probe_id": "owasp_01_prompt_injection_basic",
    "verdict": "fail",
    "severity": "high",
    "atlas_id": ["AML.T0051.000"],
}


async def _fake_run(*args, **kwargs):
    yield FAKE_FINDING


async def _collect(gen):
    return [e async for e in gen]


async def test_run_local_yields_findings_then_coverage(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    with patch("orchestrator.redteam.api._run_probes", _fake_run):
        events = await _collect(run_local(TARGET, ["owasp_01_prompt_injection_basic"]))
    assert events[0] == FAKE_FINDING
    assert events[-1]["type"] == "coverage"
    assert isinstance(events[-1]["coverage"], dict)
    assert len(events) == 2


async def test_run_local_passes_the_key_to_run_probes(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-abc")
    seen = {}

    async def _spy(req, anthropic_api_key):
        seen["key"] = anthropic_api_key
        seen["probe_ids"] = req.probe_ids
        seen["cap"] = req.per_run_cap_usd
        yield FAKE_FINDING

    with patch("orchestrator.redteam.api._run_probes", _spy):
        await _collect(run_local(TARGET, ["owasp_01_prompt_injection_basic"], per_run_cap_usd=2.0))
    assert seen == {"key": "sk-ant-abc", "probe_ids": ["owasp_01_prompt_injection_basic"], "cap": 2.0}


async def test_run_local_requires_anthropic_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("REDTEAM_MODEL_PROVIDER", raising=False)
    with pytest.raises(LocalRunError) as exc:
        await _collect(run_local(TARGET, ["owasp_01_prompt_injection_basic"]))
    assert exc.value.code == "config"
    assert "ANTHROPIC_API_KEY" in str(exc.value)


async def test_run_local_rejects_unknown_mode(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    with pytest.raises(LocalRunError) as exc:
        await _collect(run_local(TARGET, ["owasp_01_prompt_injection_basic"], mode="bogus"))
    assert exc.value.code == "input"
    assert "unknown mode" in str(exc.value)


async def test_run_local_rejects_bad_target(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    with pytest.raises(LocalRunError) as exc:
        await _collect(run_local({"kind": "nope"}, ["owasp_01_prompt_injection_basic"]))
    assert exc.value.code == "input"
    assert "nope" in str(exc.value)


async def test_run_local_translates_cost_cap(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")

    def _boom(**kwargs):
        raise CostExceededError("estimated $9.00 exceeds per-run cap $0.50")

    with patch("orchestrator.redteam.api._COST_METER.check_or_abort_pre_run", _boom):
        with pytest.raises(LocalRunError) as exc:
            await _collect(run_local(TARGET, ["owasp_01_prompt_injection_basic"]))
    assert exc.value.code == "cost"
    assert "per-run cap" in str(exc.value)
