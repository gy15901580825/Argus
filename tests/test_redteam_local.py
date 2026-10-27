"""Tests for argus.local — the in-process entry point the CLI uses."""

import pytest
from unittest.mock import patch

from argus.cost_meter import CostExceededError
from argus.local import LocalRunError, run_local

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
    with patch("argus.api._run_probes", _fake_run):
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

    with patch("argus.api._run_probes", _spy):
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

    with patch("argus.api._COST_METER.check_or_abort_pre_run", _boom):
        with pytest.raises(LocalRunError) as exc:
            await _collect(run_local(TARGET, ["owasp_01_prompt_injection_basic"]))
    assert exc.value.code == "cost"
    assert "per-run cap" in str(exc.value)


async def test_run_local_rejects_target_with_unknown_field(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    target = {"kind": "openai_compat", "endpoint_url": "https://x", "model": "m", "bogus": 1}
    with pytest.raises(LocalRunError) as exc:
        await _collect(run_local(target, ["owasp_01_prompt_injection_basic"]))
    assert exc.value.code == "input"


async def test_run_local_rejects_non_dict_target(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    with pytest.raises(LocalRunError) as exc:
        await _collect(run_local("not-a-dict", ["owasp_01_prompt_injection_basic"]))
    assert exc.value.code == "input"
    assert "JSON object" in str(exc.value)


async def test_run_local_rejects_deep_mode_without_probes(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    with pytest.raises(LocalRunError) as exc:
        await _collect(run_local(TARGET, [], mode="deep"))
    assert exc.value.code == "input"
    assert "deep" in str(exc.value)


async def test_run_local_translates_mid_stream_cost_cap(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")

    async def _cap_mid_run(*args, **kwargs):
        yield FAKE_FINDING
        raise CostExceededError("daily cap reached")

    with patch("argus.api._run_probes", _cap_mid_run):
        with pytest.raises(LocalRunError) as exc:
            await _collect(run_local(TARGET, ["owasp_01_prompt_injection_basic"]))
    assert exc.value.code == "cost"
    assert "daily cap" in str(exc.value)


async def test_run_local_propagates_other_mid_stream_errors(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")

    async def _judge_down(*args, **kwargs):
        yield FAKE_FINDING
        raise RuntimeError("judge down")

    with patch("argus.api._run_probes", _judge_down):
        with pytest.raises(RuntimeError, match="judge down"):
            await _collect(run_local(TARGET, ["owasp_01_prompt_injection_basic"]))


async def test_run_local_azure_provider_needs_no_anthropic_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with patch("argus.api._run_probes", _fake_run):
        events = await _collect(
            run_local(
                TARGET,
                ["owasp_01_prompt_injection_basic"],
                env={"REDTEAM_MODEL_PROVIDER": "azure"},
            )
        )
    assert events[0] == FAKE_FINDING
    assert events[-1]["type"] == "coverage"


async def test_run_local_uses_explicit_env_over_os_environ(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    seen = {}

    async def _spy(req, anthropic_api_key):
        seen["key"] = anthropic_api_key
        yield FAKE_FINDING

    with patch("argus.api._run_probes", _spy):
        await _collect(
            run_local(
                TARGET,
                ["owasp_01_prompt_injection_basic"],
                env={"ANTHROPIC_API_KEY": "sk-ant-explicit"},
            )
        )
    assert seen["key"] == "sk-ant-explicit"


async def test_openai_only_env_passes_credential_gate():
    with pytest.raises(LocalRunError) as exc:
        await _collect(run_local({"kind": "nope"}, ["owasp_01_prompt_injection_basic"],
                                 env={"OPENAI_API_KEY": "sk-x"}))
    assert exc.value.code == "input"


async def test_no_keys_message_names_both_keys():
    with pytest.raises(LocalRunError) as exc:
        await _collect(run_local(TARGET, ["owasp_01_prompt_injection_basic"], env={}))
    assert exc.value.code == "config"
    msg = str(exc.value)
    assert "ANTHROPIC_API_KEY" in msg and "OPENAI_API_KEY" in msg and "litellm" in msg


async def test_litellm_judge_yields_warning_first():
    env = {"REDTEAM_MODEL_PROVIDER": "litellm", "REDTEAM_FAST_MODEL": "ollama/qwen2.5:32b"}
    with patch("argus.api._run_probes", _fake_run):
        events = await _collect(
            run_local(TARGET, ["owasp_01_prompt_injection_basic"], env=env)
        )
    assert events[0]["type"] == "warning"
    assert "ollama/qwen2.5:32b" in events[0]["message"]
    assert "61%" in events[0]["message"]
    assert events[1] == FAKE_FINDING


async def test_default_judge_yields_no_warning():
    with patch("argus.api._run_probes", _fake_run):
        events = await _collect(
            run_local(
                TARGET,
                ["owasp_01_prompt_injection_basic"],
                env={"ANTHROPIC_API_KEY": "sk-ant-test"},
            )
        )
    assert not any(e.get("type") == "warning" for e in events)


MCP_TARGET = {
    "kind": "mcp_agent",
    "testbed_url": "http://127.0.0.1:1",
    "sandbox": True,
    "inner": {"kind": "openai_compat", "endpoint_url": "http://127.0.0.1:2/v1/chat/completions", "model": "demo"},
}
ASSERTION_PROBE = "mcp_poison_description_exfil"
JUDGED_PROBE = "owasp_07_system_prompt_leakage"


async def test_assertion_only_run_needs_no_key():
    with patch("argus.api._run_probes", _fake_run):
        events = await _collect(run_local(MCP_TARGET, [ASSERTION_PROBE], env={}))
    assert events[0] == FAKE_FINDING
    assert events[-1]["type"] == "coverage"


async def test_assertion_only_run_skips_litellm_warning():
    env = {"REDTEAM_MODEL_PROVIDER": "litellm", "REDTEAM_FAST_MODEL": "ollama/x"}
    with patch("argus.api._run_probes", _fake_run):
        events = await _collect(run_local(MCP_TARGET, [ASSERTION_PROBE], env=env))
    assert not [e for e in events if e.get("type") == "warning"]


async def test_mixed_selection_still_needs_key():
    with pytest.raises(LocalRunError) as exc:
        await _collect(run_local(MCP_TARGET, [ASSERTION_PROBE, JUDGED_PROBE], env={}))
    assert exc.value.code == "config"
    assert "ANTHROPIC_API_KEY" in str(exc.value)


async def test_invalid_provider_still_rejected_for_assertion_only_run():
    with pytest.raises(LocalRunError) as exc:
        await _collect(run_local(MCP_TARGET, [ASSERTION_PROBE], env={"REDTEAM_MODEL_PROVIDER": "bogus"}))
    assert exc.value.code == "config"
