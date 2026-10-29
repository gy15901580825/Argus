"""Tests for argus.local — the in-process entry point the CLI uses."""

import re

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


async def test_mixed_selection_without_key_skips_the_judged_probe():
    seen = {}

    async def _spy(req, anthropic_api_key):
        seen["probe_ids"] = req.probe_ids
        yield FAKE_FINDING

    with patch("argus.api._run_probes", _spy):
        events = await _collect(run_local(MCP_TARGET, [ASSERTION_PROBE, JUDGED_PROBE], env={}))
    # Only the deterministic probe is sent; the judged one is reported, not run.
    assert seen["probe_ids"] == [ASSERTION_PROBE]
    skipped = [e for e in events if e.get("verdict") == "skipped"]
    assert [e["probe_id"] for e in skipped] == [JUDGED_PROBE]
    assert skipped[0]["reasoning"].startswith("no judge key")
    assert "ANTHROPIC_API_KEY" in skipped[0]["reasoning"]


async def test_invalid_provider_still_rejected_for_assertion_only_run():
    with pytest.raises(LocalRunError) as exc:
        await _collect(run_local(MCP_TARGET, [ASSERTION_PROBE], env={"REDTEAM_MODEL_PROVIDER": "bogus"}))
    assert exc.value.code == "config"


async def test_run_local_rejects_unknown_probe_ids_before_anything_runs(monkeypatch):
    # A typo used to run nothing, report `completed` and exit 0. No key is needed to be told.
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("REDTEAM_MODEL_PROVIDER", raising=False)

    async def _must_not_run(*a, **k):
        raise AssertionError("probes ran")
        yield  # pragma: no cover

    with patch("argus.api._run_probes", _must_not_run):
        with pytest.raises(LocalRunError) as exc:
            await _collect(run_local(TARGET, ["owasp_01_prompt_injection_basic", "owasp_01_typo", "zz_nope"]))
    assert exc.value.code == "usage"
    assert str(exc.value) == (
        "unknown probe id(s): owasp_01_typo, zz_nope; run `argus-probe list-probes` to see the valid ids"
    )


async def test_run_local_turns_an_unreachable_target_into_a_stop(monkeypatch):
    from argus.runner import TargetUnreachableError

    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")

    async def _dead(*args, **kwargs):
        yield FAKE_FINDING
        raise TargetUnreachableError("target unreachable: 5 probes in a row failed (x)")

    with patch("argus.api._run_probes", _dead):
        with pytest.raises(LocalRunError) as exc:
            await _collect(run_local(TARGET, ["owasp_01_prompt_injection_basic"]))
    assert exc.value.code == "unreachable"
    assert str(exc.value) == "target unreachable: 5 probes in a row failed (x)"


# --- `--probes all` selection and the no-judge-key path ------------------------

import json

from argus import api
from argus.probe import load_probe_library

PAYMENT_TARGET = {
    "kind": "payment_agent",
    "testbed_url": "http://127.0.0.1:1",
    "sandbox": True,
    "inner": {"kind": "openai_compat", "endpoint_url": "http://127.0.0.1:2/v1/chat/completions", "model": "demo"},
}


def _ids_for(cls: str) -> list[str]:
    return [p.id for p in load_probe_library(api.PROBES_DIR) if cls in p.target_class]


def _judged(ids: list[str]) -> list[str]:
    by_id = {p.id: p for p in load_probe_library(api.PROBES_DIR)}
    return [pid for pid in ids if not by_id[pid].assertions]


def _spy_run(seen: dict):
    async def _spy(req, anthropic_api_key):
        seen["probe_ids"] = list(req.probe_ids)
        yield FAKE_FINDING
    return _spy


async def test_all_selects_only_probes_the_target_can_run():
    # mcp_agent serves only the MCP probes; the rest would only be skipped.
    seen = {}
    with patch("argus.api._run_probes", _spy_run(seen)):
        await _collect(run_local(MCP_TARGET, [], env={}))
    assert sorted(seen["probe_ids"]) == sorted(_ids_for("mcp_agent"))
    assert 0 < len(seen["probe_ids"]) < len(load_probe_library(api.PROBES_DIR))


async def test_all_on_assertion_only_target_needs_no_key_and_skips_nothing():
    with patch("argus.api._run_probes", _spy_run({})):
        events = await _collect(run_local(MCP_TARGET, [], env={}))
    assert not [e for e in events if e.get("verdict") == "skipped"]
    assert not [e for e in events if e.get("type") == "warning"]


async def test_all_without_key_skips_judged_probes_and_runs_the_rest():
    seen = {}
    with patch("argus.api._run_probes", _spy_run(seen)):
        events = await _collect(run_local(PAYMENT_TARGET, [], env={}))
    selected = _ids_for("payment_agent")
    judged = _judged(selected)
    assert judged and len(judged) < len(selected), "fixture needs a mixed payment library"
    assert sorted(seen["probe_ids"]) == sorted(set(selected) - set(judged))
    skipped = [e for e in events if e.get("verdict") == "skipped"]
    assert sorted(e["probe_id"] for e in skipped) == sorted(judged)
    for f in skipped:
        assert f["severity"] == "info"
        assert f["reasoning"].startswith("no judge key: ANTHROPIC_API_KEY is not set")
        json.dumps(f)  # same wire shape as a finding from the runner
        assert isinstance(f["id"], str) and isinstance(f["probed_at"], str)
    # The skipped probes keep their standards mappings, so coverage still shows them.
    by_id = {p.id: p for p in load_probe_library(api.PROBES_DIR)}
    assert skipped[0]["owasp_id"] == list(by_id[skipped[0]["probe_id"]].mappings.owasp_llm)
    # Skipped findings come first, then the probes that ran, then coverage.
    assert [e.get("verdict") for e in events[:len(judged)]] == ["skipped"] * len(judged)
    assert events[len(judged)] == FAKE_FINDING
    assert events[-1]["type"] == "coverage"


async def test_all_without_key_refuses_when_every_probe_needs_the_judge():
    # A chat target has no deterministic probe: an all-skipped report would exit 0
    # having tested nothing, so the run is refused instead.
    async def _must_not_run(*a, **k):
        raise AssertionError("probes ran")
        yield  # pragma: no cover

    from argus.targets.openai_compat import OpenAICompatTarget

    n = len([p for p in load_probe_library(api.PROBES_DIR)
             if set(p.target_class) & OpenAICompatTarget.compatible_classes])
    assert n > 100
    with patch("argus.api._run_probes", _must_not_run):
        with pytest.raises(LocalRunError) as exc:
            await _collect(run_local(TARGET, [], env={}))
    assert exc.value.code == "config"
    msg = str(exc.value)
    assert msg.startswith(f"all {n} selected probes need an LLM judge")
    assert "ANTHROPIC_API_KEY is not set" in msg


async def test_cost_estimate_covers_only_probes_that_will_run(monkeypatch):
    captured = {}

    def _capture(**kwargs):
        captured.update(kwargs)
        return 0.0

    with patch("argus.api._COST_METER.check_or_abort_pre_run", _capture):
        with patch("argus.api._run_probes", _spy_run({})):
            await _collect(run_local(PAYMENT_TARGET, [], env={}))
    runnable = sorted(set(_ids_for("payment_agent")) - set(_judged(_ids_for("payment_agent"))))
    assert sorted(captured["probe_ids"]) == runnable
    assert captured["total_exchanges"] == 0  # nothing left that calls the judge


async def test_cost_rejection_names_the_cap_that_would_fit(monkeypatch):
    monkeypatch.delenv("REDTEAM_MODEL_PROVIDER", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with pytest.raises(LocalRunError) as exc:
        await _collect(run_local(TARGET, [], per_run_cap_usd=0.10,
                                 env={"ANTHROPIC_API_KEY": "sk-ant-test"}))
    assert exc.value.code == "cost"
    msg = str(exc.value)
    m = re.search(r"estimated cost \$(\d+\.\d+) > per_run_cap \$0\.10; rerun with --per-run-cap (\d+\.\d\d)", msg)
    assert m, msg
    estimate, fit = float(m.group(1)), float(m.group(2))
    assert estimate <= fit < estimate + 0.01


async def test_all_with_no_compatible_probe_is_refused(monkeypatch):
    class _Odd:
        compatible_classes = frozenset({"no_such_class"})

    monkeypatch.setattr("argus.local.build_target", lambda spec: _Odd())
    with pytest.raises(LocalRunError) as exc:
        await _collect(run_local(TARGET, [], env={"ANTHROPIC_API_KEY": "sk-ant-test"}))
    assert exc.value.code == "input"
    assert "no probe in the library fits target kind openai_compat" in str(exc.value)
