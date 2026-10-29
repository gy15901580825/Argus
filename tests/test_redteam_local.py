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


# --- selection, the no-judge-key path and the run-time cap ---------------------
# These build their own probe library, so they test the rules, not today's library.

import json
from dataclasses import replace

from argus import api
from argus.probe import load_probe_library

KEY = {"ANTHROPIC_API_KEY": "sk-ant-test"}
_ASSERT = ({"type": "tool_not_called", "tool": "x"},)
GRPC_MCP_TARGET = {**MCP_TARGET, "inner": {"kind": "grpc", "endpoint": "127.0.0.1:1", "service_method": "a.B/C"}}


@pytest.fixture
def library(monkeypatch):
    """A small library: chat probes judged and deterministic, MCP probes, a browser probe."""
    base = load_probe_library(api.PROBES_DIR)[0]

    def probe(pid, cls, *, assertions=(), conversation=False, prompts=2):
        return replace(base, id=pid, target_class=(cls,), assertions=assertions,
                       conversation=conversation, prompts=tuple(f"p{i}" for i in range(prompts)))

    probes = [
        probe("chat_j1", "llm_chat"), probe("chat_j2", "llm_chat", prompts=3),
        probe("chat_a1", "llm_chat", assertions=_ASSERT),
        probe("mcp_a1", "mcp_agent", assertions=_ASSERT),
        probe("mcp_j1", "mcp_agent"),
        probe("mcp_conv", "mcp_agent", assertions=_ASSERT, conversation=True),
        probe("browser_j1", "browser-using"),
    ]
    monkeypatch.setattr("argus.api.load_probe_library", lambda *_: probes)
    monkeypatch.setattr("argus.local.load_probe_library", lambda *_: probes)
    return {p.id: p for p in probes}


def _spy_run(seen: dict, *, then=None):
    async def _spy(req, anthropic_api_key):
        seen["probe_ids"] = list(req.probe_ids)
        yield FAKE_FINDING
        if then is not None:
            then()
    return _spy


def _verdicts(events, verdict):
    return [e["probe_id"] for e in events if e.get("verdict") == verdict]


async def test_all_selects_only_probes_the_target_can_run(library):
    seen = {}
    with patch("argus.api._run_probes", _spy_run(seen)):
        await _collect(run_local(TARGET, [], env=KEY))
    assert seen["probe_ids"] == ["chat_j1", "chat_j2", "chat_a1"]


async def test_all_leaves_out_conversation_probes_when_the_inner_target_has_no_history(library):
    seen = {}
    with patch("argus.api._run_probes", _spy_run(seen)):
        await _collect(run_local(GRPC_MCP_TARGET, [], env=KEY))
    assert seen["probe_ids"] == ["mcp_a1", "mcp_j1"]
    with patch("argus.api._run_probes", _spy_run(seen)):
        await _collect(run_local(MCP_TARGET, [], env=KEY))
    assert seen["probe_ids"] == ["mcp_a1", "mcp_j1", "mcp_conv"]


async def test_no_key_refuses_when_any_selected_probe_needs_the_judge(library):
    async def _must_not_run(*a, **k):
        raise AssertionError("probes ran")
        yield  # pragma: no cover

    with patch("argus.api._run_probes", _must_not_run):
        with pytest.raises(LocalRunError) as exc:
            await _collect(run_local(TARGET, [], env={}))
    assert exc.value.code == "config"
    assert str(exc.value).startswith(
        "2 of 3 selected probes need an LLM judge: ANTHROPIC_API_KEY is not set. "
        "Set a key, or pass --skip-judged to run only the 1 probe decided by deterministic checks. "
        "Judge keys: ANTHROPIC_API_KEY or OPENAI_API_KEY")


async def test_skip_judged_reports_judged_probes_as_skipped_and_runs_the_rest(library):
    seen = {}
    with patch("argus.api._run_probes", _spy_run(seen)):
        events = await _collect(run_local(TARGET, [], env={}, skip_judged=True))
    assert seen["probe_ids"] == ["chat_a1"]
    assert _verdicts(events, "skipped") == ["chat_j1", "chat_j2"]
    skipped = [e for e in events if e.get("verdict") == "skipped"]
    for f in skipped:
        assert f["reasoning"] == "no judge key: ANTHROPIC_API_KEY is not set; skipped by --skip-judged"
        assert f["severity"] == "info"
        json.dumps(f)  # same wire shape as a finding from the runner
    assert skipped[0]["owasp_id"] == list(library["chat_j1"].mappings.owasp_llm)
    # Skipped findings first, then the probes that ran, then coverage.
    assert [e.get("verdict") for e in events[:2]] == ["skipped", "skipped"]
    assert events[2] == FAKE_FINDING
    assert events[-1]["type"] == "coverage"


async def test_skip_judged_still_refuses_when_nothing_would_run(library):
    with pytest.raises(LocalRunError) as exc:
        await _collect(run_local(TARGET, ["chat_j1", "chat_j2"], env={}, skip_judged=True))
    assert exc.value.code == "config"
    assert str(exc.value).startswith(
        "2 of 2 selected probes need an LLM judge: ANTHROPIC_API_KEY is not set. "
        "Set a key; --skip-judged would leave nothing to run.")


async def test_skip_judged_with_a_key_is_a_noop_with_a_warning(library):
    seen = {}
    with patch("argus.api._run_probes", _spy_run(seen)):
        events = await _collect(run_local(TARGET, [], env=KEY, skip_judged=True))
    assert seen["probe_ids"] == ["chat_j1", "chat_j2", "chat_a1"]
    assert _verdicts(events, "skipped") == []
    assert events[0] == {"type": "warning",
                         "message": "--skip-judged has no effect: a judge key is set, so every probe runs."}


async def test_a_probe_the_target_cannot_run_never_needs_the_judge(library):
    # chat_j1 does not fit an MCP target: the runner skips it by class, so no key is asked for.
    seen = {}
    with patch("argus.api._run_probes", _spy_run(seen)):
        events = await _collect(run_local(MCP_TARGET, ["mcp_a1", "chat_j1"], env={}))
    assert seen["probe_ids"] == ["mcp_a1", "chat_j1"]
    assert _verdicts(events, "skipped") == []


async def test_assertion_only_selection_needs_no_key_and_no_flag(library):
    seen = {}
    with patch("argus.api._run_probes", _spy_run(seen)):
        events = await _collect(run_local(MCP_TARGET, ["mcp_a1", "mcp_conv"], env={}))
    assert seen["probe_ids"] == ["mcp_a1", "mcp_conv"]
    assert not [e for e in events if e.get("type") == "warning"]


async def test_cost_estimate_counts_judged_prompts_of_probes_that_run(library):
    captured = {}

    def _capture(**kwargs):
        captured.update(kwargs)
        return 0.0

    with patch("argus.api._COST_METER.check_or_abort_pre_run", _capture):
        with patch("argus.api._run_probes", _spy_run({})):
            # chat_j1 (2 prompts) and chat_j2 (3) are judged; chat_a1 is not; mcp_j1 does not fit.
            await _collect(run_local(TARGET, ["chat_j1", "chat_j2", "chat_a1", "mcp_j1"], env=KEY))
    assert captured["total_exchanges"] == 5
    with patch("argus.api._COST_METER.check_or_abort_pre_run", _capture):
        with patch("argus.api._run_probes", _spy_run({})):
            await _collect(run_local(TARGET, [], env={}, skip_judged=True))
    assert captured["probe_ids"] == ["chat_a1"]
    assert captured["total_exchanges"] == 0


async def test_cost_rejection_names_a_cap_at_or_above_the_estimate(library, monkeypatch):
    monkeypatch.delenv("REDTEAM_MODEL_PROVIDER", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with pytest.raises(LocalRunError) as exc:
        await _collect(run_local(TARGET, [], per_run_cap_usd=0.01, env=KEY))
    assert exc.value.code == "cost"
    msg = str(exc.value)
    m = re.search(r"estimated cost \$(\d+\.\d+) > per_run_cap \$0\.01; rerun with --per-run-cap (\d+\.\d\d)", msg)
    assert m, msg
    estimate, fit = float(m.group(1)), float(m.group(2))
    assert estimate <= fit < estimate + 0.01


async def test_all_with_no_compatible_probe_is_refused(library, monkeypatch):
    class _Odd:
        compatible_classes = frozenset({"no_such_class"})

    monkeypatch.setattr("argus.local.build_target", lambda spec: _Odd())
    with pytest.raises(LocalRunError) as exc:
        await _collect(run_local(TARGET, [], env=KEY))
    assert exc.value.code == "input"
    assert "no probe in the library fits target kind openai_compat" in str(exc.value)


def _spend(usd_tokens: int):
    # Haiku output is $5 per 1M tokens.
    return lambda: api._COST_METER.record("claude-haiku-4-5-20251001", 0, usd_tokens)


async def test_spend_past_the_per_run_cap_stops_the_run(library):
    with patch("argus.api._run_probes", _spy_run({}, then=_spend(10_000))):  # $0.05
        with pytest.raises(LocalRunError) as exc:
            await _collect(run_local(TARGET, ["chat_a1"], per_run_cap_usd=0.01, env=KEY))
    assert exc.value.code == "cost"
    assert str(exc.value) == "per_run cap $0.01 would be exceeded by this call"
    # The scope closes with the run, so the next run starts clean.
    assert api._COST_METER.spent_in_current_run() == 0.0


async def test_spend_under_the_per_run_cap_lets_the_run_finish(library):
    with patch("argus.api._run_probes", _spy_run({}, then=_spend(10_000))):
        events = await _collect(run_local(TARGET, ["chat_a1"], per_run_cap_usd=1.00, env=KEY))
    assert events[-1]["type"] == "coverage"


async def test_run_probes_names_the_probe_the_cap_stopped(library):
    from argus.cost_meter import CostExceededError as _Cap

    class _Runner:
        def __init__(self, **kw):
            pass

        async def run_probe(self, probe):
            raise _Cap("per_run cap $0.01 would be exceeded by this call")
            yield  # pragma: no cover

    req = api.RunRequest(target=TARGET, probe_ids=["chat_j1", "chat_j2"])
    events = []
    with patch("argus.api.Runner", _Runner):
        with pytest.raises(_Cap):
            async for e in api._run_probes(req, "k"):
                events.append(e)
    assert [(e["probe_id"], e["verdict"]) for e in events] == [("chat_j1", "aborted_cost")]
    assert events[0]["reasoning"] == "cost cap reached: per_run cap $0.01 would be exceeded by this call"
