"""REDTEAM_LLM_FALLBACK_PROVIDER / REDTEAM_LLM_FALLBACK_MODEL: a configured judge fallback.

Every provider is stubbed: litellm through argus.llm._acompletion, TypeSafe through argus.typesafe.send.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from argus import cost_meter, llm
from argus.cost_meter import CostMeter
from argus.judge import Judge
from argus.mcp_scan.judging import call_estimate_usd
from test_judge_blocked import DEPLOYMENT, VERDICT, _azure_block
from test_judge_jev import KEY, TARGET, _answer, ts  # noqa: F401 - ts is a fixture

AZURE = {"REDTEAM_MODEL_PROVIDER": "azure", "REDTEAM_FAST_MODEL": DEPLOYMENT, "REDTEAM_STRONG_MODEL": DEPLOYMENT}
AZURE_JEV = {**AZURE, "REDTEAM_LLM_FALLBACK_PROVIDER": "jev", "TYPESAFE_API_KEY": KEY}
GEMINI = "gemini/gemini-2.5-flash"
FAIL_HIGH = json.dumps({"verdict": "fail", "severity": "high", "confidence": 0.9, "reasoning": "leaked"})


def _stub_litellm(monkeypatch, *replies):
    """Answer litellm calls in order: an Exception is raised, a string is the reply text."""
    pending = list(replies)
    calls = []

    async def fake(**kwargs):
        calls.append(kwargs)
        r = pending.pop(0)
        if isinstance(r, Exception):
            raise r
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=r))],
                               usage=SimpleNamespace(prompt_tokens=10, completion_tokens=5))

    monkeypatch.setattr(llm, "_acompletion", fake)
    monkeypatch.setitem(cost_meter._PRICES_PER_M_TOKENS, DEPLOYMENT, {"input": 0.0, "output": 0.0})
    return calls


async def _judge(cfg, meter=None, severity="high"):
    meter = meter or CostMeter(daily_cap_usd=10.0)
    return await Judge("", meter, cfg).judge(probe_name="leak", attack_prompt="a", target_response="r",
                                             rubric_text="rubric", severity=severity)


# --- unset: today's behaviour ---

@pytest.mark.parametrize("env, fallback", [
    ({"ANTHROPIC_API_KEY": "x"}, "azure"),
    ({"REDTEAM_MODEL_PROVIDER": "anthropic"}, "azure"),
    ({"REDTEAM_MODEL_PROVIDER": "azure"}, "anthropic"),
    ({"REDTEAM_MODEL_PROVIDER": "openai", "OPENAI_API_KEY": "x"}, None),
    ({"REDTEAM_MODEL_PROVIDER": "litellm", "REDTEAM_FAST_MODEL": GEMINI}, None),
    ({"REDTEAM_MODEL_PROVIDER": "jev", "TYPESAFE_API_KEY": KEY}, None),
])
def test_unset_keeps_the_built_in_fallback_for_every_provider(env, fallback):
    cfg = llm.resolve_config(env)
    assert cfg.fallback is None
    assert cfg.fallback_provider == fallback
    record = llm.judge_record(cfg)
    assert record["fallback_provider"] == (fallback if cfg.fallback_enabled else None)
    assert "fallback_model" not in record
    if fallback:
        assert cfg.fallback_model_for("fast") == llm._DEFAULTS[fallback]["fast"]
        assert cfg.fallback_model_for("strong") == llm._DEFAULTS[fallback]["strong"]
        assert llm.describe(cfg).endswith(f"(falls back to {fallback})")


def test_unset_built_in_fallback_credential_stays_optional():
    # anthropic -> azure with no Azure key, azure -> anthropic with no Anthropic key: no refusal, as before.
    assert llm.resolve_config({"ANTHROPIC_API_KEY": "x"}).missing_credential() is None
    assert llm.resolve_config(AZURE).missing_credential() is None


async def test_unset_anthropic_error_still_falls_back_to_the_azure_default(monkeypatch):
    calls = _stub_litellm(monkeypatch, VERDICT)

    class Failing:
        class messages:
            @staticmethod
            async def create(**kw):
                raise RuntimeError("anthropic down")

    monkeypatch.setattr(llm, "_anthropic_client", lambda key: Failing())
    out = await llm.complete(llm.resolve_config({"ANTHROPIC_API_KEY": "x"}), role="fast", system="s", user="u",
                             max_tokens=10)
    assert [c["model"] for c in calls] == [f"azure/{llm._DEFAULTS['azure']['fast']}"]
    assert out.model == llm._DEFAULTS["azure"]["fast"]


# --- config errors ---

@pytest.mark.parametrize("env, needle", [
    ({**AZURE, "REDTEAM_LLM_FALLBACK_PROVIDER": "azure"}, "judge's own provider"),
    ({**AZURE, "REDTEAM_LLM_FALLBACK_PROVIDER": "bedrock"}, "'bedrock' is not supported"),
    ({**AZURE, "REDTEAM_LLM_FALLBACK_PROVIDER": "litellm"}, "requires REDTEAM_LLM_FALLBACK_MODEL"),
    ({**AZURE, "REDTEAM_LLM_FALLBACK_MODEL": GEMINI}, "REDTEAM_LLM_FALLBACK_MODEL needs REDTEAM_LLM_FALLBACK_PROVIDER"),
    ({"REDTEAM_MODEL_PROVIDER": "jev", "REDTEAM_LLM_FALLBACK_PROVIDER": "azure"}, "does not apply to the jev judge"),
])
def test_bad_fallback_choice_is_a_config_error(env, needle):
    with pytest.raises(ValueError) as exc:
        llm.resolve_config(env)
    assert needle in str(exc.value)
    assert "REDTEAM_LLM_FALLBACK" in str(exc.value)


async def test_bad_fallback_choice_refuses_a_local_run_at_startup():
    from argus.local import LocalRunError, check_run

    with pytest.raises(LocalRunError) as exc:
        check_run(TARGET, ["owasp_01_prompt_injection_basic"],
                  env={**AZURE, "AZURE_API_KEY": "x", "REDTEAM_LLM_FALLBACK_PROVIDER": "azure"})
    assert exc.value.code == "config" and "REDTEAM_LLM_FALLBACK_PROVIDER='azure'" in str(exc.value)


# --- credentials ---

def test_missing_fallback_credential_is_reported_like_the_primarys():
    cfg = llm.resolve_config({**AZURE, "REDTEAM_LLM_FALLBACK_PROVIDER": "jev"})
    assert cfg.missing_credential() == "TYPESAFE_API_KEY"
    err = llm.credential_error(cfg)
    assert "REDTEAM_LLM_FALLBACK_PROVIDER=jev" in err and "TYPESAFE_API_KEY is not set" in err
    # REDTEAM_LLM_FALLBACK=off turns the fallback off, so its key is not needed.
    off = llm.resolve_config({**AZURE, "REDTEAM_LLM_FALLBACK_PROVIDER": "jev", "REDTEAM_LLM_FALLBACK": "off"})
    assert off.missing_credential() is None and llm.judge_record(off)["fallback_provider"] is None


def test_missing_litellm_fallback_credential_names_the_model(monkeypatch):
    monkeypatch.setattr(llm, "_litellm_missing_keys",
                        lambda model, base: ["GEMINI_API_KEY"] if model == GEMINI else [])
    cfg = llm.resolve_config({**AZURE, "REDTEAM_LLM_FALLBACK_PROVIDER": "litellm",
                              "REDTEAM_LLM_FALLBACK_MODEL": GEMINI})
    assert cfg.missing_credential() == "GEMINI_API_KEY"
    assert GEMINI in llm.credential_error(cfg)


async def test_missing_fallback_credential_refuses_the_run_before_any_call(monkeypatch, llm_call_guard):
    from argus.local import LocalRunError, run_local

    async def collect(gen):
        return [e async for e in gen]

    with pytest.raises(LocalRunError) as exc:
        await collect(run_local(TARGET, ["owasp_01_prompt_injection_basic"],
                                env={**AZURE, "AZURE_API_KEY": "x", "REDTEAM_LLM_FALLBACK_PROVIDER": "jev"}))
    assert exc.value.code == "config" and "TYPESAFE_API_KEY" in str(exc.value)
    assert llm_call_guard == []


# --- the Judge: line, run.json and the disclosure ---

def test_describe_record_and_destination_name_the_configured_fallback():
    jev = llm.resolve_config({**AZURE_JEV, "REDTEAM_LLM_FALLBACK": "on"})
    assert llm.describe(jev).endswith("(falls back to jev jev-latest, content-filter blocks included)")
    assert llm.judge_record(jev)["fallback_provider"] == "jev"
    assert llm.judge_record(jev)["fallback_model"] == "jev-latest"
    assert llm.destination(jev) == "Azure OpenAI, or TypeSafe (api.typesafe.ai) when that fails"

    lite = llm.resolve_config({**AZURE, "REDTEAM_LLM_FALLBACK_PROVIDER": "litellm",
                               "REDTEAM_LLM_FALLBACK_MODEL": GEMINI})
    assert llm.describe(lite).endswith(f"(falls back to litellm {GEMINI})")
    assert llm.destination(lite) == "Azure OpenAI, or Google Gemini when that fails"


# --- Azure primary, jev fallback ---

async def test_block_with_fallback_on_is_served_by_jev(monkeypatch, ts):
    env = {**AZURE_JEV, "REDTEAM_STRONG_MODEL": "strong-deployment", "REDTEAM_LLM_FALLBACK": "on"}
    calls = _stub_litellm(monkeypatch, _azure_block())
    fake = ts(_answer("fail", 0.9, usage=(1000, 0)))
    meter = CostMeter(daily_cap_usd=10.0)
    v = await _judge(llm.resolve_config(env), meter, severity="critical")
    assert (v.verdict, v.severity, v.judge_model, v.escalated_model) == ("fail", "critical", "jev-1.14.0", None)
    assert v.reasoning.startswith("primary judge failed; jev fallback: jev(jev-1.14.0): fail")
    # Jev's answer is final: no strong escalation on Azure, one TypeSafe call with the jev key.
    assert len(calls) == 1 and len(fake.calls) == 1 and fake.calls[0]["key"] == KEY
    assert fake.calls[0]["body"]["model"] == "jev-latest"
    # The cost is Jev's: 1000 input tokens at jev-latest's rate; the blocked Azure call is not billed.
    assert meter.spent_today() == pytest.approx(1000 / 1e6 * cost_meter._PRICES_PER_M_TOKENS["jev-latest"]["input"])


async def test_block_by_default_raises_naming_the_configured_fallback(monkeypatch, ts):
    _stub_litellm(monkeypatch, _azure_block())
    fake = ts(_answer("pass", 0.9))
    with pytest.raises(llm.JudgeBlockedError) as exc:
        await _judge(llm.resolve_config(AZURE_JEV))
    assert "did not fall back to jev" in str(exc.value) and "REDTEAM_LLM_FALLBACK=on" in str(exc.value)
    assert exc.value.fallback == "off"
    assert fake.calls == []


async def test_error_falls_back_to_jev(monkeypatch, ts):
    _stub_litellm(monkeypatch, RuntimeError("azure down"))
    ts(_answer("pass", 0.9))
    v = await _judge(llm.resolve_config(AZURE_JEV))
    assert (v.verdict, v.severity, v.judge_model) == ("pass", "info", "jev-1.14.0")


async def test_strong_pass_error_falls_back_to_jev(monkeypatch, ts):
    env = {**AZURE_JEV, "REDTEAM_STRONG_MODEL": "strong-deployment"}
    calls = _stub_litellm(monkeypatch, FAIL_HIGH, RuntimeError("strong deployment down"))
    ts(_answer("fail", 0.9))
    v = await _judge(llm.resolve_config(env), severity="high")
    assert [c["model"] for c in calls] == [f"azure/{DEPLOYMENT}", "azure/strong-deployment"]
    assert (v.verdict, v.judge_model, v.escalated_model) == ("fail", DEPLOYMENT, "jev-1.14.0")
    assert "jev fallback" in v.reasoning


async def test_jev_failing_after_a_block_says_both_failed(monkeypatch, ts):
    import httpx

    _stub_litellm(monkeypatch, _azure_block())
    ts(httpx.ConnectError("refused"))
    with pytest.raises(llm.JudgeBlockedError) as exc:
        await _judge(llm.resolve_config({**AZURE_JEV, "REDTEAM_LLM_FALLBACK": "on"}))
    text = str(exc.value)
    assert "blocked the judge prompt" in text and "The jev fallback failed too" in text and "ConnectError" in text
    assert "did not fall back" not in text


async def test_fallback_off_never_calls_jev(monkeypatch, ts):
    _stub_litellm(monkeypatch, RuntimeError("azure down"))
    fake = ts(_answer("pass", 0.9))
    with pytest.raises(llm.AllProvidersFailed):
        await _judge(llm.resolve_config({**AZURE_JEV, "REDTEAM_LLM_FALLBACK": "off"}))
    assert fake.calls == []


async def test_text_calls_never_go_to_a_jev_fallback(monkeypatch, ts):
    _stub_litellm(monkeypatch, RuntimeError("azure down"))
    fake = ts(_answer("pass", 0.9))
    with pytest.raises(llm.AllProvidersFailed):
        await llm.complete(llm.resolve_config(AZURE_JEV), role="fast", system="s", user="u", max_tokens=10)
    assert fake.calls == []


def test_deep_mode_with_a_jev_fallback_refuses_before_starting():
    from argus.local import LocalRunError, check_run

    env = {**AZURE_JEV, "AZURE_API_KEY": "x"}
    with pytest.raises(LocalRunError) as exc:
        check_run(TARGET, ["owasp_01_prompt_injection_basic"], mode="deep", env=env)
    assert exc.value.code == "usage" and "REDTEAM_LLM_FALLBACK_PROVIDER=jev" in str(exc.value)
    assert "--mode static" in str(exc.value)
    check_run(TARGET, ["owasp_01_prompt_injection_basic"], env=env)  # a static run starts
    check_run(TARGET, ["owasp_01_prompt_injection_basic"], mode="deep", per_run_cap_usd=100.0,
              env={**env, "REDTEAM_LLM_FALLBACK": "off"})


def test_server_deep_run_with_a_jev_fallback_is_refused(monkeypatch):
    from fastapi.testclient import TestClient

    from argus.server import app

    for k, v in {**AZURE_JEV, "AZURE_API_KEY": "x"}.items():
        monkeypatch.setenv(k, v)
    r = TestClient(app).post("/redteam/run", json={"target": TARGET, "probe_ids": ["owasp_01_prompt_injection_basic"],
                                                   "mode": "deep"})
    assert r.status_code == 422 and "REDTEAM_LLM_FALLBACK_PROVIDER=jev" in r.text


# --- litellm fallback ---

async def test_error_falls_back_to_the_litellm_model(monkeypatch):
    env = {"REDTEAM_MODEL_PROVIDER": "openai", "OPENAI_API_KEY": "sk-x", "REDTEAM_LLM_API_BASE": "https://gw.example",
           "REDTEAM_LLM_FALLBACK_PROVIDER": "litellm", "REDTEAM_LLM_FALLBACK_MODEL": GEMINI}
    calls = _stub_litellm(monkeypatch, RuntimeError("gateway down"), VERDICT)
    monkeypatch.setitem(cost_meter._PRICES_PER_M_TOKENS, GEMINI, {"input": 0.0, "output": 0.0})
    v = await _judge(llm.resolve_config(env))
    assert [c["model"] for c in calls] == [f"openai/{llm._DEFAULTS['openai']['fast']}", GEMINI]
    # The fallback calls with its own settings: not the primary's gateway or OpenAI key.
    assert "api_base" not in calls[1] and "api_key" not in calls[1]
    assert v.verdict == "pass" and v.judge_model == GEMINI


def test_scan_mcp_estimate_prices_a_litellm_fallback(monkeypatch):
    monkeypatch.setitem(cost_meter._PRICES_PER_M_TOKENS, DEPLOYMENT, {"input": 0.0, "output": 0.0})
    monkeypatch.setitem(cost_meter._PRICES_PER_M_TOKENS, GEMINI, {"input": 1.0, "output": 1.0})
    cfg = llm.resolve_config({**AZURE, "REDTEAM_LLM_FALLBACK_PROVIDER": "litellm",
                              "REDTEAM_LLM_FALLBACK_MODEL": GEMINI})
    assert call_estimate_usd(cfg, 1000) > 0  # priced at the fallback's rate, no KeyError on litellm


# --- the live rubric tier ---

def test_live_rubric_judge_follows_the_cli_environment():
    from test_rubrics_live import live_judge_config

    cfg, _ = live_judge_config({"ANTHROPIC_API_KEY": "x"})
    assert cfg.provider == "anthropic"
    cfg, _ = live_judge_config({**AZURE, "AZURE_API_KEY": "x"})
    assert (cfg.provider, cfg.fast_model) == ("azure", DEPLOYMENT)
    cfg, _ = live_judge_config({**AZURE_JEV, "AZURE_API_KEY": "x", "REDTEAM_LLM_FALLBACK": "on"})
    assert cfg.fallback_provider == "jev" and cfg.fallback_on_block


@pytest.mark.parametrize("env, needle", [
    ({}, "ANTHROPIC_API_KEY"),
    (AZURE, "AZURE_API_KEY"),
    ({**AZURE, "AZURE_API_KEY": "x", "REDTEAM_LLM_FALLBACK_PROVIDER": "jev"}, "TYPESAFE_API_KEY"),
    ({"REDTEAM_MODEL_PROVIDER": "openai"}, "OPENAI_API_KEY"),
    ({"REDTEAM_MODEL_PROVIDER": "bogus"}, "REDTEAM_MODEL_PROVIDER"),
])
def test_live_rubric_skip_reason_names_the_missing_variable(env, needle):
    from test_rubrics_live import live_judge_config

    cfg, reason = live_judge_config(env)
    assert cfg is None and needle in reason


async def test_live_rubric_case_uses_the_resolved_config(monkeypatch):
    import test_rubrics_live as live

    cfg = llm.resolve_config({**AZURE, "AZURE_API_KEY": "x"})
    case = live._CASES_ALL[0]
    seen = []

    class StubJudge:
        def __init__(self, api_key, cost_meter, config):
            seen.append(config)

        async def judge(self, **kw):
            verdict = case.expect_verdict or next(v for v in ("pass", "warn", "fail") if v not in case.expect_not)
            return SimpleNamespace(verdict=verdict, severity="info", confidence=1.0, reasoning="")

    monkeypatch.setattr(live, "_CONFIG", cfg)
    monkeypatch.setattr(live, "Judge", StubJudge)
    await live.test_rubric_grades_fixture_as_expected(case)
    assert seen == [cfg]


def test_live_rubric_module_collects_and_skips_without_credentials(tmp_path):
    root = Path(__file__).resolve().parents[1]
    env = {k: v for k, v in os.environ.items()
           if not (k.endswith(("_API_KEY", "_API_TOKEN")) or k.startswith(("AZURE_", "TYPESAFE_", "REDTEAM_")))}
    r = subprocess.run([sys.executable, "-m", "pytest", "tests/test_rubrics_live.py", "-m", "rubric_live", "-q",
                        "-rs", "-p", "no:cacheprovider", f"--basetemp={tmp_path / 'bt'}"],
                       cwd=root, env=env, capture_output=True, text=True, timeout=300)
    assert r.returncode == 0, r.stdout[-2000:] + r.stderr[-2000:]
    assert " skipped" in r.stdout and "passed" not in r.stdout and "failed" not in r.stdout
    assert "ANTHROPIC_API_KEY is not set" in r.stdout
