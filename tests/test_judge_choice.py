"""Choosing the judge: flags to env to LLMConfig, declared prices, litellm credential check, "Judged by"."""

from __future__ import annotations

import json
import os
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from argus import cost_meter, llm
from argus.cli.__main__ import main
from argus.cost_meter import _price_for, estimate_call_usd, price_env_names


# --- declared prices ---

@pytest.mark.parametrize("model, stem", [
    ("gemini/gemini-2.5-flash", "GEMINI_GEMINI_2_5_FLASH"),
    ("ollama/qwen2.5:32b", "OLLAMA_QWEN2_5_32B"),
    ("claude-haiku-4-5-20251001", "CLAUDE_HAIKU_4_5_20251001"),
    ("bedrock/anthropic.claude-3-5-haiku-20241022-v1:0", "BEDROCK_ANTHROPIC_CLAUDE_3_5_HAIKU_20241022_V1_0"),
    ("openai/My--Model", "OPENAI_MY_MODEL"),
])
def test_price_env_names_normalise_the_model_string(model, stem):
    assert price_env_names(model) == (f"REDTEAM_PRICE_{stem}_INPUT", f"REDTEAM_PRICE_{stem}_OUTPUT")


def test_declared_price_beats_the_table(monkeypatch):
    inp, out = price_env_names("claude-haiku-4-5-20251001")
    monkeypatch.setenv(inp, "0.5")
    monkeypatch.setenv(out, "2.5")
    assert _price_for("claude-haiku-4-5-20251001") == {"input": 0.5, "output": 2.5}


def test_declared_price_for_an_unknown_model_is_used_without_the_warning(monkeypatch, caplog):
    inp, out = price_env_names("gemini/gemini-2.5-flash")
    monkeypatch.setenv(inp, "0.30")
    monkeypatch.setenv(out, "2.50")
    with caplog.at_level("WARNING"):
        assert _price_for("gemini/gemini-2.5-flash") == {"input": 0.30, "output": 2.50}
    assert caplog.records == []


def test_declared_price_also_applies_to_ollama(monkeypatch):
    assert _price_for("ollama/llama3") == {"input": 0.0, "output": 0.0}
    inp, out = price_env_names("ollama/llama3")
    monkeypatch.setenv(inp, "1")
    monkeypatch.setenv(out, "1")
    assert _price_for("ollama/llama3") == {"input": 1.0, "output": 1.0}


@pytest.mark.parametrize("values", [("1.0", None), ("abc", "1"), ("-1", "1"), ("nan", "1"), ("inf", "1")])
def test_half_or_bad_declared_price_is_ignored_with_a_warning(monkeypatch, caplog, values):
    for name, v in zip(price_env_names("claude-sonnet-4-6"), values):
        if v is not None:
            monkeypatch.setenv(name, v)
    with caplog.at_level("WARNING"):
        assert _price_for("claude-sonnet-4-6") == {"input": 3.0, "output": 15.0}
    assert any("REDTEAM_PRICE_CLAUDE_SONNET_4_6" in r.getMessage() for r in caplog.records)


def test_unknown_model_warning_names_the_flag_and_the_env_names_once(caplog):
    with caplog.at_level("WARNING"):
        _price_for("mistral/warn-once-model")
        _price_for("mistral/warn-once-model")
    msgs = [r.getMessage() for r in caplog.records]
    assert len(msgs) == 1
    assert "--judge-price" in msgs[0]
    assert "REDTEAM_PRICE_MISTRAL_WARN_ONCE_MODEL_INPUT" in msgs[0]
    assert _price_for("mistral/warn-once-model")["output"] == max(
        p["output"] for p in cost_meter._PRICES_PER_M_TOKENS.values())  # still the dearest rate


def test_estimate_uses_the_declared_price(monkeypatch):
    before = estimate_call_usd("gemini/gemini-2.5-flash", 4000, 1000)
    for name in price_env_names("gemini/gemini-2.5-flash"):
        monkeypatch.setenv(name, "0")
    assert before > 0 and estimate_call_usd("gemini/gemini-2.5-flash", 4000, 1000) == 0.0


# --- flags to env ---

def test_judge_env_maps_each_flag_to_its_env_name():
    env = llm.judge_env(provider="litellm", model="gemini/gemini-2.5-flash", strong_model="gemini/gemini-2.5-pro",
                        api_base="http://h:1", env={})
    assert env == {"REDTEAM_MODEL_PROVIDER": "litellm", "REDTEAM_FAST_MODEL": "gemini/gemini-2.5-flash",
                   "REDTEAM_STRONG_MODEL": "gemini/gemini-2.5-pro", "REDTEAM_LLM_API_BASE": "http://h:1"}
    cfg = llm.resolve_config(env)
    assert (cfg.provider, cfg.fast_model, cfg.strong_model, cfg.api_base) == (
        "litellm", "gemini/gemini-2.5-flash", "gemini/gemini-2.5-pro", "http://h:1")


def test_judge_env_leaves_unset_flags_to_the_env():
    base = {"REDTEAM_MODEL_PROVIDER": "litellm", "REDTEAM_FAST_MODEL": "ollama/a"}
    assert llm.judge_env(model="ollama/b", env=base) == {"REDTEAM_FAST_MODEL": "ollama/b"}
    assert llm.judge_env(env=base) == {}


def test_judge_env_rejects_litellm_without_a_model():
    with pytest.raises(ValueError, match="REDTEAM_FAST_MODEL"):
        llm.judge_env(provider="litellm", env={})


def test_judge_env_price_covers_fast_and_strong_models():
    env = llm.judge_env(provider="openai", price=(0.25, 2.0), env={})
    for model in ("gpt-5.6-luna", "gpt-5.6-terra"):
        inp, out = price_env_names(model)
        assert (env[inp], env[out]) == ("0.25", "2.0")


def test_describe_names_provider_models_and_api_base_host_only():
    cfg = llm.resolve_config({"REDTEAM_MODEL_PROVIDER": "litellm", "REDTEAM_FAST_MODEL": "openai/m",
                              "REDTEAM_LLM_API_BASE": "https://user:pw@llm.example.com:8443/v1?key=s3cret"})
    text = llm.describe(cfg)
    assert text == "litellm, fast openai/m, strong openai/m, api base llm.example.com:8443"
    assert "pw" not in text and "s3cret" not in text


def test_describe_names_the_fallback_provider():
    cfg = llm.resolve_config({})
    assert llm.describe(cfg) == ("anthropic, fast claude-haiku-4-5-20251001, strong claude-sonnet-4-6, "
                                 "falls back to azure")


# --- litellm credential check ---

def test_litellm_missing_keys_are_named(monkeypatch):
    monkeypatch.setattr(llm, "_litellm_missing_keys", lambda model, api_base: ["GOOGLE_API_KEY", "GEMINI_API_KEY"])
    cfg = llm.resolve_config({"REDTEAM_MODEL_PROVIDER": "litellm", "REDTEAM_FAST_MODEL": "gemini/gemini-2.5-flash"})
    assert cfg.missing_credential() == "GOOGLE_API_KEY, GEMINI_API_KEY"
    err = llm.credential_error(cfg)
    assert "GOOGLE_API_KEY, GEMINI_API_KEY" in err and "gemini/gemini-2.5-flash" in err
    assert "Set ANTHROPIC_API_KEY or OPENAI_API_KEY" not in err


def test_litellm_check_covers_the_strong_model_too(monkeypatch):
    monkeypatch.setattr(llm, "_litellm_missing_keys",
                        lambda model, api_base: ["MISTRAL_API_KEY"] if model.startswith("mistral/") else [])
    cfg = llm.resolve_config({"REDTEAM_MODEL_PROVIDER": "litellm", "REDTEAM_FAST_MODEL": "ollama/x",
                              "REDTEAM_STRONG_MODEL": "mistral/mistral-large-latest"})
    assert cfg.missing_credential() == "MISTRAL_API_KEY"


def test_litellm_check_uses_litellms_own_validation(monkeypatch):
    monkeypatch.delenv("MISTRAL_API_KEY", raising=False)
    assert llm._litellm_missing_keys("mistral/mistral-small-latest", None) == ["MISTRAL_API_KEY"]


@pytest.mark.parametrize("model, api_base", [
    ("ollama/llama3", None),
    ("ollama_chat/llama3", None),
    ("openai/local-model", "http://127.0.0.1:8000/v1"),
    ("gemini/gemini-2.5-flash", "https://proxy.internal"),
    # Credentials can come from an AWS profile or Google ADC, which litellm's check cannot see.
    ("bedrock/anthropic.claude-3-5-haiku-20241022-v1:0", None),
    ("vertex_ai/gemini-2.5-flash", None),
])
def test_litellm_check_does_not_block_what_litellm_cannot_tell(monkeypatch, model, api_base):
    for k in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "VERTEXAI_PROJECT", "VERTEXAI_LOCATION",
              "OLLAMA_API_BASE", "OPENAI_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    assert llm._litellm_missing_keys(model, api_base) == []


def test_validation_crash_does_not_block(monkeypatch):
    import litellm

    def boom(**kw):
        raise RuntimeError("x")

    monkeypatch.setattr(litellm, "validate_environment", boom)
    assert llm._litellm_missing_keys("mistral/m", None) == []


# --- the engine: refusal, --skip-judged, the judge event ---

TARGET = {"kind": "openai_compat", "endpoint_url": "https://api.example.com/v1/chat/completions", "model": "m"}
GEMINI = {"REDTEAM_MODEL_PROVIDER": "litellm", "REDTEAM_FAST_MODEL": "gemini/gemini-2.5-flash"}


async def _collect(gen):
    return [e async for e in gen]


async def _one_finding(*a, **k):
    yield {"probe_id": "owasp_01_prompt_injection_basic", "verdict": "pass", "severity": "info"}


async def test_litellm_without_credentials_refuses_naming_the_variables(monkeypatch):
    from argus.local import LocalRunError, run_local

    monkeypatch.setattr(llm, "_litellm_missing_keys", lambda model, api_base: ["GOOGLE_API_KEY", "GEMINI_API_KEY"])
    with patch("argus.api._run_probes", _one_finding), pytest.raises(LocalRunError) as exc:
        await _collect(run_local(TARGET, ["owasp_01_prompt_injection_basic"], env=GEMINI))
    assert exc.value.code == "config"
    assert "GOOGLE_API_KEY, GEMINI_API_KEY" in str(exc.value)
    assert "gemini/gemini-2.5-flash" in str(exc.value)


async def test_litellm_without_credentials_and_skip_judged_skips_with_the_names(monkeypatch):
    from argus.local import run_local

    monkeypatch.setattr(llm, "_litellm_missing_keys", lambda model, api_base: ["MISTRAL_API_KEY"])
    env = {"REDTEAM_MODEL_PROVIDER": "litellm", "REDTEAM_FAST_MODEL": "mistral/m"}
    assertion_probe = "garak_leakreplay_guardiancloze"  # decided by deterministic checks, no judge
    seen = {}

    async def spy(req, key):
        seen["ids"] = req.probe_ids
        yield {"probe_id": assertion_probe, "verdict": "pass", "severity": "info"}

    with patch("argus.api._run_probes", spy):
        events = await _collect(run_local(
            TARGET, [assertion_probe, "owasp_07_system_prompt_leakage"], env=env, skip_judged=True))
    skipped = [e for e in events if e.get("verdict") == "skipped"]
    assert [e["probe_id"] for e in skipped] == ["owasp_07_system_prompt_leakage"]
    assert skipped[0]["reasoning"] == ("no judge key: litellm finds no credentials for mistral/m; it looks for "
                                       "MISTRAL_API_KEY; skipped by --skip-judged")
    assert seen["ids"] == [assertion_probe]
    assert not [e for e in events if e.get("type") == "judge"]  # nothing left for the judge


async def test_run_local_announces_the_judge_once_before_findings(monkeypatch):
    from argus.local import run_local

    monkeypatch.setattr(llm, "_litellm_missing_keys", lambda model, api_base: [])
    with patch("argus.api._run_probes", _one_finding):
        events = await _collect(run_local(TARGET, ["owasp_01_prompt_injection_basic"], env=GEMINI))
    judges = [i for i, e in enumerate(events) if e.get("type") == "judge"]
    assert judges == [0]
    assert events[0]["judge"] == "litellm, fast gemini/gemini-2.5-flash, strong gemini/gemini-2.5-flash"


async def test_assertion_only_run_does_not_announce_a_judge():
    from argus.local import run_local

    target = {"kind": "mcp_agent", "testbed_url": "http://127.0.0.1:1", "sandbox": True,
              "inner": {"kind": "openai_compat", "endpoint_url": "http://127.0.0.1:2/v1/chat/completions",
                        "model": "demo"}}
    with patch("argus.api._run_probes", _one_finding):
        events = await _collect(run_local(target, ["mcp_poison_description_exfil"], env={}))
    assert not [e for e in events if e.get("type") == "judge"]


# --- CLI: run ---

def _target_file(tmp_path):
    p = tmp_path / "t.json"
    p.write_text(json.dumps(TARGET))
    return str(p)


def _run(tmp_path, *extra):
    return CliRunner().invoke(main, ["run", "--local", "--target", _target_file(tmp_path),
                                     "--probes", "owasp_01_prompt_injection_basic",
                                     "--out", str(tmp_path / "r.json"), "--format", "json", *extra])


def test_run_litellm_without_a_model_is_a_usage_error(tmp_path):
    r = _run(tmp_path, "--judge-provider", "litellm")
    assert r.exit_code == 2, r.output
    assert "--judge-model" in r.output


def test_run_unknown_provider_is_a_usage_error(tmp_path):
    r = _run(tmp_path, "--judge-provider", "nosuch")
    assert r.exit_code == 2 and "nosuch" in r.output


@pytest.mark.parametrize("price", ["1", "a,b", "-1,2", "1,2,3", "nan,1", "inf,1"])
def test_run_bad_judge_price_is_a_usage_error(tmp_path, price):
    r = _run(tmp_path, "--judge-provider", "litellm", "--judge-model", "ollama/x", "--judge-price", price)
    assert r.exit_code == 2, r.output
    assert "--judge-price" in r.output


def test_judge_flags_need_local(tmp_path):
    r = CliRunner().invoke(main, ["run", "--target", _target_file(tmp_path), "--probes", "p",
                                  "--out", str(tmp_path / "r.html"), "--api-url", "http://x", "--token", "t",
                                  "--judge-model", "m"])
    assert r.exit_code == 2 and "--local" in r.output


def test_run_flags_reach_the_engine_and_the_report_then_env_is_restored(tmp_path, monkeypatch):
    monkeypatch.setattr(llm, "_litellm_missing_keys", lambda model, api_base: [])
    monkeypatch.setenv("REDTEAM_FAST_MODEL", "ollama/from-env")
    seen = {}

    async def fake_run_probes(req, key):
        seen["env"] = {k: os.environ.get(k) for k in (
            "REDTEAM_MODEL_PROVIDER", "REDTEAM_FAST_MODEL", "REDTEAM_STRONG_MODEL", "REDTEAM_LLM_API_BASE",
            *price_env_names("gemini/gemini-2.5-flash"))}
        seen["cfg"] = llm.resolve_config()
        yield {"probe_id": "owasp_01_prompt_injection_basic", "verdict": "pass", "severity": "info",
               "judge_model": "gemini/gemini-2.5-flash"}

    with patch("argus.api._run_probes", fake_run_probes):
        r = _run(tmp_path, "--judge-provider", "litellm", "--judge-model", "gemini/gemini-2.5-flash",
                 "--judge-api-base", "https://gw.example.com/v1", "--judge-price", "0.3,2.5")
    assert r.exit_code == 0, r.output
    assert seen["env"] == {
        "REDTEAM_MODEL_PROVIDER": "litellm", "REDTEAM_FAST_MODEL": "gemini/gemini-2.5-flash",
        "REDTEAM_STRONG_MODEL": None, "REDTEAM_LLM_API_BASE": "https://gw.example.com/v1",
        "REDTEAM_PRICE_GEMINI_GEMINI_2_5_FLASH_INPUT": "0.3", "REDTEAM_PRICE_GEMINI_GEMINI_2_5_FLASH_OUTPUT": "2.5",
    }
    assert seen["cfg"].strong_model == "gemini/gemini-2.5-flash"
    described = "litellm, fast gemini/gemini-2.5-flash, strong gemini/gemini-2.5-flash, api base gw.example.com"
    assert r.output.count(f"Judge: {described}") == 1
    assert json.loads((tmp_path / "r.json").read_text())["notes"] == [f"Judged by {described}"]
    # The flags applied to this command only.
    assert os.environ["REDTEAM_FAST_MODEL"] == "ollama/from-env"
    assert "REDTEAM_MODEL_PROVIDER" not in os.environ
    assert "REDTEAM_PRICE_GEMINI_GEMINI_2_5_FLASH_INPUT" not in os.environ


def test_run_litellm_missing_credentials_exit_1_naming_them(tmp_path, monkeypatch):
    monkeypatch.setattr(llm, "_litellm_missing_keys", lambda model, api_base: ["GOOGLE_API_KEY", "GEMINI_API_KEY"])
    r = _run(tmp_path, "--judge-provider", "litellm", "--judge-model", "gemini/gemini-2.5-flash")
    assert r.exit_code == 1, r.output
    assert "GOOGLE_API_KEY, GEMINI_API_KEY" in r.output
    assert not (tmp_path / "r.json").exists()


# --- CLI: scan-mcp ---

def test_scan_mcp_takes_the_judge_flags_and_records_the_judge(monkeypatch, tmp_path):
    from argus.cli import cmd_scan_mcp
    from argus.mcp_scan import scan
    from argus.mcp_scan.scan import ScanResult

    monkeypatch.setattr(cmd_scan_mcp, "sdk_problem", lambda extra: None)
    monkeypatch.setattr(llm, "_litellm_missing_keys", lambda model, api_base: [])
    seen = []

    async def fake(cfg, *, mask, echo):
        seen.append(cfg)
        return ScanResult(findings=[], notes=["n"], server_info=None, all_selected_unexercised=False,
                          unjudged=0, no_tool_called=False, out_of_time=False)

    monkeypatch.setattr(scan, "scan_mcp", fake)
    out = tmp_path / "r.sarif"
    r = CliRunner().invoke(main, ["scan-mcp", "http://127.0.0.1:9/mcp", "--format", "sarif", "--out", str(out),
                                  "--judge-provider", "litellm", "--judge-model", "mistral/mistral-small-latest"])
    assert r.exit_code == 0, r.output
    (cfg,) = seen
    assert cfg.judge_config.provider == "litellm"
    assert cfg.judge_config.fast_model == "mistral/mistral-small-latest"
    described = "litellm, fast mistral/mistral-small-latest, strong mistral/mistral-small-latest"
    assert f"Judge: {described}" in r.output
    notes = json.loads(out.read_text())["runs"][0]["properties"]["notes"]
    assert f"Judged by {described}" in notes


def test_scan_mcp_litellm_without_a_model_is_a_usage_error(monkeypatch):
    from argus.cli import cmd_scan_mcp

    monkeypatch.setattr(cmd_scan_mcp, "sdk_problem", lambda extra: None)
    r = CliRunner().invoke(main, ["scan-mcp", "http://127.0.0.1:9/mcp", "--judge-provider", "litellm"])
    assert r.exit_code == 2 and "--judge-model" in r.output
