"""`argus-probe judge-check`: estimate, credential and cap refusals, scoring output. No live calls."""

from __future__ import annotations

import json
import re
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from click.testing import CliRunner

from argus import judge_bench, llm
from argus.cli.__main__ import main
from argus.judge_bench import Case, load_all_cases, sample_cases

OLLAMA = ["--judge-provider", "litellm", "--judge-model", "ollama/judge"]


def _invoke(*args):
    return CliRunner().invoke(main, ["judge-check", *args])


def _estimate(output: str) -> float:
    return float(re.search(r"Estimated cost: \$([0-9.]+)", output).group(1))


def _reply(verdict):
    text = json.dumps({"verdict": verdict, "severity": "high", "confidence": 0.9, "reasoning": f"said {verdict}"})
    return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=text))],
                           usage=SimpleNamespace(prompt_tokens=100, completion_tokens=20))


def test_default_sample_is_one_pass_and_one_fail_per_rubric_plus_the_shared_cases():
    cases = load_all_cases()
    sample = sample_cases(cases)
    own = [c for c in sample if not c.shared]
    rubrics = {c.rubric for c in cases if not c.shared}
    assert sorted((c.rubric, c.expect_verdict) for c in own) == sorted(
        [(r, "pass") for r in rubrics] + [(r, "fail") for r in rubrics])
    assert [c for c in sample if c.shared] == [c for c in cases if c.shared]
    assert len(sample) < len(cases)


def test_estimate_is_printed_before_the_credential_refusal(monkeypatch):
    monkeypatch.setattr(llm, "_litellm_missing_keys", lambda model, api_base: ["GOOGLE_API_KEY", "GEMINI_API_KEY"])
    r = _invoke("--judge-provider", "litellm", "--judge-model", "gemini/gemini-2.5-flash")
    assert r.exit_code == 1, r.output
    assert r.output.index("Estimated cost") < r.output.index("GOOGLE_API_KEY, GEMINI_API_KEY")
    assert "Judge: litellm, fast gemini/gemini-2.5-flash" in r.output


def test_default_anthropic_without_a_key_refuses():
    r = _invoke()
    assert r.exit_code == 1 and "ANTHROPIC_API_KEY" in r.output


def test_judge_price_changes_the_estimate(monkeypatch):
    monkeypatch.setattr(llm, "_litellm_missing_keys", lambda model, api_base: ["MISTRAL_API_KEY"])
    args = ["--judge-provider", "litellm", "--judge-model", "mistral/mistral-small-latest"]
    dearest = _estimate(_invoke(*args).output)
    declared = _estimate(_invoke(*args, "--judge-price", "0.1,0.3").output)
    assert dearest > 0 and 0 < declared < dearest / 10


def test_litellm_without_a_model_is_a_usage_error():
    r = _invoke("--judge-provider", "litellm")
    assert r.exit_code == 2 and "--judge-model" in r.output


def test_env_litellm_without_a_model_is_a_usage_error(monkeypatch):
    monkeypatch.setenv("REDTEAM_MODEL_PROVIDER", "litellm")
    r = _invoke()
    assert r.exit_code == 2 and "REDTEAM_FAST_MODEL" in r.output


def test_estimate_above_the_cap_refuses_without_calling(monkeypatch):
    monkeypatch.setattr(llm, "_litellm_missing_keys", lambda model, api_base: [])
    call = AsyncMock()
    monkeypatch.setattr(llm, "_acompletion", call)
    r = _invoke(*OLLAMA, "--judge-price", "5,25", "--per-run-cap", "0.001")
    assert r.exit_code == 4, r.output
    assert "--per-run-cap" in r.output and not call.called


def test_run_prints_scores_wrong_cases_and_the_label_caveat(monkeypatch):
    cases = [
        Case("default.md", "pass_case", "p", "a", "REPLY-HELD-1", expect_verdict="pass"),
        Case("default.md", "fail_case", "p", "a", "REPLY-COMPLIED-2", expect_verdict="fail"),
        Case("jailbreak.md", "pass_case", "p", "a", "REPLY-HELD-1", expect_verdict="pass"),
        Case("default.md", "shared:empty_reply", "p", "a", "", expect_not=("pass",), shared=True),
    ]
    monkeypatch.setattr(judge_bench, "load_all_cases", lambda: cases)
    # The judge passes both non-empty replies, so the fail case is a false pass.
    replies = {"REPLY-HELD-1": "pass", "REPLY-COMPLIED-2": "pass"}

    async def fake_acompletion(**kw):
        user = kw["messages"][1]["content"]
        for reply, verdict in replies.items():
            if reply in user:
                return _reply(verdict)
        return _reply("fail")

    monkeypatch.setattr(llm, "_acompletion", fake_acompletion)
    r = _invoke(*OLLAMA)
    assert r.exit_code == 0, r.output
    out = r.output
    assert "Cases: 4" in out
    assert "Accuracy: 75.0% (3/4)" in out
    assert "False pass: 1 of 2" in out and "False fail: 0 of 2" in out and "Errors: 0" in out
    wrong = out[out.index("Wrong"):]
    assert "default.md fail_case: expected fail, got pass" in wrong
    assert "jailbreak.md" not in wrong
    assert "not a population estimate" in out
    assert out.index("Estimated cost") < out.index("Accuracy")


def test_all_runs_every_case(monkeypatch):
    monkeypatch.setattr(llm, "_litellm_missing_keys", lambda model, api_base: ["X_KEY"])
    sample = _invoke(*OLLAMA[:2], "--judge-model", "mistral/m").output
    every = _invoke(*OLLAMA[:2], "--judge-model", "mistral/m", "--all").output
    n = len(load_all_cases())
    assert f"Cases: {len(sample_cases(load_all_cases()))}" in sample
    assert f"Cases: {n}" in every


def test_unusable_reply_is_an_error_and_still_exit_0(monkeypatch):
    monkeypatch.setattr(judge_bench, "load_all_cases",
                        lambda: [Case("default.md", "pass_case", "p", "a", "held", expect_verdict="pass")])

    async def garbage(**kw):
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content="not json"))],
                               usage=SimpleNamespace(prompt_tokens=1, completion_tokens=1))

    monkeypatch.setattr(llm, "_acompletion", garbage)
    r = _invoke(*OLLAMA)
    assert r.exit_code == 0, r.output
    assert "Errors: 1" in r.output and "default.md pass_case: expected pass, got error" in r.output


@pytest.mark.parametrize("flag", ["--judge-provider", "--judge-model", "--judge-strong-model", "--judge-api-base",
                                  "--judge-price", "--all", "--per-run-cap"])
def test_help_lists_the_flags(flag):
    assert flag in _invoke("--help").output
