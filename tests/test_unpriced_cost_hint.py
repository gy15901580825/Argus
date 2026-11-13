"""A cost rejection names each model the estimate priced at the fallback rate. Real CLI path, no calls."""

import re

from click.testing import CliRunner

from argus import llm
from argus.cli.__main__ import main

UNPRICED = "azure/my-judge-deployment"
FIRST_LINE = re.compile(r"Run rejected for cost: estimated cost \$(\d+\.\d+) > per_run_cap \$0\.00; "
                        r"rerun with --per-run-cap \d+\.\d\d or select fewer probes")


def _run(tmp_path, monkeypatch, *judge):
    monkeypatch.setattr(llm, "_litellm_missing_keys", lambda model, api_base: [])
    target = tmp_path / "t.json"
    target.write_text('{"kind":"openai_compat","endpoint_url":"https://x","model":"m"}')
    return CliRunner().invoke(main, [
        "run", "--local", "--target", str(target), "--probes", "owasp_01_prompt_injection_basic",
        "--out", str(tmp_path / "r.json"), "--format", "json", "--per-run-cap", "0.0001",
        "--judge-provider", "litellm", *judge])


def _rejection(output):
    return output[output.index("Run rejected for cost"):].rstrip("\n").split("\n")


def test_unpriced_model_is_named_with_both_fixes(tmp_path, monkeypatch):
    r = _run(tmp_path, monkeypatch, "--judge-model", UNPRICED)
    assert r.exit_code == 4, r.output
    first, *hint = _rejection(r.output)
    assert FIRST_LINE.fullmatch(first), first
    assert hint == [
        f"{UNPRICED} has no registered price, so the estimate used the most expensive known rate "
        "(in=$15.00/out=$75.00 per 1M tokens). Declare its price with --judge-price INPUT,OUTPUT "
        "(--judge-explain-price for a jev explain model) or REDTEAM_PRICE_AZURE_MY_JUDGE_DEPLOYMENT_INPUT "
        "and REDTEAM_PRICE_AZURE_MY_JUDGE_DEPLOYMENT_OUTPUT (USD per 1M tokens)."]
    assert not (tmp_path / "r.json").exists()


def test_priced_model_rejection_is_unchanged(tmp_path, monkeypatch):
    r = _run(tmp_path, monkeypatch, "--judge-model", "gpt-6-luna")
    assert r.exit_code == 4, r.output
    rejection = _rejection(r.output)
    assert len(rejection) == 1 and FIRST_LINE.fullmatch(rejection[0]), rejection


def test_declared_price_removes_the_hint_and_lowers_the_estimate(tmp_path, monkeypatch):
    unpriced = _rejection(_run(tmp_path, monkeypatch, "--judge-model", UNPRICED).output)
    declared = _rejection(_run(tmp_path, monkeypatch, "--judge-model", UNPRICED,
                               "--judge-price", "0.1,0.4").output)
    assert len(declared) == 1, declared
    before = float(FIRST_LINE.fullmatch(unpriced[0]).group(1))
    after = float(FIRST_LINE.fullmatch(declared[0]).group(1))
    assert 0 < after < before / 100


def test_declared_price_by_env_removes_the_hint(tmp_path, monkeypatch):
    monkeypatch.setenv("REDTEAM_PRICE_AZURE_MY_JUDGE_DEPLOYMENT_INPUT", "0.1")
    monkeypatch.setenv("REDTEAM_PRICE_AZURE_MY_JUDGE_DEPLOYMENT_OUTPUT", "0.4")
    r = _run(tmp_path, monkeypatch, "--judge-model", UNPRICED)
    assert r.exit_code == 4 and len(_rejection(r.output)) == 1, r.output


def _judge_check(monkeypatch, *args):
    monkeypatch.setattr(llm, "_litellm_missing_keys", lambda model, api_base: [])
    return CliRunner().invoke(main, ["judge-check", "--judge-provider", "litellm", "--per-run-cap", "0.001", *args])


def test_judge_check_rejection_names_the_unpriced_model(monkeypatch):
    r = _judge_check(monkeypatch, "--judge-model", UNPRICED)
    assert r.exit_code == 4, r.output
    first, *hint = r.output[r.output.index("Rejected for cost"):].rstrip("\n").split("\n")
    assert re.fullmatch(r"Rejected for cost: estimate \$\d+\.\d+ > --per-run-cap \$0\.00; "
                        r"rerun with --per-run-cap \d+\.\d\d", first), first
    assert len(hint) == 1 and hint[0].startswith(f"{UNPRICED} has no registered price")
    assert "--judge-price INPUT,OUTPUT" in hint[0] and "REDTEAM_PRICE_AZURE_MY_JUDGE_DEPLOYMENT_OUTPUT" in hint[0]


def test_judge_check_priced_rejection_is_unchanged(monkeypatch):
    r = _judge_check(monkeypatch, "--judge-model", UNPRICED, "--judge-price", "5,25")
    assert r.exit_code == 4, r.output
    assert r.output[r.output.index("Rejected for cost"):].rstrip("\n").count("\n") == 0, r.output
