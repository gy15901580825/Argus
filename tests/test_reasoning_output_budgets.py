"""Offline budget and fail-closed behavior for every text-model call."""
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest

from argus import iterative_pair, iterative_tap, jev_judge, llm, persona_strategy
from argus.cost_meter import CostMeter
from argus.judge import Judge
from argus.mcp_scan import judging
from argus.mcp_scan.models import Candidate


def config():
    return llm.LLMConfig(anthropic_api_key="", provider="azure", fast_model="gpt-6-luna", strong_model="gpt-6-luna",
                         fallback_enabled=False)


def stub(monkeypatch, text):
    calls = []
    async def complete(cfg, **kwargs):
        calls.append(kwargs)
        return llm.Completion(text, 100, kwargs["max_tokens"], cfg.fast_model)
    monkeypatch.setattr(llm, "complete", complete)
    monkeypatch.setattr(llm, "text_config", config)
    return calls


@pytest.mark.parametrize("role", ["fast", "strong"])
@pytest.mark.parametrize("text", ["", " \n\t"])
async def test_judge_exhaustion_is_named_error(monkeypatch, role, text):
    calls = stub(monkeypatch, text)
    judge = Judge("", CostMeter(daily_cap_usd=float("inf")), config())
    judge._decider = SimpleNamespace(decide=AsyncMock())
    verdict = await judge._call(role, "probe", "attack", "reply", "rubric")
    assert verdict.verdict == "error"
    assert "CompletionTruncated" in verdict.reasoning
    assert calls[0]["max_tokens"] == 4000
    assert calls[0]["role"] == role
    judge._decider.decide.assert_not_awaited()


async def test_strong_truncation_cannot_be_decided_as_pass(monkeypatch):
    calls = []
    async def complete(cfg, **kwargs):
        calls.append(kwargs)
        text = json.dumps(dict(verdict="pass", severity="high", confidence=1, reasoning="safe")) if len(calls) == 1 else ""
        return llm.Completion(text, 100, kwargs["max_tokens"], cfg.fast_model)
    monkeypatch.setattr(llm, "complete", complete)
    cfg = llm.LLMConfig(anthropic_api_key="", provider="openai", fast_model="fast", strong_model="strong", fallback_enabled=False)
    judge = Judge("", CostMeter(daily_cap_usd=float("inf")), cfg)
    judge._decider = SimpleNamespace(decide=AsyncMock())
    verdict = await judge.judge("probe", "attack", "reply", "rubric")
    assert verdict.verdict == "error" and "CompletionTruncated" in verdict.reasoning
    judge._decider.decide.assert_not_awaited()
    assert [c["max_tokens"] for c in calls] == [4000, 4000]


async def test_scan_truncation_is_unjudged_with_named_reason(monkeypatch):
    calls = stub(monkeypatch, "")
    cand = Candidate(probe_id="p", tool="t", text="body", call_seq=1, source="result")
    [out] = await judging.JudgeGate(1, config(), "rubric").judge_all([cand], lambda s: s)
    assert out.status == "error" and out.verdict == ""
    assert "CompletionTruncated" in out.reasoning
    assert out.error_code == "completion_truncated"
    assert calls[0]["max_tokens"] == 4000


@pytest.mark.parametrize("module", [persona_strategy, iterative_pair, iterative_tap])
@pytest.mark.parametrize("text", ["", " \n ", "next prompt"])
async def test_attackers_budget_and_truncation(monkeypatch, module, text):
    calls = stub(monkeypatch, text)
    monkeypatch.setattr(module, "_cost_meter", None)
    call = module._call_planner_llm if module is iterative_tap else module._call_attacker_llm
    if text.strip():
        assert await call("system", "user") == text
    else:
        error = persona_strategy.AttackerTruncated if module is persona_strategy else llm.CompletionTruncated
        with pytest.raises(error):
            await call("system", "user")
    assert calls[0]["max_tokens"] == 4000


@pytest.mark.parametrize("text", ["", " \n ", "The target complied."])
async def test_explanation_keeps_verdict_and_names_truncation(monkeypatch, text):
    calls = stub(monkeypatch, text)
    monkeypatch.setattr(llm, "explain_config", lambda cfg: config())
    result = await jev_judge._explain(config(), None, "fail", "fail", "p", "attack", "reply", "rubric")
    assert result.startswith("fail")
    assert ("CompletionTruncated" in result) == (not text.strip())
    if text.strip():
        assert text in result
    assert calls[0]["max_tokens"] == 4000


@pytest.mark.parametrize("text", ["", " \n ", "valid"])
async def test_proposal_budget_and_named_failure(tmp_path, monkeypatch, text):
    from argus.drafting.openapi import load_openapi, catalog_operations
    from argus.drafting.proposal import propose_choices
    from test_draft_target import input_file
    from test_draft_target_model import proposed_document, proposal_document_choices
    calls = stub(monkeypatch, json.dumps(proposal_document_choices()) if text == "valid" else text)
    monkeypatch.setattr(llm, "missing_text", lambda cfg: None)
    catalog = catalog_operations(load_openapi(input_file(tmp_path, proposed_document())))
    result = await propose_choices(catalog)
    if text == "valid":
        assert result.disclosure.status == "accepted"
    else:
        assert result.disclosure.status == "failed"
        assert result.disclosure.error_type == "CompletionTruncated"
        assert any(g.code == "model_completion_truncated" for g in result.choices.gaps)
        assert result.disclosure.usage["output_tokens"] == 4000
        assert result.disclosure.cost_usd > 0
    assert calls[0]["max_tokens"] == 4000


@pytest.mark.parametrize("text,tokens,raises", [("", 4000, True), (" \n", 4001, True),
                                                ("", 3999, False), ("reply", 4000, False)])
def test_shared_truncation_boundary(text, tokens, raises):
    out = llm.Completion(text, 0, tokens, "fixture")
    if raises:
        with pytest.raises(llm.CompletionTruncated, match="4000"):
            llm.check_completion(out, 4000)
    else:
        llm.check_completion(out, 4000)


async def test_truncation_does_not_try_provider_fallback(monkeypatch):
    first = AsyncMock(return_value=llm.Completion("", 100, 4000, "fixture"))
    second = AsyncMock()
    monkeypatch.setitem(llm._DISPATCH, "azure", first)
    monkeypatch.setitem(llm._DISPATCH, "anthropic", second)
    cfg = llm.LLMConfig(anthropic_api_key="", provider="azure", fast_model="fixture", strong_model="fixture", fallback_enabled=True)
    out = await llm.complete(cfg, role="fast", system="s", user="u", max_tokens=4000)
    with pytest.raises(llm.CompletionTruncated):
        llm.check_completion(out, 4000)
    first.assert_awaited_once()
    second.assert_not_awaited()


def test_scan_estimate_uses_the_actual_budget(monkeypatch):
    seen = []
    monkeypatch.setattr(judging, "estimate_call_usd", lambda m, c, t: seen.append(t) or 0.01)
    judging.call_estimate_usd(config(), 1000)
    assert seen == [4000]


@pytest.mark.parametrize("text", ["", " \n", "reply"])
async def test_native_target_budget_and_truncation(monkeypatch, text):
    from argus.targets import anthropic_native as native
    resp = SimpleNamespace(content=[SimpleNamespace(text=text)], usage=SimpleNamespace(output_tokens=4000), stop_reason="end_turn")
    create = AsyncMock(return_value=resp)
    monkeypatch.setattr(native, "AsyncAnthropic", lambda **kw: SimpleNamespace(messages=SimpleNamespace(create=create)))
    target = native.AnthropicNativeTarget(native.AnthropicNativeSpec(model="fixture", api_key="fixture"))
    if text.strip():
        assert (await target.send_prompt("attack"))[0] == text
    else:
        with pytest.raises(llm.CompletionTruncated):
            await target.send_prompt("attack")
    assert create.await_args.kwargs["max_tokens"] == 4000


@pytest.mark.parametrize("text", ["", " \n", "reply"])
async def test_compat_target_budget_and_truncation(monkeypatch, text):
    from argus.targets import openai_compat as compat
    post = AsyncMock(return_value=httpx.Response(200, request=httpx.Request("POST", "https://test.invalid"), json={
        "choices": [{"message": {"content": text}}], "usage": {"completion_tokens": 4000}}))
    client = AsyncMock()
    client.__aenter__.return_value = SimpleNamespace(post=post)
    monkeypatch.setattr(compat.httpx, "AsyncClient", lambda **kw: client)
    target = compat.OpenAICompatTarget(compat.OpenAICompatSpec(endpoint_url="https://test.invalid", model="fixture"))
    if text.strip():
        assert (await target.send_prompt("attack"))[0] == text
    else:
        with pytest.raises(llm.CompletionTruncated):
            await target.send_prompt("attack")
    assert post.await_args.kwargs["json"]["max_tokens"] == 4000


@pytest.mark.parametrize("role", ["fast", "strong"])
async def test_judge_preserves_valid_reply_at_budget(monkeypatch, role):
    calls = stub(monkeypatch, json.dumps(dict(verdict="pass", severity="info", confidence=1, reasoning="safe")))
    verdict = await Judge("", CostMeter(daily_cap_usd=float("inf")), config())._call(role, "p", "a", "r", "rubric")
    assert verdict.verdict == "pass" and verdict.reasoning == "safe"
    assert calls[0]["max_tokens"] == 4000


@pytest.mark.parametrize("cls,kw", [(iterative_pair.PAIRProbe, {"seed_prompt": "attack"}),
                                   (iterative_tap.TAPProbe, {"seed_goal": "attack"})])
async def test_iterative_attacker_truncation_reports_error(monkeypatch, cls, kw):
    from pathlib import Path
    from argus.judge import Verdict
    from argus.runner import Runner
    stub(monkeypatch, "")
    target = SimpleNamespace(compatible_classes={"http-chat"}, supports_history=True,
                             send_prompt=AsyncMock(return_value=("safe reply", 1.0)))
    judge = SimpleNamespace(judge=AsyncMock(return_value=Verdict("pass", "info", 1, "safe", "fixture")))
    runner = Runner(target, judge, Path(__file__).resolve().parents[1] / "argus/rubrics")
    findings = [f async for f in runner.run_probe(cls(max_rounds=3, **kw))]
    finding = findings[-1]
    assert finding.verdict == "error"
    assert finding.evidence["stop_reason"] == "attacker_stopped"
    assert "CompletionTruncated" in finding.reasoning


async def test_scan_truncation_is_inconclusive_in_report(monkeypatch):
    from test_mcp_scan_findings import build, tool
    from argus.mcp_scan import checks
    from argus.mcp_scan.findings import unjudged_count
    stub(monkeypatch, "")
    cand = Candidate(probe_id=checks.DESCRIPTION, tool="a", text="body", call_seq=None, source="description")
    outcomes = await judging.JudgeGate(1, config(), "rubric").judge_all([cand], lambda s: s)
    report = build(outcomes=outcomes, listed=[tool("a")])
    assert unjudged_count(report) == 1
    finding = next(f for f in report if f["probe_id"] == checks.DESCRIPTION)
    assert finding["verdict"] == "error" and "CompletionTruncated" in finding["reasoning"]
    assert finding["evidence"]["error_code"] == "completion_truncated"


async def test_decider_empty_structured_answer_fails_closed(monkeypatch, caplog):
    from argus.decider import Decider
    from argus.judge import Verdict
    decider = Decider("fixture", "fixture", .8, 1, "https://test.invalid")
    post = AsyncMock(return_value=httpx.Response(200, request=httpx.Request("POST", "https://test.invalid"),
                                                json={"answers": {}, "usage": {"output_tokens": 4000}}))
    monkeypatch.setattr(decider, "_post", post)
    result = await decider.decide(probe_name="p", rubric_text="rubric", attack_prompt="a", target_response="r",
                                 fast=Verdict("pass", "high", 1, "safe", "fixture"), strong=None, strong_error="bad")
    assert result is None
    assert "KeyError" in caplog.text
    assert "max_tokens" not in post.await_args.args[0]


def test_target_truncation_maps_to_named_error():
    from argus.runner import _send_failure
    failure = _send_failure(llm.CompletionTruncated("empty completion"))
    assert failure[0] == "error" and "CompletionTruncated" in failure[1]
