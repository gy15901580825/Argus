"""Judge output contract (reasoning before verdict) and the blank-reply guard in Judge.judge."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from argus import llm
from argus.cost_meter import CostMeter
from argus.judge import BLANK_REPLY_REASON, Judge, build_judge_prompts
from argus.runner import _no_text_reason


def _judge() -> Judge:
    return Judge(api_key="sk-ant-test", cost_meter=CostMeter(daily_cap_usd=10.0))


@pytest.mark.asyncio
@pytest.mark.parametrize("reply", ["", "   ", " \n\t \n", None])
async def test_blank_reply_is_an_error_without_a_model_call(reply, monkeypatch):
    called = []

    async def no_call(*a, **kw):
        called.append(kw)
        raise AssertionError("a blank reply must not reach a model")

    monkeypatch.setattr(llm, "complete", no_call)
    v = await _judge().judge("p", "attack", reply, "rubric")
    assert (v.verdict, v.severity, v.confidence) == ("error", "info", 1.0)
    assert v.reasoning == BLANK_REPLY_REASON
    assert v.judge_model == ""
    assert called == []


@pytest.mark.asyncio
async def test_blank_reply_guard_runs_before_the_jev_judge(monkeypatch):
    judge = _judge()
    monkeypatch.setattr(judge, "_cfg", MagicMock(provider=llm.PROVIDER_JEV))
    jev = AsyncMock(side_effect=AssertionError("a blank reply must not reach the jev judge"))
    monkeypatch.setattr("argus.jev_judge.judge", jev)
    v = await judge.judge("p", "attack", "  ", "rubric")
    assert v.verdict == "error" and v.reasoning == BLANK_REPLY_REASON
    jev.assert_not_awaited()


def test_blank_reply_reason_matches_the_runner_default():
    # A target with no kind gets the runner's generic hint.
    assert BLANK_REPLY_REASON == _no_text_reason(object())


def test_output_contract_asks_for_reasoning_before_verdict():
    system, _ = build_judge_prompts("p", "attack", "reply", "rubric")
    contract = system[system.index("# Output"):]
    order = [contract.index(f'"{k}"') for k in ("reasoning", "verdict", "severity", "confidence")]
    assert order == sorted(order)
    assert "overrides any order shown in the rubric" in contract


def _raw(text: str):
    r = MagicMock()
    r.content = [MagicMock(text=text)]
    r.usage = MagicMock(input_tokens=10, output_tokens=5)
    return r


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "keys",
    [
        ("verdict", "severity", "confidence", "reasoning"),  # the old order
        ("reasoning", "verdict", "severity", "confidence"),  # the order the contract now asks for
    ],
)
async def test_parser_accepts_either_key_order(keys):
    fields = {"verdict": "warn", "severity": "low", "confidence": 0.8, "reasoning": "offered to act"}
    text = json.dumps({k: fields[k] for k in keys})
    assert text.index(f'"{keys[0]}"') < text.index(f'"{keys[-1]}"')
    with patch("argus.llm._anthropic_client") as mock_client:
        client = AsyncMock()
        client.messages.create = AsyncMock(return_value=_raw(text))
        mock_client.return_value = client
        v = await _judge().judge("p", "attack", "reply", "rubric")
    assert (v.verdict, v.severity, v.confidence, v.reasoning) == ("warn", "low", 0.8, "offered to act")
