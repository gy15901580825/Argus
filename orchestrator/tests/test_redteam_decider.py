"""Tests for the optional Jev decider and its wiring into the judge."""

import asyncio
import json
import logging
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from orchestrator.redteam import decider
from orchestrator.redteam.cost_meter import CostMeter
from orchestrator.redteam.judge import Judge, Verdict

URL = "https://api.typesafe.ai/v1/systemone"
CANARY = "tsk-canary-1234567890"

FAST = '{"verdict":"fail","severity":"high","confidence":0.9,"reasoning":"complied"}'
STRONG_PASS = '{"verdict":"pass","severity":"info","confidence":0.9,"reasoning":"refused"}'
STRONG_FAIL = '{"verdict":"fail","severity":"critical","confidence":0.95,"reasoning":"confirmed"}'
STRONG_WARN = '{"verdict":"warn","severity":"medium","confidence":0.8,"reasoning":"hm"}'
GARBAGE = "this is not json"


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for k in (
        "REDTEAM_DECIDER", "TYPESAFE_API_KEY", "REDTEAM_DECIDER_MODEL",
        "REDTEAM_DECIDER_GATE", "REDTEAM_DECIDER_TIMEOUT_S", "TYPESAFE_API_URL",
    ):
        monkeypatch.delenv(k, raising=False)


@pytest.fixture
def jev_on(monkeypatch):
    monkeypatch.setenv("REDTEAM_DECIDER", "jev")
    monkeypatch.setenv("TYPESAFE_API_KEY", CANARY)


def _answer(choice, confidence, probability=None, model="jev-2026-10"):
    others = {"fail": 0.1, "pass": 0.1, "insufficient_evidence": 0.1}
    others[choice] = probability if probability is not None else 0.9
    return {
        "model": model,
        "answers": {"verdict": {
            "type": "choice", "choice": choice,
            "confidence": confidence, "probabilities": others,
        }},
        "usage": {"input_tokens": 10, "output_tokens": 2},
    }


async def _judge(texts):
    """Run Judge.judge with the given model replies (fast first, then strong)."""
    replies = []
    for t in texts:
        r = MagicMock()
        r.content = [MagicMock(text=t)]
        r.usage = MagicMock(input_tokens=10, output_tokens=5)
        replies.append(r)
    with patch("orchestrator.redteam.llm._anthropic_client") as MockClient:
        client = AsyncMock()
        client.messages.create = AsyncMock(side_effect=replies)
        MockClient.return_value = client
        judge = Judge(api_key="sk-ant-test", cost_meter=CostMeter(daily_cap_usd=10.0))
        return await judge.judge(
            probe_name="p", attack_prompt="attack", target_response="resp", rubric_text="rubric",
        )


# ---- off by default -------------------------------------------------------


def test_from_env_off_by_default():
    assert decider.from_env() is None


def test_from_env_requires_exact_value_and_key(monkeypatch):
    monkeypatch.setenv("REDTEAM_DECIDER", "jev")
    assert decider.from_env() is None  # no key
    monkeypatch.setenv("TYPESAFE_API_KEY", "   ")
    assert decider.from_env() is None  # blank key
    monkeypatch.setenv("TYPESAFE_API_KEY", CANARY)
    monkeypatch.setenv("REDTEAM_DECIDER", "on")
    assert decider.from_env() is None  # other value
    monkeypatch.setenv("REDTEAM_DECIDER", "jev")
    assert decider.from_env() is not None


@pytest.mark.asyncio
async def test_off_sends_no_request(httpx_mock):
    with pytest.raises(ValueError):
        await _judge([FAST, GARBAGE])
    assert httpx_mock.get_requests() == []


@pytest.mark.asyncio
async def test_no_key_sends_no_request(httpx_mock, monkeypatch):
    monkeypatch.setenv("REDTEAM_DECIDER", "jev")
    with pytest.raises(ValueError):
        await _judge([FAST, GARBAGE])
    assert httpx_mock.get_requests() == []


# ---- case (a): strong reply cannot be parsed ------------------------------


@pytest.mark.asyncio
async def test_parse_failure_acted_fail(httpx_mock, jev_on):
    httpx_mock.add_response(url=URL, json=_answer("fail", 0.93, 0.96))
    v = await _judge([FAST, GARBAGE])
    assert (v.verdict, v.severity) == ("fail", "high")  # fast judge's severity
    assert v.escalated_model == "jev-2026-10"
    assert v.reasoning.endswith("| jev(jev-2026-10): fail p=0.96 conf=0.93 gate=0.80 -> acted")


@pytest.mark.asyncio
async def test_parse_failure_acted_pass(httpx_mock, jev_on):
    httpx_mock.add_response(url=URL, json=_answer("pass", 0.9, 0.95))
    v = await _judge([FAST, GARBAGE])
    assert (v.verdict, v.severity) == ("pass", "info")
    assert v.reasoning.endswith("-> acted")


@pytest.mark.asyncio
async def test_parse_failure_below_gate_is_warn(httpx_mock, jev_on):
    httpx_mock.add_response(url=URL, json=_answer("pass", 0.79, 0.9))
    v = await _judge([FAST, GARBAGE])
    assert (v.verdict, v.severity) == ("warn", "high")  # review, never pass
    assert v.escalated_model == "jev-2026-10"
    assert v.reasoning.endswith("pass p=0.90 conf=0.79 gate=0.80 -> review")


@pytest.mark.asyncio
async def test_parse_failure_insufficient_evidence_is_warn(httpx_mock, jev_on):
    httpx_mock.add_response(url=URL, json=_answer("insufficient_evidence", 0.99, 0.99))
    v = await _judge([FAST, GARBAGE])
    assert (v.verdict, v.severity) == ("warn", "high")
    assert v.reasoning.endswith("-> review")


@pytest.mark.asyncio
async def test_gate_is_configurable(httpx_mock, jev_on, monkeypatch):
    monkeypatch.setenv("REDTEAM_DECIDER_GATE", "0.5")
    httpx_mock.add_response(url=URL, json=_answer("fail", 0.6, 0.8))
    v = await _judge([FAST, GARBAGE])
    assert v.verdict == "fail"
    assert "gate=0.50 -> acted" in v.reasoning


# ---- fail closed ----------------------------------------------------------


@pytest.mark.asyncio
async def test_http_500_keeps_parse_error(httpx_mock, jev_on):
    httpx_mock.add_response(url=URL, status_code=500)
    with pytest.raises(ValueError):
        await _judge([FAST, GARBAGE])


@pytest.mark.asyncio
async def test_timeout_keeps_parse_error(httpx_mock, jev_on):
    httpx_mock.add_exception(httpx.ReadTimeout("slow"), url=URL)
    with pytest.raises(ValueError):
        await _judge([FAST, GARBAGE])


@pytest.mark.asyncio
async def test_malformed_answer_keeps_parse_error(httpx_mock, jev_on):
    httpx_mock.add_response(url=URL, json={"answers": {}})
    with pytest.raises(ValueError):
        await _judge([FAST, GARBAGE])


@pytest.mark.asyncio
async def test_unknown_choice_keeps_parse_error(httpx_mock, jev_on):
    httpx_mock.add_response(url=URL, json=_answer("maybe", 0.99, 0.99))
    with pytest.raises(ValueError):
        await _judge([FAST, GARBAGE])


@pytest.mark.asyncio
async def test_http_500_keeps_strong_verdict_on_conflict(httpx_mock, jev_on):
    httpx_mock.add_response(url=URL, status_code=500)
    v = await _judge([FAST, STRONG_PASS])
    assert (v.verdict, v.severity) == ("pass", "info")
    assert v.escalated_model == "claude-sonnet-4-6"
    assert "jev(" not in v.reasoning


# ---- case (b): fast and strong disagree -----------------------------------


@pytest.mark.asyncio
async def test_conflict_acted_uses_jev_choice(httpx_mock, jev_on):
    httpx_mock.add_response(url=URL, json=_answer("fail", 0.9, 0.95))
    v = await _judge([FAST, STRONG_WARN])
    assert (v.verdict, v.severity) == ("fail", "medium")  # strong judge's severity
    assert v.escalated_model == "jev-2026-10"
    assert v.reasoning.endswith("-> acted")


@pytest.mark.asyncio
async def test_conflict_acted_pass_is_info(httpx_mock, jev_on):
    httpx_mock.add_response(url=URL, json=_answer("pass", 0.9, 0.95))
    v = await _judge([FAST, STRONG_WARN])
    assert (v.verdict, v.severity) == ("pass", "info")


@pytest.mark.asyncio
async def test_conflict_below_gate_is_warn(httpx_mock, jev_on):
    httpx_mock.add_response(url=URL, json=_answer("pass", 0.5, 0.75))
    v = await _judge([FAST, STRONG_PASS])
    assert v.verdict == "warn"
    assert v.reasoning.endswith("-> review")
    assert v.escalated_model == "jev-2026-10"


@pytest.mark.asyncio
async def test_agreement_never_calls_jev(httpx_mock, jev_on):
    v = await _judge([FAST, STRONG_FAIL])
    assert v.verdict == "fail"
    assert httpx_mock.get_requests() == []


@pytest.mark.asyncio
async def test_no_escalation_never_calls_jev(httpx_mock, jev_on):
    v = await _judge(['{"verdict":"pass","severity":"info","confidence":0.9,"reasoning":"ok"}'])
    assert v.verdict == "pass"
    assert httpx_mock.get_requests() == []


# ---- request shape and secrecy --------------------------------------------


@pytest.mark.asyncio
async def test_request_shape_and_key_only_in_header(httpx_mock, jev_on, caplog):
    caplog.set_level(logging.DEBUG)
    httpx_mock.add_response(url=URL, json=_answer("fail", 0.9, 0.95))
    await _judge([FAST, GARBAGE])
    (req,) = httpx_mock.get_requests()
    assert req.method == "POST"
    assert req.headers["Authorization"] == f"Bearer {CANARY}"
    assert req.headers["Content-Type"] == "application/json"
    body = json.loads(req.content)
    assert body["model"] == "jev-latest"
    q = body["questions"]["verdict"]
    assert q["type"] == "choice"
    assert set(q["criteria"]) == {"fail", "pass", "insufficient_evidence"}
    st = body["state"]
    assert (st["probe"], st["rubric"], st["attack_prompt"], st["target_response"]) == (
        "p", "rubric", "attack", "resp",
    )
    assert st["fast_judge"]["verdict"] == "fail"
    assert "error" in st["strong_judge"]
    assert CANARY not in req.content.decode()
    assert CANARY not in caplog.text


@pytest.mark.asyncio
async def test_key_not_logged_on_failure(httpx_mock, jev_on, caplog):
    caplog.set_level(logging.DEBUG)
    httpx_mock.add_response(url=URL, status_code=500)
    with pytest.raises(ValueError):
        await _judge([FAST, GARBAGE])
    assert CANARY not in caplog.text


@pytest.mark.asyncio
async def test_strong_verdict_in_state_when_parsed(httpx_mock, jev_on):
    httpx_mock.add_response(url=URL, json=_answer("fail", 0.9, 0.95))
    await _judge([FAST, STRONG_PASS])
    st = json.loads(httpx_mock.get_requests()[0].content)["state"]
    assert st["strong_judge"] == {"verdict": "pass", "severity": "info", "reasoning": "refused"}


@pytest.mark.asyncio
async def test_config_env_overrides(httpx_mock, jev_on, monkeypatch):
    monkeypatch.setenv("REDTEAM_DECIDER_MODEL", "jev-x")
    monkeypatch.setenv("TYPESAFE_API_URL", "https://ts.example/v1/systemone")
    httpx_mock.add_response(url="https://ts.example/v1/systemone", json=_answer("fail", 0.9, 0.95, model="jev-x"))
    await _judge([FAST, GARBAGE])
    assert json.loads(httpx_mock.get_requests()[0].content)["model"] == "jev-x"


def test_timeout_configurable(monkeypatch, jev_on):
    assert decider.from_env()._timeout_s == 20.0
    monkeypatch.setenv("REDTEAM_DECIDER_TIMEOUT_S", "3")
    assert decider.from_env()._timeout_s == 3.0


@pytest.mark.asyncio
async def test_text_fields_truncated_at_8000(httpx_mock, jev_on):
    httpx_mock.add_response(url=URL, json=_answer("fail", 0.9, 0.95))
    d = decider.from_env()
    v = Verdict(verdict="fail", severity="high", confidence=0.9, reasoning="r", judge_model="m")
    await d.decide(
        probe_name="p", rubric_text="R" * 20000, attack_prompt="A" * 8000,
        target_response="T" * 8001, fast=v, strong=None, strong_error="e",
    )
    st = json.loads(httpx_mock.get_requests()[0].content)["state"]
    assert len(st["rubric"]) < 8100 and st["rubric"].startswith("R" * 8000)
    assert "[truncated]" in st["rubric"]
    assert st["attack_prompt"] == "A" * 8000  # at the limit: untouched
    assert "[truncated]" in st["target_response"]


@pytest.mark.asyncio
async def test_total_deadline_returns_none(jev_on, monkeypatch, caplog):
    """A response that never finishes (slow drip) is cut off by the total deadline."""
    monkeypatch.setenv("REDTEAM_DECIDER_TIMEOUT_S", "0.05")

    async def never(self, *a, **kw):
        await asyncio.sleep(30)

    monkeypatch.setattr(httpx.AsyncClient, "post", never)
    d = decider.from_env()
    v = Verdict(verdict="fail", severity="high", confidence=0.9, reasoning="r", judge_model="m")
    loop = asyncio.get_running_loop()
    start = loop.time()
    out = await d.decide(
        probe_name="p", rubric_text="r", attack_prompt="a", target_response="t",
        fast=v, strong=None, strong_error="e",
    )
    assert out is None
    assert loop.time() - start < 5
    assert "TimeoutError" in caplog.text


@pytest.mark.parametrize("raw", ["nan", "inf", "-inf"])
@pytest.mark.parametrize("name,default", [
    ("REDTEAM_DECIDER_GATE", 0.8), ("REDTEAM_DECIDER_TIMEOUT_S", 20.0),
])
def test_non_finite_env_falls_back(monkeypatch, caplog, name, default, raw):
    monkeypatch.setenv(name, raw)
    assert decider._float_env(name, default, max_value=1.0 if "GATE" in name else None) == default
    assert "out of range" in caplog.text


@pytest.mark.parametrize("raw", ["0", "-0.5", "1.5"])
def test_gate_out_of_range_falls_back(monkeypatch, jev_on, caplog, raw):
    monkeypatch.setenv("REDTEAM_DECIDER_GATE", raw)
    assert decider.from_env()._gate == 0.8
    assert "REDTEAM_DECIDER_GATE" in caplog.text


def test_gate_upper_bound_inclusive(monkeypatch, jev_on):
    monkeypatch.setenv("REDTEAM_DECIDER_GATE", "1")
    assert decider.from_env()._gate == 1.0


@pytest.mark.parametrize("raw", ["0", "-3"])
def test_timeout_non_positive_falls_back(monkeypatch, jev_on, caplog, raw):
    monkeypatch.setenv("REDTEAM_DECIDER_TIMEOUT_S", raw)
    assert decider.from_env()._timeout_s == 20.0
    assert "REDTEAM_DECIDER_TIMEOUT_S" in caplog.text
