"""A testbed network error fails one probe, never the whole scan."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from argus.probe import Probe, ProbeMappings
from argus.runner import VERDICT_ERROR, Runner

_GOOD_EVIDENCE = {
    "authorizations": [{"amount": "500000000", "asset": "USDC", "payee": "0xa"}],
    "interaction_count": 2,
    "expected_payee": "0xa",
}


def _status_error(code: int) -> httpx.HTTPStatusError:
    request = httpx.Request("GET", "http://testbed.local/sessions/s1/evidence")
    response = httpx.Response(code, request=request)
    return httpx.HTTPStatusError(f"{code} session expired", request=request, response=response)


class _FlakyTarget:
    """collect_evidence raises on the calls listed in `fail_on` (1-based)."""

    compatible_classes = frozenset({"payment_agent"})
    supports_history = False

    def __init__(self, fail_on=(), exc=None, begin_exc=None):
        self._fail_on = set(fail_on)
        self._exc = exc
        self._begin_exc = begin_exc
        self.calls = 0
        self.sent = []

    async def begin_probe(self, probe):
        if self._begin_exc is not None and probe.id == "pay_0":
            raise self._begin_exc

    async def send_prompt(self, prompt, history=()):
        self.sent.append(prompt)
        return "done", 5.0

    async def collect_evidence(self):
        self.calls += 1
        if self.calls in self._fail_on:
            raise self._exc
        return dict(_GOOD_EVIDENCE)


class _ExplodingJudge:
    _cost_meter = None

    async def judge(self, **kwargs):
        raise AssertionError("judge must not be called for assertion-backed probes")


def _probe(pid, **kw):
    base = dict(
        id=pid, name=pid, target_class=("payment_agent",),
        attack_class=("payment",), severity="critical", prompts=(f"go {pid}",),
        mappings=ProbeMappings(), judge_model="m", judge_rubric_path="rubrics/default.md",
        assertions=({"no_payment_over": "1000 USDC"},),
    )
    base.update(kw)
    return Probe(**base)


@pytest.mark.asyncio
async def test_evidence_error_on_one_assertion_probe_errors_only_that_probe(tmp_path):
    target = _FlakyTarget(fail_on={2}, exc=_status_error(404))
    runner = Runner(target=target, judge=_ExplodingJudge(), rubrics_dir=tmp_path)
    findings = []
    for pid in ("pay_0", "pay_1", "pay_2"):
        findings += [f async for f in runner.run_probe(_probe(pid))]
    assert [f.verdict for f in findings] == ["fail", VERDICT_ERROR, "fail"]
    err = findings[1]
    assert err.severity == "info"
    assert err.confidence == 1.0
    assert err.evidence is None
    assert "could not read evidence from the testbed" in err.reasoning
    assert "404" in err.reasoning
    # No refetch after the failure: one fetch per probe.
    assert target.calls == 3


@pytest.mark.asyncio
async def test_evidence_error_after_a_judged_verdict_keeps_the_verdict(tmp_path):
    target = _FlakyTarget(fail_on={1}, exc=httpx.ConnectError("connection refused"))
    judge = MagicMock()
    judge._cost_meter = None
    judge.judge = AsyncMock(return_value=MagicMock(
        verdict="fail", severity="high", confidence=0.8,
        reasoning="complied", judge_model="haiku", escalated_model=None,
    ))
    (tmp_path / "default.md").write_text("rubric")  # a judged probe needs its rubric file
    runner = Runner(target=target, judge=judge, rubrics_dir=tmp_path)
    findings = [f async for f in runner.run_probe(_probe("judged", assertions=()))]
    assert len(findings) == 1
    f = findings[0]
    assert f.verdict == "fail"
    assert f.severity == "high"
    assert f.evidence is None
    assert f.reasoning.startswith("complied")
    assert "evidence unavailable" in f.reasoning
    assert "connection refused" in f.reasoning


@pytest.mark.asyncio
async def test_begin_probe_network_error_is_one_error_finding(tmp_path):
    target = _FlakyTarget(begin_exc=httpx.ConnectError("testbed unreachable"))
    runner = Runner(target=target, judge=_ExplodingJudge(), rubrics_dir=tmp_path)
    first = [f async for f in runner.run_probe(_probe("pay_0"))]
    second = [f async for f in runner.run_probe(_probe("pay_1"))]
    assert [f.verdict for f in first] == [VERDICT_ERROR]
    assert "could not set up this probe" in first[0].reasoning
    assert "testbed unreachable" in first[0].reasoning
    assert [f.verdict for f in second] == ["fail"]
    assert target.sent == ["go pay_1"]


def test_sse_stream_reaches_coverage_when_one_evidence_fetch_fails(monkeypatch):
    from fastapi.testclient import TestClient
    from argus.server import app

    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    target = _FlakyTarget(fail_on={1}, exc=_status_error(404))
    body = {
        "target": {"kind": "payment_agent"},
        "probe_ids": ["pay_approval_forged", "pay_approval_threshold_split"],
    }
    with patch("argus.api.build_target", lambda spec: target):
        client = TestClient(app)
        with client.stream("POST", "/redteam/run", json=body) as resp:
            assert resp.status_code == 200
            lines = list(resp.iter_lines())
    assert "event: error" not in lines
    payloads = [json.loads(c[len("data: "):]) for c in lines
                if c.startswith("data: ") and c != "data: {}"]
    verdicts = [p["verdict"] for p in payloads if "verdict" in p]
    assert verdicts == [VERDICT_ERROR, "fail"]
    assert payloads[-1]["type"] == "coverage"


@pytest.mark.asyncio
async def test_blocked_assertion_probe_still_gets_session_evidence(tmp_path):
    """Only a failed fetch stops the post-hoc attach. A 4xx-blocked round of an
    assertion-backed probe still shows what the agent already did."""

    class _Blocking(_FlakyTarget):
        async def send_prompt(self, prompt, history=()):
            request = httpx.Request("POST", "http://agent.local/chat")
            response = httpx.Response(403, request=request)
            raise httpx.HTTPStatusError("403", request=request, response=response)

    runner = Runner(target=_Blocking(), judge=_ExplodingJudge(), rubrics_dir=tmp_path)
    findings = [f async for f in runner.run_probe(_probe("pay_0"))]
    assert [f.verdict for f in findings] == ["blocked_by_target"]
    assert findings[0].evidence == _GOOD_EVIDENCE
