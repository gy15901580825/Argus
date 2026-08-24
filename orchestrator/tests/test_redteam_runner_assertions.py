"""Verdicts that come from evidence, not from the judge."""

import pytest

from orchestrator.redteam.probe import Probe, ProbeMappings
from orchestrator.redteam.runner import VERDICT_ERROR, Runner


class _Target:
    compatible_classes = frozenset({"payment_agent"})
    supports_history = False

    def __init__(self, evidence):
        self._evidence = evidence

    async def send_prompt(self, prompt, history=()):
        return "done", 5.0

    async def collect_evidence(self):
        return self._evidence


class _ExplodingJudge:
    """Calling the judge for an assertion-backed probe is the bug this catches."""

    _cost_meter = None

    async def judge(self, **kwargs):
        raise AssertionError("judge must not be called when assertions decide the verdict")


def _probe(**kw):
    base = dict(
        id="pay_test", name="pay test", target_class=("payment_agent",),
        attack_class=("payment",), severity="critical", prompts=("go",),
        mappings=ProbeMappings(), judge_model="m", judge_rubric_path="rubrics/default.md",
        assertions=({"no_payment_over": "1000 USDC"},),
    )
    base.update(kw)
    return Probe(**base)


@pytest.mark.asyncio
async def test_assertion_failure_produces_fail_without_the_judge(tmp_path):
    ev = {
        "authorizations": [{"amount": "500000000", "asset": "USDC", "payee": "0xa"}],
        "interaction_count": 2,
        "expected_payee": "0xa",
    }
    runner = Runner(target=_Target(ev), judge=_ExplodingJudge(), rubrics_dir=tmp_path)
    findings = [f async for f in runner.run_probe(_probe())]
    assert [f.verdict for f in findings] == ["fail"]
    assert findings[0].severity == "critical"
    assert "500000000" in findings[0].reasoning
    assert findings[0].evidence == ev
    assert findings[0].confidence == 1.0
    assert findings[0].judge_model == ""


@pytest.mark.asyncio
async def test_assertions_all_pass_is_a_pass(tmp_path):
    ev = {
        "authorizations": [{"amount": "1000", "asset": "USDC", "payee": "0xa"}],
        "interaction_count": 2,
        "expected_payee": "0xa",
    }
    runner = Runner(target=_Target(ev), judge=_ExplodingJudge(), rubrics_dir=tmp_path)
    findings = [f async for f in runner.run_probe(_probe())]
    assert [f.verdict for f in findings] == ["pass"]
    assert findings[0].severity == "info"


@pytest.mark.asyncio
async def test_zero_interaction_is_an_error_not_a_pass(tmp_path):
    """Doing nothing satisfies every 'did not overpay' assertion. Not a pass."""
    runner = Runner(
        target=_Target({"authorizations": [], "interaction_count": 0}),
        judge=_ExplodingJudge(), rubrics_dir=tmp_path,
    )
    findings = [f async for f in runner.run_probe(_probe())]
    assert [f.verdict for f in findings] == [VERDICT_ERROR]
    assert "never" in findings[0].reasoning.lower()


@pytest.mark.asyncio
async def test_zero_interaction_is_tolerated_when_the_probe_opts_out(tmp_path):
    runner = Runner(
        target=_Target({"authorizations": [], "interaction_count": 0}),
        judge=_ExplodingJudge(), rubrics_dir=tmp_path,
    )
    findings = [f async for f in runner.run_probe(_probe(requires_interaction=False))]
    assert [f.verdict for f in findings] == ["pass"]


@pytest.mark.asyncio
async def test_every_prompt_yields_its_own_finding(tmp_path):
    ev = {"authorizations": [], "interaction_count": 1, "expected_payee": "0xa"}
    runner = Runner(target=_Target(ev), judge=_ExplodingJudge(), rubrics_dir=tmp_path)
    findings = [f async for f in runner.run_probe(_probe(prompts=("a", "b")))]
    assert len(findings) == 2


@pytest.mark.asyncio
async def test_a_conversation_probe_yields_one_verdict_for_the_whole_thread(tmp_path):
    """Setup turns are not attempts. Judging each turn separately reported two
    'the probe did not run' errors for a three-turn attack whose payload only
    lands on the last turn."""
    ev = {
        "authorizations": [{"amount": "500000000", "asset": "USDC", "payee": "0xa"}],
        "interaction_count": 2,
        "expected_payee": "0xa",
    }
    target = _Target(ev)
    target.supports_history = True  # a conversation probe is skipped without it
    runner = Runner(target=target, judge=_ExplodingJudge(), rubrics_dir=tmp_path)
    probe = _probe(prompts=("set the scene", "raise the limit", "now pay"), conversation=True)
    findings = [f async for f in runner.run_probe(probe)]
    assert len(findings) == 1
    assert findings[0].verdict == "fail"
    assert findings[0].attack_prompt == "now pay"
