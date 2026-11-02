import pytest

from argus.probe import Probe, ProbeMappings
from argus.runner import Runner, VERDICT_BLOCKED_BY_TARGET, VERDICT_ERROR
from argus.targets._base import TargetBlockedError


class Agent:
    compatible_classes = frozenset({"mcp_agent"})
    supports_history = False

    def __init__(self, exc, evidence):
        self.exc = exc
        self.evidence = evidence

    async def send_prompt(self, prompt, history=()):
        raise self.exc

    async def collect_evidence(self):
        return self.evidence


class Judge:
    _cost_meter = None

    async def judge(self, **kwargs):
        raise AssertionError("a refused request cannot be judged")


def probe():
    return Probe(
        id="test_mapping",
        name="mapping",
        target_class=("mcp_agent",),
        attack_class=("mcp-abuse",),
        severity="high",
        prompts=("read the scenario",),
        mappings=ProbeMappings(),
        judge_model="m",
        judge_rubric_path="default.md",
        assertions=({"no_tool_call": "send_external"},),
    )


async def test_policy_refusal_final_blocked_but_untested(tmp_path):
    metadata = {
        "outcome": "blocked",
        "matched_rule_id": "policy",
        "origin": "mapped_body_rule",
        "http_status": 200,
        "exposure": "not_exercised",
    }
    exc = TargetBlockedError(
        "target API refused the request", transport_metadata=metadata
    )
    [finding] = [
        f
        async for f in Runner(
            target=Agent(exc, {}), judge=Judge(), rubrics_dir=tmp_path
        ).run_probe(probe())
    ]
    assert finding.verdict == VERDICT_BLOCKED_BY_TARGET
    assert finding.evidence["transport"] == metadata
    assert "scenario was not exercised" in finding.reasoning
    from argus.coverage import build_summary

    summary = build_summary(
        [{"verdict": finding.verdict, "severity": finding.severity}]
    )
    assert summary["evaluated"] == 0


async def test_unmapped_http_block_without_touch_still_errors(tmp_path):
    metadata = {
        "outcome": "blocked",
        "matched_rule_id": "policy",
        "origin": "mapped_body_rule",
        "http_status": 200,
    }
    exc = TargetBlockedError("generic refusal")
    [finding] = [
        f
        async for f in Runner(
            target=Agent(exc, {"transport": metadata}),
            judge=Judge(),
            rubrics_dir=tmp_path,
        ).run_probe(probe())
    ]
    assert finding.verdict == VERDICT_ERROR
    assert "never reached" in finding.reasoning
