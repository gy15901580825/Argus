"""Tests for IterativeProbe base + Runner dispatch."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import AsyncIterator
from unittest.mock import AsyncMock, MagicMock

import pytest

from orchestrator.redteam.iterative import IterativeProbe, IterationContext
from orchestrator.redteam.probe import ProbeMappings
from orchestrator.redteam.runner import Runner


@dataclass
class _FakeIterativeProbe(IterativeProbe):
    """Minimal concrete iterative probe for tests."""
    id: str = "fake_iter"
    name: str = "fake"
    target_class: tuple[str, ...] = ("http-chat",)
    attack_class: tuple[str, ...] = ("iterative",)
    severity: str = "medium"
    judge_model: str = "claude-haiku-4-5-20251001"
    judge_rubric_path: str = "rubrics/iterative.md"
    iterative: bool = True
    max_rounds: int = 3
    mappings: ProbeMappings = field(default_factory=ProbeMappings)

    async def next_prompt(self, ctx: IterationContext) -> str | None:
        if ctx.round_n >= self.max_rounds:
            return None
        return f"round-{ctx.round_n}-prompt"


@pytest.mark.asyncio
async def test_iterative_probe_yields_one_finding_per_round(tmp_path):
    target = AsyncMock()
    target.send_prompt = AsyncMock(return_value=("response", 100.0))
    judge = MagicMock()
    judge.judge = AsyncMock(
        return_value=MagicMock(
            verdict="warn", severity="medium", confidence=0.6,
            reasoning="ambiguous", judge_model="haiku", escalated_model=None,
        )
    )
    rubrics_dir = tmp_path / "rubrics"
    rubrics_dir.mkdir()
    (rubrics_dir / "iterative.md").write_text("iter rubric")

    runner = Runner(target=target, judge=judge, rubrics_dir=rubrics_dir)
    probe = _FakeIterativeProbe()
    findings = [f async for f in runner.run_probe(probe)]
    assert len(findings) == 3
    assert [f.attack_prompt for f in findings] == ["round-0-prompt", "round-1-prompt", "round-2-prompt"]


@pytest.mark.asyncio
async def test_iterative_probe_terminates_early_on_fail_verdict(tmp_path):
    target = AsyncMock()
    target.send_prompt = AsyncMock(return_value=("response", 100.0))
    judge = MagicMock()
    # Round 0: warn (continue). Round 1: fail (stop).
    judge.judge = AsyncMock(side_effect=[
        MagicMock(verdict="warn", severity="medium", confidence=0.6, reasoning="r0", judge_model="haiku", escalated_model=None),
        MagicMock(verdict="fail", severity="high", confidence=0.9, reasoning="r1", judge_model="haiku", escalated_model=None),
    ])
    rubrics_dir = tmp_path / "rubrics"
    rubrics_dir.mkdir()
    (rubrics_dir / "iterative.md").write_text("iter rubric")

    runner = Runner(target=target, judge=judge, rubrics_dir=rubrics_dir)
    probe = _FakeIterativeProbe()
    findings = [f async for f in runner.run_probe(probe)]
    assert len(findings) == 2  # round 0 and 1, then early-stop on fail
    assert findings[-1].verdict == "fail"


@pytest.mark.asyncio
async def test_iterative_probe_threads_prior_verdicts_into_next_round(tmp_path):
    """Verify ctx.prior_prompts / prior_responses / prior_verdicts are correctly
    accumulated across rounds and visible to next_prompt(ctx). T2/T3 hold against this."""
    target = AsyncMock()
    target.send_prompt = AsyncMock(side_effect=[
        ("response-0", 100.0),
        ("response-1", 200.0),
    ])
    judge = MagicMock()
    judge.judge = AsyncMock(side_effect=[
        MagicMock(verdict="warn", severity="medium", confidence=0.5,
                  reasoning="r0", judge_model="haiku", escalated_model=None),
        MagicMock(verdict="warn", severity="medium", confidence=0.7,
                  reasoning="r1", judge_model="haiku", escalated_model=None),
    ])
    rubrics_dir = tmp_path / "rubrics"
    rubrics_dir.mkdir()
    (rubrics_dir / "iterative.md").write_text("iter rubric")

    @dataclass
    class _ContextReadingProbe(IterativeProbe):
        id: str = "ctx_reading"
        name: str = "ctx reading"
        target_class: tuple[str, ...] = ("http-chat",)
        attack_class: tuple[str, ...] = ("iterative",)
        severity: str = "medium"
        judge_model: str = "claude-haiku-4-5-20251001"
        judge_rubric_path: str = "rubrics/iterative.md"
        iterative: bool = True
        max_rounds: int = 2
        mappings: ProbeMappings = field(default_factory=ProbeMappings)
        observations: list[str] = field(default_factory=list)

        async def next_prompt(self, ctx: IterationContext) -> str | None:
            # Capture what the probe sees at each round.
            self.observations.append(
                f"round={ctx.round_n} "
                f"prior_prompts={list(ctx.prior_prompts)} "
                f"prior_responses={list(ctx.prior_responses)} "
                f"prior_verdicts={[v.verdict for v in ctx.prior_verdicts]}"
            )
            return f"prompt-{ctx.round_n}"

    runner = Runner(target=target, judge=judge, rubrics_dir=rubrics_dir)
    probe = _ContextReadingProbe()
    findings = [f async for f in runner.run_probe(probe)]
    assert len(findings) == 2
    # Round 0: empty priors
    assert "round=0 prior_prompts=[] prior_responses=[] prior_verdicts=[]" in probe.observations[0]
    # Round 1: prior is round 0's prompt/response/verdict
    assert "round=1 prior_prompts=['prompt-0'] prior_responses=['response-0'] prior_verdicts=['warn']" in probe.observations[1]
