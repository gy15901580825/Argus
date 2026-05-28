"""IterativeProbe abstract base — for attacks that mutate prompts across rounds.

Plan 2's static `Probe` dataclass declared `prompts: tuple[str, ...]` — the
runner just iterates it. Iterative attacks (TAP/PAIR/GCG) need a generator
that consumes prior-round verdicts to pick the next prompt. The runner
dispatches on `iterative=True`.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from orchestrator.redteam.judge import Verdict
from orchestrator.redteam.probe import ProbeMappings


@dataclass(frozen=True)
class IterationContext:
    """State threaded into next_prompt(): prior round, prior verdicts, prior responses."""
    round_n: int
    prior_prompts: tuple[str, ...] = field(default_factory=tuple)
    prior_responses: tuple[str, ...] = field(default_factory=tuple)
    prior_verdicts: tuple[Verdict, ...] = field(default_factory=tuple)


class IterativeProbe(ABC):
    """Abstract base. Concrete subclasses (TAP/PAIR/GCG) implement next_prompt."""

    id: str
    name: str
    target_class: tuple[str, ...]
    attack_class: tuple[str, ...]
    severity: str
    judge_model: str
    judge_rubric_path: str
    iterative: bool
    max_rounds: int
    mappings: ProbeMappings = ProbeMappings()

    @abstractmethod
    async def next_prompt(self, ctx: IterationContext) -> str | None:
        """Return the next prompt to send, or None to halt early.

        Implementations may inspect ctx.prior_verdicts to mutate based on judge feedback.
        Note: max_rounds is enforced by should_halt; subclasses do not need to re-check ctx.round_n >= max_rounds.
        """

    def should_halt(self, ctx: IterationContext) -> bool:
        """Default halt policy: stop if last verdict was 'fail' OR round >= max_rounds.
        Subclasses can override for attack-specific stopping criteria.
        """
        if ctx.round_n >= self.max_rounds:
            return True
        if ctx.prior_verdicts and ctx.prior_verdicts[-1].verdict == "fail":
            return True
        return False
