from __future__ import annotations

import datetime
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType

COUNT_KEYS = (
    "attempted",
    "pass",
    "fail",
    "warn",
    "error",
    "skipped",
    "blocked_by_target",
)
INCOMPLETE_TRIALS = "incomplete_trials"


@dataclass(frozen=True)
class TrialSummary:
    counts: Mapping[str, int]
    valid: int
    verdict: str
    reason_code: str | None

    def counts_line(self) -> str:
        return (
            " ".join(f"{key}={self.counts[key]}" for key in COUNT_KEYS)
            + f" valid={self.valid}"
        )

    def sentence(self) -> str:
        return f"{self.counts['fail']} of {self.valid} valid trials failed ({self.counts['attempted']} attempted; {self.counts['error']} error, {self.counts['skipped']} skipped)."

    def as_dict(self) -> dict:
        return {
            **self.counts,
            "valid": self.valid,
            "verdict": self.verdict,
            "reason_code": self.reason_code,
        }


def aggregate_trials(
    verdicts: Sequence[str], *, stopped_at_cost_cap: bool = False
) -> TrialSummary:
    allowed = set(COUNT_KEYS[1:]) | {"aborted_cost"}
    if any(v not in allowed for v in verdicts):
        raise ValueError("unknown trial verdict")
    counts = {key: verdicts.count(key) for key in COUNT_KEYS[1:]}
    counts = {"attempted": len(verdicts), **counts}
    valid = counts["pass"] + counts["fail"] + counts["warn"]
    reason = None
    if counts["fail"]:
        verdict = "fail"
    elif counts["warn"]:
        verdict = "warn"
    elif stopped_at_cost_cap:
        verdict = "aborted_cost"
    elif verdicts and all(v == "pass" for v in verdicts):
        verdict = "pass"
    elif verdicts and all(v == "skipped" for v in verdicts):
        verdict = "skipped"
    elif verdicts and all(v == "blocked_by_target" for v in verdicts):
        verdict = "blocked_by_target"
    else:
        verdict, reason = "error", INCOMPLETE_TRIALS
    return TrialSummary(MappingProxyType(counts), valid, verdict, reason)


def pass_wording(trials: int, on: datetime.date) -> str:
    return f"Not observed in this environment on {on.isoformat()} in {trials} of {trials} trials; a pass is weak evidence, not proof of safety."
