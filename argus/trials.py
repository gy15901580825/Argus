from __future__ import annotations

import datetime
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING, TypeAlias, Union
from uuid import UUID

if TYPE_CHECKING:
    from argus.runner import Finding

JSONValue: TypeAlias = Union[None, bool, int, float, str, list["JSONValue"], dict[str, "JSONValue"]]


def snapshot(value: object) -> JSONValue:
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, (datetime.datetime, datetime.date, UUID)):
        return str(value) if isinstance(value, UUID) else value.isoformat()
    if isinstance(value, (list, tuple)):
        return [snapshot(item) for item in value]
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise TypeError("trial evidence requires string dictionary keys")
        return {key: snapshot(item) for key, item in value.items()}
    raise TypeError(f"unsupported trial evidence value: {type(value).__name__}")


@dataclass(frozen=True)
class TrialRecord:
    trial: int
    verdict: str
    reason_code: str | None
    reason: str
    clean: JSONValue
    attack: JSONValue

    def __post_init__(self) -> None:
        object.__setattr__(self, "clean", snapshot(self.clean))
        object.__setattr__(self, "attack", snapshot(self.attack))

    def as_dict(self) -> dict[str, JSONValue]:
        return {"trial": self.trial, "verdict": self.verdict,
                "reason_code": self.reason_code, "reason": self.reason,
                "clean": snapshot(self.clean), "attack": snapshot(self.attack)}


def snapshot_finding(finding: "Finding") -> dict[str, JSONValue]:
    return {"attack_prompt": finding.attack_prompt,
            "target_response": finding.target_response,
            "verdict": finding.verdict, "reasoning": finding.reasoning,
            "target_latency_ms": finding.target_latency_ms,
            "evidence": snapshot(finding.evidence)}


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
