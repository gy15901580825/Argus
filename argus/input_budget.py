"""Shared target input limits and the history sent on the wire."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from argus.targets._base import Turn


@dataclass(frozen=True)
class InputLimits:
    max_message_chars: int | None = None
    max_history_chars: int | None = None

    @classmethod
    def from_spec(cls, spec: dict) -> InputLimits:
        if "input_limits" not in spec:
            return cls()
        values = spec["input_limits"]
        if not isinstance(values, dict):
            raise ValueError("input_limits must be an object")
        unknown = values.keys() - {"max_message_chars", "max_history_chars"}
        if unknown:
            raise ValueError(f"input_limits has unknown fields: {sorted(unknown)}")
        for name, value in values.items():
            if type(value) is not int or value <= 0:
                raise ValueError(f"input_limits.{name} must be a positive integer")
        return cls(**values)


def fit_history(history: tuple[Turn, ...], max_chars: int | None) -> tuple[tuple[Turn, ...], int]:
    """Drop oldest complete exchanges; the current message is outside this budget.

    The runner builds history as consecutive user/assistant pairs and keeps its
    complete transcript independently of this wire view.
    """
    if max_chars is None:
        return history, 0
    total = sum(len(turn.content) for turn in history)
    dropped = 0
    while total > max_chars and dropped < len(history):
        total -= sum(len(turn.content) for turn in history[dropped:dropped + 2])
        dropped += 2
    return history[dropped:], dropped
