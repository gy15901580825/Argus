"""Target ABC and shared spec model."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import ClassVar

_VALID_ROLES = frozenset({"user", "assistant"})


@dataclass(frozen=True)
class Turn:
    """One exchange in a conversation transcript.

    Only `user` and `assistant` are valid. System prompts belong to the target,
    not to the attacker — a probe that could set one would be testing a
    configuration it does not have in production.
    """

    role: str
    content: str

    def __post_init__(self) -> None:
        if self.role not in _VALID_ROLES:
            raise ValueError(
                f"invalid role {self.role!r}; must be one of {sorted(_VALID_ROLES)}"
            )


class Target(ABC):
    """Each Target implements `send_prompt(prompt, history) -> (response_text, latency_ms)`.

    Concurrency contract: send_prompt is called sequentially within a run — no
    shared mutable state between calls is required.

    Conversation state is *client-replayed*: the runner owns the transcript and
    passes it on every call, rather than relying on the target to mint and honour
    a session id. `history` is everything said before `prompt`; an empty tuple
    reproduces single-shot behaviour exactly.
    """

    # Each adapter declares which probe target_classes it serves.
    # TODO(Plan 4 T7): Runner will skip probes whose target_class is disjoint
    # from this set, emitting verdict=skipped. Until T7 lands, this field is
    # advisory metadata only.
    compatible_classes: ClassVar[frozenset[str]] = frozenset()

    # Whether this adapter can carry a conversation. Adapters that cannot must
    # still accept the `history` kwarg so the runner can call them uniformly;
    # the runner skips history-requiring probes rather than silently dropping
    # the transcript and reporting a defended verdict that was never tested.
    supports_history: ClassVar[bool] = False

    @abstractmethod
    async def send_prompt(
        self, prompt: str, history: tuple[Turn, ...] = ()
    ) -> tuple[str, float]:
        ...
