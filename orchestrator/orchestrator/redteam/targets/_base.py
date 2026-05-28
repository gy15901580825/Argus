"""Target ABC and shared spec model."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar


class Target(ABC):
    """Each Target implements `send_prompt(prompt) -> (response_text, latency_ms)`.

    Adapters live in this package, one per kind. Concurrency contract: send_prompt
    is called sequentially within a run — no shared mutable state between calls
    is required.
    """

    # Each adapter declares which probe target_classes it serves.
    # TODO(Plan 4 T7): Runner will skip probes whose target_class is disjoint
    # from this set, emitting verdict=skipped. Until T7 lands, this field is
    # advisory metadata only.
    compatible_classes: ClassVar[frozenset[str]] = frozenset()

    @abstractmethod
    async def send_prompt(self, prompt: str) -> tuple[str, float]:
        ...
