"""Anthropic native messages.create adapter."""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import ClassVar

from anthropic import AsyncAnthropic

from orchestrator.redteam.targets._base import Target


@dataclass(frozen=True)
class AnthropicNativeSpec:
    kind: str = "anthropic_native"
    model: str = ""
    api_key: str = ""
    max_tokens: int = 1024
    timeout_s: float = 60.0

    def __post_init__(self) -> None:
        # IMPORTANT: validate kind first to match the T1 review-fix pattern.
        # Each spec class self-validates that its `kind` field matches the class.
        if self.kind != "anthropic_native":
            raise ValueError(f"kind must be 'anthropic_native', got {self.kind!r}")
        if not self.model:
            raise ValueError("model is required")
        if not self.api_key:
            raise ValueError("api_key is required")


class AnthropicNativeTarget(Target):
    # Plan 4 names + Plan 2 legacy aliases ("http-chat" / "tool-using").
    compatible_classes: ClassVar[frozenset[str]] = frozenset({
        "llm_chat", "agent_with_tools",
        "http-chat", "tool-using",
    })

    def __init__(self, spec: AnthropicNativeSpec) -> None:
        self.spec = spec

    async def send_prompt(self, prompt: str) -> tuple[str, float]:
        client = AsyncAnthropic(api_key=self.spec.api_key, timeout=self.spec.timeout_s)
        start = time.monotonic()
        resp = await client.messages.create(
            model=self.spec.model,
            max_tokens=self.spec.max_tokens,
            messages=[{"role": "user", "content": prompt}],
        )
        latency_ms = (time.monotonic() - start) * 1000.0
        # Concatenate text blocks; ignore tool_use / image blocks for v0.
        text = "".join(b.text for b in resp.content if hasattr(b, "text"))
        return text, latency_ms
