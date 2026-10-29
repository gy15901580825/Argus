"""Anthropic native messages.create adapter."""
from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import ClassVar

from anthropic import AsyncAnthropic

from argus.targets._base import Target, TargetBlockedError, Turn


@dataclass(frozen=True)
class AnthropicNativeSpec:
    kind: str = "anthropic_native"
    model: str = ""
    api_key: str = ""
    max_tokens: int = 1024
    timeout_s: float = 120.0

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
    supports_history: ClassVar[bool] = True

    # Plan 4 names + Plan 2 legacy aliases ("http-chat" / "tool-using").
    compatible_classes: ClassVar[frozenset[str]] = frozenset({
        "llm_chat", "agent_with_tools",
        "http-chat", "tool-using",
    })

    def __init__(self, spec: AnthropicNativeSpec) -> None:
        self.spec = spec

    async def send_prompt(
        self, prompt: str, history: tuple[Turn, ...] = ()
    ) -> tuple[str, float]:
        # One retry, so the longest wait for a reply is 2 x timeout_s, as the docs say.
        client = AsyncAnthropic(api_key=self.spec.api_key, timeout=self.spec.timeout_s, max_retries=1)
        messages = [{"role": t.role, "content": t.content} for t in history]
        messages.append({"role": "user", "content": prompt})
        start = time.monotonic()
        resp = await client.messages.create(
            model=self.spec.model,
            max_tokens=self.spec.max_tokens,
            messages=messages,
        )
        latency_ms = (time.monotonic() - start) * 1000.0
        # Concatenate text blocks. A reply that only calls tools is judged on its calls.
        text = "".join(b.text for b in resp.content if hasattr(b, "text"))
        if not text.strip():
            text = "\n".join(
                f"[tool_call] {b.name}({json.dumps(b.input, ensure_ascii=False)})"
                for b in resp.content if getattr(b, "type", None) == "tool_use"
            )
        if not text.strip() and getattr(resp, "stop_reason", None) == "refusal":
            raise TargetBlockedError("target refused to answer (stop_reason: refusal)")
        return text, latency_ms
