"""OpenAI-compatible chat-completions target adapter."""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import ClassVar, Optional

import httpx

from orchestrator.redteam.targets._base import Target, Turn


@dataclass(frozen=True)
class OpenAICompatSpec:
    kind: str = "openai_compat"
    endpoint_url: str = ""
    model: str = ""
    api_key: Optional[str] = None
    extra_headers: tuple[tuple[str, str], ...] = ()
    timeout_s: float = 30.0

    def __post_init__(self) -> None:
        # Allow callers to pass headers as dict OR list-of-2-element-lists
        # (model_dump() emits list-of-lists for tuple fields).
        hdrs = self.extra_headers
        if isinstance(hdrs, dict):
            object.__setattr__(self, "extra_headers", tuple(hdrs.items()))
        elif isinstance(hdrs, list):
            object.__setattr__(self, "extra_headers", tuple(tuple(h) for h in hdrs))
        if self.kind != "openai_compat":
            raise ValueError(f"kind must be 'openai_compat', got {self.kind!r}")
        if not self.endpoint_url:
            raise ValueError("endpoint_url is required")
        if not self.model:
            raise ValueError("model is required")


class OpenAICompatTarget(Target):
    # New (Plan 4) names + legacy (Plan 2) aliases. Plan 2-3 probe YAMLs still
    # carry "http-chat" / "tool-using" — accept both vocabularies.
    supports_history: ClassVar[bool] = True

    compatible_classes: ClassVar[frozenset[str]] = frozenset({
        "llm_chat", "agent_with_tools",
        "http-chat", "tool-using",
    })

    def __init__(self, spec: OpenAICompatSpec) -> None:
        self.spec = spec

    async def send_prompt(
        self, prompt: str, history: tuple[Turn, ...] = ()
    ) -> tuple[str, float]:
        headers = dict(self.spec.extra_headers)
        if self.spec.api_key:
            headers.setdefault("Authorization", f"Bearer {self.spec.api_key}")
        messages = [{"role": t.role, "content": t.content} for t in history]
        messages.append({"role": "user", "content": prompt})
        body = {"model": self.spec.model, "messages": messages}
        start = time.monotonic()
        async with httpx.AsyncClient(timeout=self.spec.timeout_s) as client:
            resp = await client.post(self.spec.endpoint_url, headers=headers, json=body)
            resp.raise_for_status()
            data = resp.json()
        latency_ms = (time.monotonic() - start) * 1000.0
        # The endpoint is user-supplied, so the body may not be OpenAI-shaped at
        # all ({"error": ...} with HTTP 200, an empty choices array). A KeyError
        # here would escape the runner's 4xx handling and kill the whole run
        # rather than yielding one empty response.
        choices = data.get("choices") if isinstance(data, dict) else None
        first = choices[0] if isinstance(choices, list) and choices else {}
        message = first.get("message") if isinstance(first, dict) else None
        text = ""
        if isinstance(message, dict):
            text = message.get("content") or message.get("refusal") or ""
        return text, latency_ms
