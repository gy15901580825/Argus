"""Anthropic Messages API wrapper with prompt caching.

Exports:
  build_request_args(): produces the kwargs dict for client.messages.create(),
    with cache_control placed on system, last tool, and (if history present)
    the last history message.
  create_client(): returns an anthropic.AsyncAnthropic instance using the
    configured key. Separated so tests can bypass it.
"""

from __future__ import annotations

from typing import Any

import anthropic

from orchestrator.config import ANTHROPIC_API_KEY, PLANNER_MODEL


def create_client() -> anthropic.AsyncAnthropic:
    return anthropic.AsyncAnthropic(api_key=ANTHROPIC_API_KEY)


def build_request_args(
    *,
    system_text: str,
    tools: list[dict],
    messages: list[dict],
    history_length: int = 0,
    max_tokens: int = 8192,
    model: str | None = None,
) -> dict[str, Any]:
    """Construct the kwargs for anthropic.messages.create() with 3 cache breakpoints.

    history_length: number of *historical* messages at the head of `messages`.
                    Everything from `messages[history_length:]` is the new user input.
                    Cache breakpoint goes on `messages[history_length - 1]` when history_length > 0.
    """
    # 1. System as a list of blocks, last block tagged cache_control
    system_blocks = [{"type": "text", "text": system_text,
                      "cache_control": {"type": "ephemeral"}}]

    # 2. Tools: clone + tag last one
    if not tools:
        tagged_tools = tools
    else:
        tagged_tools = [dict(t) for t in tools]
        tagged_tools[-1] = {**tagged_tools[-1], "cache_control": {"type": "ephemeral"}}

    # 3. Messages: tag the last history message's last content block
    out_messages = [dict(m) for m in messages]
    if history_length > 0:
        idx = history_length - 1
        hist = out_messages[idx]
        content = hist.get("content", "")
        if isinstance(content, str):
            blocks = [{"type": "text", "text": content,
                       "cache_control": {"type": "ephemeral"}}]
        else:
            blocks = [dict(b) for b in content]
            if blocks:
                blocks[-1] = {**blocks[-1], "cache_control": {"type": "ephemeral"}}
        out_messages[idx] = {**hist, "content": blocks}

    return {
        "model": model or PLANNER_MODEL,
        "max_tokens": max_tokens,
        "system": system_blocks,
        "tools": tagged_tools,
        "messages": out_messages,
    }
