"""Fallback ReAct loop using LiteLlm(azure/gpt-5.4-mini).

Called by PlannerAgent when Anthropic is unavailable. Runs its own ReAct loop
over the same ToolRegistry. Tool-format translation: Anthropic tool_use ↔
OpenAI function tool_calls.

Temperature MUST NOT be passed — gpt-5.4-mini rejects it (CLAUDE.md gotcha #2).
"""

from __future__ import annotations

import json
from typing import Any, AsyncGenerator

from litellm import acompletion

from orchestrator.config import PLANNER_FALLBACK_MODEL


def anthropic_tools_to_openai_tools(tools: list[dict]) -> list[dict]:
    return [
        {
            "type": "function",
            "function": {
                "name": t["name"],
                "description": t["description"],
                "parameters": t["input_schema"],
            },
        }
        for t in tools
    ]


async def run_fallback_react(
    *,
    system_text: str,
    tools: list[dict],
    messages: list[dict],
    max_steps: int,
    tool_registry_get,
    ctx: Any,
) -> AsyncGenerator[dict, None]:
    """Minimal ReAct loop against gpt-5.4-mini.

    Yields dicts shaped like planner's yields:
      {"event_type": ..., "payload": ...}  for passthrough
      Final event type="result" with final text.
    """
    openai_tools = anthropic_tools_to_openai_tools(tools)
    # OpenAI wants system as first message
    wire_messages = [{"role": "system", "content": system_text}, *messages]

    for step in range(max_steps):
        resp = await acompletion(
            model=f"azure/{PLANNER_FALLBACK_MODEL}",
            messages=wire_messages,
            tools=openai_tools,
            stream=False,
        )
        choice = resp.choices[0]
        msg = choice.message

        # Append assistant message to context
        wire_messages.append({
            "role": "assistant",
            "content": msg.content or "",
            "tool_calls": getattr(msg, "tool_calls", None),
        })

        if not getattr(msg, "tool_calls", None):
            # end
            yield {"event_type": "result",
                   "payload": {"type": "result", "content": msg.content or ""}}
            return

        for tc in msg.tool_calls:
            fn_name = tc.function.name
            fn_args = json.loads(tc.function.arguments or "{}")
            try:
                tool_fn = tool_registry_get(fn_name)
            except KeyError:
                tool_result = json.dumps({"error": f"unknown tool {fn_name}"})
            else:
                tool_result = ""
                async for sub in tool_fn(**fn_args, ctx=ctx):
                    if sub.get("is_terminal"):
                        tool_result = sub["result"]
                    else:
                        yield sub
            wire_messages.append({
                "role": "tool",
                "tool_call_id": tc.id,
                "name": fn_name,
                "content": tool_result,
            })

    yield {"event_type": "error",
           "payload": {"type": "error",
                       "message": f"Fallback exceeded {max_steps} steps"}}
