"""ask_user tool — yield a clarification event and terminate the turn.

The planner loop treats the terminal result as the tool_result content, but after
this tool runs the planner should stop-after-this-turn; that logic lives in the
ReAct loop. Here we only emit the clarification event + result.
"""

from __future__ import annotations

from typing import Any, AsyncGenerator


async def ask_user(*, question: str, ctx: Any) -> AsyncGenerator[dict, None]:
    yield {
        "is_terminal": False,
        "event_type": "log",
        "payload": {
            "type": "log",
            "category": "clarification_needed",
            "question": question,
        },
    }
    yield {
        "is_terminal": True,
        "result": f"Asked user: {question}. Turn ends; wait for user reply.",
        "stop_turn": True,
    }
