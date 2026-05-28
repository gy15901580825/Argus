"""Event builders for the planner.

planner_step() produces the new SSE event type the frontend timeline consumes.
passthrough_event() wraps a sub-tool event into the SSE dict shape the runner yields.

All payloads are JSON-encoded strings (matching the rest of the orchestrator's SSE convention).
"""

from __future__ import annotations

import json
import time
from typing import Any


def planner_step(
    *,
    step_index: int,
    type: str,
    text: str | None = None,
    tool_name: str | None = None,
    tool_input: dict[str, Any] | None = None,
    tool_summary: str | None = None,
    error: str | None = None,
    reason: str | None = None,
    to: str | None = None,
) -> dict[str, str]:
    """Build a planner_step SSE event.

    Valid `type` values:
      - "thinking"        — intermediate text delta from the model
      - "tool_use_start"  — model issued a tool_use; include tool_name + tool_input
      - "tool_use_end"    — tool finished; include tool_name + tool_summary
      - "tool_error"      — tool raised; include tool_name + error
      - "fallback"        — switched to fallback model; include reason + to
      - "malformed"       — model output could not be parsed; retrying
      - "max_steps_hit"   — step cap reached, forcing summary
      - "done"            — planner finished this turn
    """
    payload: dict[str, Any] = {
        "type": type,
        "step_index": step_index,
        "timestamp": time.time(),
    }
    if text is not None:
        payload["text"] = text
    if tool_name is not None:
        payload["tool_name"] = tool_name
    if tool_input is not None:
        payload["tool_input"] = tool_input
    if tool_summary is not None:
        payload["tool_summary"] = tool_summary
    if error is not None:
        payload["error"] = error
    if reason is not None:
        payload["reason"] = reason
    if to is not None:
        payload["to"] = to

    return {"event_type": "planner_step", "payload": json.dumps(payload)}


def passthrough_event(*, event_type: str, payload: Any) -> dict[str, str]:
    """Wrap a tool's sub-event (e.g., ssh_result, web_ui_bug, wizard_round) for forwarding.

    Tools yield two payload shapes today:
      - raw dict (run_api_test → ssh_result, run_web_ui_* → web_ui_bug)
      - pre-encoded JSON string (offer_choices → wizard_round/aborted/guide,
        because the wizard_* builders in this module already json.dumps)

    Re-encoding a pre-encoded string would double-encode and break consumers
    that JSON.parse(payload) once (api_service _apply_event_to_state, frontend
    api.ts:785). Pass strings through; encode only dicts.
    """
    if isinstance(payload, str):
        return {"event_type": event_type, "payload": payload}
    return {"event_type": event_type, "payload": json.dumps(payload)}


def wizard_round(
    *,
    round_n: int,
    question: str,
    options: list[str],
    allow_free_text: bool,
    allow_back: bool,
    round_label: str,
) -> dict[str, str]:
    """Build a wizard_round SSE event."""
    payload = {
        "round_n": round_n,
        "question": question,
        "options": list(options),
        "allow_free_text": allow_free_text,
        "allow_back": allow_back,
        "round_label": round_label,
    }
    return {"event_type": "wizard_round", "payload": json.dumps(payload)}


def wizard_aborted(*, at_round_label: str, rounds_used: int) -> dict[str, str]:
    """Build a wizard_aborted SSE event."""
    payload = {"at_round_label": at_round_label, "rounds_used": rounds_used}
    return {"event_type": "wizard_aborted", "payload": json.dumps(payload)}


def wizard_guide(*, kind: str, markdown: str) -> dict[str, str]:
    """Build a wizard_guide SSE event."""
    payload = {"kind": kind, "markdown": markdown}
    return {"event_type": "wizard_guide", "payload": json.dumps(payload)}
