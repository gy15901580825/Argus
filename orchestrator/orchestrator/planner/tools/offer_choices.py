"""offer_choices — wizard-only planner tool.

Emits a wizard_round SSE event, then a terminal envelope with stop_turn=True
so the ReAct loop halts until api_service receives the user's next click and
re-enters the planner with a new /strategy/stream call."""

from __future__ import annotations

import logging
from typing import Any, AsyncGenerator

from orchestrator.planner.events import wizard_round

logger = logging.getLogger(__name__)

_VALID_LABELS = {
    "intent", "run_where", "credentials", "persona",
    "target_url", "local_setup_check", "confirm", "other",
}
_MAX_OPTIONS = 6
_MAX_OPTION_LEN = 60
_MAX_QUESTION_LEN = 200


async def offer_choices(
    *,
    question: str,
    options: list[str] | None = None,
    allow_free_text: bool = False,
    round_label: str = "other",
    ctx: Any,
) -> AsyncGenerator[dict, None]:
    options = list(options or [])
    allow_free_text = bool(allow_free_text)

    if not options and not allow_free_text:
        yield {
            "is_terminal": True,
            "result": ("Tool error: offer_choices called with no options and "
                       "allow_free_text=false. Provide options or set "
                       "allow_free_text=true."),
            "tool_validation_error": True,  # consumed by PlannerAgent for downgrade tracking
            # No stop_turn: let the LLM retry once this round.
        }
        return

    # Coerce
    clean_options = [
        (o or "")[:_MAX_OPTION_LEN]
        for o in options[:_MAX_OPTIONS]
        if o
    ]
    clean_question = (question or "")[:_MAX_QUESTION_LEN]
    label = round_label if round_label in _VALID_LABELS else "other"

    ws = _read_wizard_state(ctx)
    round_n = int(ws.get("round_n") or 1)
    allow_back = _allow_back(ws)

    logger.info("wizard_round_emitted", extra={
        "session_id": getattr(getattr(ctx, "session", None), "id", None),
        "round_n": round_n,
        "round_label": label,
        "options_count": len(clean_options),
        "allow_free_text": allow_free_text,
    })

    yield {
        "is_terminal": False,
        **wizard_round(
            round_n=round_n,
            question=clean_question,
            options=clean_options,
            allow_free_text=allow_free_text,
            allow_back=allow_back,
            round_label=label,
        ),
    }
    yield {
        "is_terminal": True,
        "result": f"Emitted wizard_round {round_n} (label={label}); awaiting user.",
        "stop_turn": True,
    }


def _read_wizard_state(ctx: Any) -> dict:
    state = getattr(getattr(ctx, "session", None), "state", None) or {}
    ws = state.get("wizard_state") or {}
    if not isinstance(ws, dict):
        return {}
    return ws


def _allow_back(ws: dict) -> bool:
    if ws.get("dispatched"):
        return False
    rounds = ws.get("rounds") or []
    for r in rounds:
        if r.get("answer_kind") in ("option_click", "free_text"):
            return True
    return False
