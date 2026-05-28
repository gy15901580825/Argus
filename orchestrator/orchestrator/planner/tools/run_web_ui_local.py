"""run_web_ui_local tool — dispatch to the user's local client_agent.

Delegates the start/poll/fetch flow to orchestrator.agents.common.client_web_ui_runner
(shared with the legacy ADK ClientWebUIAgent). This tool only handles the
planner-envelope translation: passthrough events, summary accumulation,
and the terminal `is_terminal` frame.
"""

from __future__ import annotations

import json
import logging
from typing import Any, AsyncGenerator

logger = logging.getLogger(__name__)


def _session_state(ctx: Any) -> dict:
    try:
        return ctx.session.state  # type: ignore[attr-defined]
    except AttributeError:
        return {}


async def run_web_ui_local(
    *,
    url: str,
    persona: str | None = None,
    max_steps: int = 30,
    auth: dict | None = None,
    ctx: Any,
) -> AsyncGenerator[dict, None]:
    from orchestrator.agents.common.client_web_ui_runner import run_client_web_ui

    state = _session_state(ctx)
    user_id = state.get("user_id")
    auth_token = state.get("auth_token")
    cdp_url = state.get("cdp_url")
    credentials = (auth or {}).get("credentials") or state.get("credentials")
    business_context = state.get("business_context")
    browser_model = state.get("browser_model")
    script_model = state.get("script_model")

    summary: dict[str, Any] = {
        "bugs_found": 0,
        "script_generated": False,
        "task_id": None,
        "status": None,
    }
    fatal_error: str | None = None

    async for sub in run_client_web_ui(
        url=url,
        user_id=user_id,
        auth_token=auth_token,
        cdp_url=cdp_url,
        max_steps=max_steps,
        user_persona=persona or "new_user",
        credentials=credentials,
        business_context=business_context,
        browser_model=browser_model,
        script_model=script_model,
    ):
        et = sub.get("event_type")
        payload = sub.get("payload", {})

        if et == "web_ui_artifact":
            summary["script_generated"] = True
        elif et == "web_ui_bug":
            summary["task_id"] = payload.get("task_id")
            summary["status"] = payload.get("status")
            counts = payload.get("bug_counts") or {}
            summary["bugs_found"] = sum(
                int(counts.get(k, 0) or 0)
                for k in ("critical", "high", "medium", "low")
            )
        elif et == "error":
            fatal_error = payload.get("message") or "local client_agent failed"

        yield {"is_terminal": False, "event_type": et, "payload": payload}

    if fatal_error:
        yield {"is_terminal": True, "result": json.dumps(
            {"error": fatal_error, **summary}, default=str)}
    else:
        yield {"is_terminal": True, "result": json.dumps(summary, default=str)}
