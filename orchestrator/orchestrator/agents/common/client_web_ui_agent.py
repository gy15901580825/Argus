"""ClientWebUIAgent — ADK adapter over the shared client_web_ui_runner.

Thin wrapper: pulls config from session state, drives `run_client_web_ui`,
and translates the runner's protocol-agnostic dicts into ADK Events.
"""

import json
import logging
from typing import AsyncGenerator

from typing_extensions import override
from google.adk.agents.base_agent import BaseAgent, BaseAgentConfig
from google.adk.events.event import Event
from google.adk.agents.invocation_context import InvocationContext
from google.genai import types

from orchestrator.agents.common.client_web_ui_runner import (
    _active_tasks,  # re-exported: server.py cancel endpoint + tests mutate this
    run_client_web_ui,
)

logger = logging.getLogger(__name__)

__all__ = ["ClientWebUIAgent", "client_web_ui_agent", "_active_tasks"]


class ClientWebUIAgentConfig(BaseAgentConfig):
    pass


class ClientWebUIAgent(BaseAgent):
    """Delegates Web UI exploration to the user's local client_agent via WebSocket."""

    config_type = ClientWebUIAgentConfig

    @override
    async def _run_async_impl(
        self, ctx: InvocationContext
    ) -> AsyncGenerator[Event, None]:
        state = ctx.session.state
        url = (
            state.get("target_url")
            or state.get("url")
            or state.get("website_url")
        )
        if not url or url == "NO_URL_PROVIDED":
            yield self._log(ctx, "⚠️ [ClientWebUIAgent] No target URL in session state.")
            return

        async for sub in run_client_web_ui(
            url=url,
            user_id=state.get("user_id"),
            auth_token=state.get("auth_token"),
            cdp_url=state.get("cdp_url") or None,
            max_steps=int(state.get("max_steps", 100)),
            user_persona=state.get("user_persona", "new_user"),
            credentials=state.get("credentials"),
            business_context=state.get("business_context"),
            browser_model=state.get("browser_model"),
            script_model=state.get("script_model"),
        ):
            et = sub.get("event_type")
            payload = sub.get("payload", {})
            if et == "log":
                yield self._log(ctx, f"[ClientWebUIAgent] {payload.get('message', '')}")
            elif et == "error":
                yield self._log(ctx, f"❌ [ClientWebUIAgent] {payload.get('message', '')}")
            else:
                # artifact / result — emit as JSON payload for frontend dispatch
                yield Event(
                    invocation_id=ctx.invocation_id,
                    author=self.name,
                    content=types.Content(parts=[types.Part(text=json.dumps(payload))]),
                )

    def _log(self, ctx: InvocationContext, message: str) -> Event:
        return Event(
            invocation_id=ctx.invocation_id,
            author=self.name,
            content=types.Content(parts=[types.Part(text=message)]),
        )


client_web_ui_agent = ClientWebUIAgent(
    name="ClientWebUITestingAgent",
    description=(
        "Executes browser-based Web UI testing on the user's LOCAL machine via a "
        "connected client agent. Required when the target URL is on an intranet or "
        "when the user wants to use their own Chrome instance (--remote-debugging-port)."
    ),
)
