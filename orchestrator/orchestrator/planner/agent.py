"""PlannerAgent — orchestrator entrypoint, ReAct loop against Claude Opus 4.7.

Scaffold for happy path first; Tasks 3.4–3.6 add tool_use execution,
max_steps fallback, and exception handling.
"""

from __future__ import annotations

import anthropic
import json
import logging
from typing import Any, AsyncGenerator

from google.adk.agents import BaseAgent
from google.adk.agents.invocation_context import InvocationContext
from google.adk.events import Event
from google.genai import types

from orchestrator.config import (
    API_SERVICE_BASE_URL,
    ORCHESTRATOR_SECRET,
    PLANNER_HISTORY_LIMIT,
    PLANNER_MAX_STEPS,
    WIZARD_MODE_ENABLED,
)
from orchestrator.planner.anthropic_client import build_request_args, create_client
from orchestrator.planner.events import planner_step, passthrough_event
from orchestrator.planner.fallback_client import run_fallback_react
from orchestrator.planner.memory import load_core_history
from orchestrator.planner.prompts import SYSTEM_PROMPT, TOOL_SCHEMAS, SYSTEM_PROMPT_WIZARD, WIZARD_TOOL_SCHEMAS
from orchestrator.planner.tools import ToolRegistry

logger = logging.getLogger(__name__)


class PlannerAgent(BaseAgent):
    """ReAct-style orchestrator planner."""

    async def _run_async_impl(
        self, ctx: InvocationContext
    ) -> AsyncGenerator[Event, None]:
        user_text = self._build_user_message(ctx)
        session_id = getattr(ctx.session, "id", "unknown")
        user_id = ctx.session.state.get("user_id", "unknown")
        history = await load_core_history(
            session_id=session_id, user_id=user_id, limit=PLANNER_HISTORY_LIMIT,
            api_service_base_url=API_SERVICE_BASE_URL, service_secret=ORCHESTRATOR_SECRET,
        )
        messages: list[dict[str, Any]] = [
            *history, {"role": "user", "content": user_text}
        ]
        client = create_client()

        # Resolve mode once per turn
        state = ctx.session.state or {}
        ws = state.get("wizard_state")
        mode = self._select_mode(wizard_state=ws, flag_enabled=WIZARD_MODE_ENABLED)
        system_text, tool_schemas = self._select_prompt_and_tools(mode)

        try:
            async for ev in self._run_anthropic_loop(
                client=client, messages=messages, history_length=len(history),
                ctx=ctx, system_text=system_text, tool_schemas=tool_schemas,
            ):
                yield ev
        except (anthropic.AuthenticationError,
                anthropic.RateLimitError,
                anthropic.APIConnectionError,
                anthropic.APIStatusError) as e:
            reason = self._classify_error(e)
            yield self._emit(planner_step(
                step_index=0, type="fallback",
                reason=reason, to="gpt-5.4-mini"))
            async for sub in run_fallback_react(
                system_text=system_text,
                tools=tool_schemas,
                messages=messages,
                max_steps=PLANNER_MAX_STEPS,
                tool_registry_get=ToolRegistry.get,
                ctx=ctx,
            ):
                yield self._emit(passthrough_event(
                    event_type=sub["event_type"], payload=sub["payload"]))
        except Exception as e:
            logger.exception("Planner unexpected failure")
            yield self._emit(planner_step(
                step_index=0, type="fallback",
                reason="unexpected", to="gpt-5.4-mini"))
            async for sub in run_fallback_react(
                system_text=system_text,
                tools=tool_schemas,
                messages=messages,
                max_steps=PLANNER_MAX_STEPS,
                tool_registry_get=ToolRegistry.get,
                ctx=ctx,
            ):
                yield self._emit(passthrough_event(
                    event_type=sub["event_type"], payload=sub["payload"]))

    def _select_mode(
        self, *, wizard_state: dict | None, flag_enabled: bool,
    ) -> str:
        if wizard_state is None:
            return "wizard" if flag_enabled else "free_text"
        if wizard_state.get("active") is True:
            return "wizard"
        return "free_text"

    def _select_prompt_and_tools(self, mode: str):
        if mode == "wizard":
            return SYSTEM_PROMPT_WIZARD, WIZARD_TOOL_SCHEMAS
        return SYSTEM_PROMPT, TOOL_SCHEMAS

    async def _run_anthropic_loop(
        self, *, client, messages, history_length, ctx,
        system_text: str, tool_schemas: list,
    ) -> AsyncGenerator[Event, None]:
        """ReAct loop against Anthropic client."""
        ask_user_count = 0
        offer_choices_validation_errors = 0  # consecutive; reset on any non-error offer_choices
        downgraded_to_ask_user = False
        usage = {
            "input_tokens": 0, "output_tokens": 0,
            "cache_read": 0, "cache_write": 0,
            "tools_called": [],
        }

        for step_index in range(PLANNER_MAX_STEPS):
            request_args = build_request_args(
                system_text=system_text, tools=tool_schemas,
                messages=messages, history_length=history_length,
            )

            async with client.messages.stream(**request_args) as stream:
                async for stream_event in stream:
                    et = getattr(stream_event, "type", None)
                    if et == "content_block_delta":
                        delta = getattr(stream_event, "delta", None)
                        if delta and getattr(delta, "text", None):
                            yield self._emit(planner_step(
                                step_index=step_index, type="thinking",
                                text=delta.text))
                final = await stream.get_final_message()

            self._accumulate_usage(usage, final)

            # Append the assistant turn to messages verbatim for the next loop
            messages.append({
                "role": "assistant",
                "content": [self._serialize_block(b) for b in final.content],
            })

            if final.stop_reason == "end_turn":
                final_text = "".join(
                    getattr(b, "text", "") for b in final.content
                    if getattr(b, "type", None) == "text"
                )
                yield self._emit(passthrough_event(
                    event_type="result",
                    payload={"type": "result", "content": final_text},
                ))
                yield self._emit(planner_step(step_index=step_index, type="done"))
                self._log_summary(ctx, usage, step_index + 1, "end_turn")
                return

            if final.stop_reason == "tool_use":
                tool_use_blocks = [
                    b for b in final.content if getattr(b, "type", None) == "tool_use"
                ]
                tool_results: list[dict[str, Any]] = []
                stop_turn_after_tools = False

                for tool_use in tool_use_blocks:
                    name = getattr(tool_use, "name", "")
                    tool_input = getattr(tool_use, "input", {}) or {}
                    tool_id = getattr(tool_use, "id", "")
                    usage["tools_called"].append(name)

                    if name == "ask_user":
                        ask_user_count += 1

                    yield self._emit(planner_step(
                        step_index=step_index, type="tool_use_start",
                        tool_name=name, tool_input=tool_input,
                    ))

                    try:
                        tool_fn = ToolRegistry.get(name)
                    except KeyError:
                        tool_results.append({
                            "type": "tool_result", "tool_use_id": tool_id,
                            "content": f"Unknown tool: {name}",
                            "is_error": True,
                        })
                        yield self._emit(planner_step(
                            step_index=step_index, type="tool_error",
                            tool_name=name, error="unknown tool"))
                        continue

                    result_text = ""
                    saw_validation_error = False
                    try:
                        async for sub in tool_fn(**tool_input, ctx=ctx):
                            if sub.get("is_terminal"):
                                result_text = sub.get("result", "")
                                if sub.get("tool_validation_error"):
                                    saw_validation_error = True
                                if sub.get("stop_turn"):
                                    stop_turn_after_tools = True
                            else:
                                yield self._emit(passthrough_event(
                                    event_type=sub["event_type"],
                                    payload=sub["payload"],
                                ))
                    except Exception as e:
                        logger.exception("Tool %s raised", name)
                        result_text = f"Tool error: {e}"
                        tool_results.append({
                            "type": "tool_result", "tool_use_id": tool_id,
                            "content": result_text, "is_error": True,
                        })
                        yield self._emit(planner_step(
                            step_index=step_index, type="tool_error",
                            tool_name=name, error=str(e)))
                        continue

                    # Track consecutive offer_choices validation errors
                    if name == "offer_choices":
                        if saw_validation_error:
                            offer_choices_validation_errors += 1
                        else:
                            offer_choices_validation_errors = 0  # LLM corrected itself

                    tool_results.append({
                        "type": "tool_result", "tool_use_id": tool_id,
                        "content": result_text,
                        "is_error": saw_validation_error,
                    })
                    yield self._emit(planner_step(
                        step_index=step_index, type="tool_use_end",
                        tool_name=name, tool_summary=result_text[:200]))

                messages.append({"role": "user", "content": tool_results})

                if offer_choices_validation_errors >= 2 and not downgraded_to_ask_user:
                    downgraded_to_ask_user = True
                    logger.info("wizard_validation_exhausted", extra={
                        "session_id": getattr(ctx.session, "id", None),
                        "step_index": step_index,
                    })
                    messages.append({
                        "role": "user",
                        "content": (
                            "Your last two offer_choices calls were rejected for "
                            "missing options. Stop calling offer_choices for this "
                            "turn. Respond directly to the user as plain text with "
                            "a single focused clarifying question."
                        ),
                    })

                if stop_turn_after_tools:
                    yield self._emit(planner_step(
                        step_index=step_index, type="done",
                        tool_summary="ask_user_stopped_turn"))
                    self._log_summary(ctx, usage, step_index + 1, "ask_user_stopped")
                    return
                continue  # next step

            # Other stop_reasons (max_tokens, pause_turn, etc.) — treat as done
            yield self._emit(planner_step(
                step_index=step_index, type="done",
                tool_summary=f"stop_reason={final.stop_reason}",
            ))
            self._log_summary(ctx, usage, step_index + 1, final.stop_reason or "unknown")
            return

        # max_steps exhausted — ask planner for a forced summary
        yield self._emit(planner_step(
            step_index=PLANNER_MAX_STEPS, type="max_steps_hit"))
        messages.append({
            "role": "user",
            "content": (
                "You have reached the maximum planning steps. "
                "Output a concise summary (≤100 words) of what you have done "
                "and the key results so far. Do not call any more tools."
            ),
        })
        summary_args = build_request_args(
            system_text=system_text, tools=[], messages=messages,
            history_length=0,
        )
        async with client.messages.stream(**summary_args) as stream:
            async for _ in stream:
                pass
            final = await stream.get_final_message()
        self._accumulate_usage(usage, final)
        summary_text = "".join(
            getattr(b, "text", "") for b in final.content
            if getattr(b, "type", None) == "text"
        )
        yield self._emit(passthrough_event(
            event_type="result",
            payload={"type": "result", "content": summary_text},
        ))
        self._log_summary(ctx, usage, PLANNER_MAX_STEPS, "max_steps_hit")

    def _accumulate_usage(self, usage: dict, final) -> None:
        u = getattr(final, "usage", None)
        if not u:
            return
        usage["input_tokens"] += getattr(u, "input_tokens", 0) or 0
        usage["output_tokens"] += getattr(u, "output_tokens", 0) or 0
        usage["cache_read"] += getattr(u, "cache_read_input_tokens", 0) or 0
        usage["cache_write"] += getattr(u, "cache_creation_input_tokens", 0) or 0

    def _log_summary(
        self, ctx, usage: dict, steps_used: int, final_status: str
    ) -> None:
        extra = {
            "session_id": getattr(ctx.session, "id", None),
            "user_id": ctx.session.state.get("user_id"),
            "steps_used": steps_used,
            "tools_called": list(usage["tools_called"]),
            "input_tokens": usage["input_tokens"],
            "output_tokens": usage["output_tokens"],
            "cache_read_tokens": usage["cache_read"],
            "cache_write_tokens": usage["cache_write"],
            "final_status": final_status,
        }
        try:
            ctx.session.state["planner_usage"] = extra
        except Exception:
            pass
        logger.info("planner_request_summary %s", json.dumps(extra), extra=extra)

    def _classify_error(self, exc) -> str:
        """Classify Anthropic exceptions into fallback reason codes."""
        if isinstance(exc, anthropic.AuthenticationError):
            return "auth"
        if isinstance(exc, anthropic.RateLimitError):
            return "rate_limit"
        if isinstance(exc, anthropic.APIConnectionError):
            return "connection"
        if isinstance(exc, anthropic.APIStatusError):
            return f"status_{exc.status_code}"
        return "unknown"

    def _serialize_block(self, block) -> dict[str, Any]:
        t = getattr(block, "type", None)
        if t == "text":
            return {"type": "text", "text": getattr(block, "text", "")}
        if t == "tool_use":
            return {
                "type": "tool_use",
                "id": getattr(block, "id", ""),
                "name": getattr(block, "name", ""),
                "input": getattr(block, "input", {}) or {},
            }
        return {"type": t or "unknown"}

    # ---- helpers ----

    def _extract_user_text(self, ctx: InvocationContext) -> str:
        if getattr(ctx, "user_content", None):
            uc = ctx.user_content
            parts = getattr(uc, "parts", None) or []
            return "".join(getattr(p, "text", "") or "" for p in parts)
        return ""

    def _build_user_message(self, ctx: InvocationContext) -> str:
        """Combine the raw user text with a structured session-context block.

        Execution flags (local_test_enabled, cdp_url, remote_test_enabled,
        ssh_config, user_persona) are pulled from ctx.session.state so the
        planner's routing decisions don't depend on upstream stringification
        of the context dict into the user message.

        In wizard mode, also surface wizard_state.bound_context and the
        prior rounds (with answers) so the LLM knows what's been resolved
        and what to ask next — without this block the LLM has no memory
        of prior rounds and re-emits offer_choices for "intent" forever.
        """
        user_text = (self._extract_user_text(ctx) or "").strip()
        state = ctx.session.state or {}
        flags_block = self._format_context_flags(state)
        wizard_block = self._format_wizard_state(state.get("wizard_state"))
        sections = [s for s in (user_text, wizard_block, flags_block) if s]
        return "\n\n".join(sections)

    def _format_context_flags(self, state: dict) -> str:
        cdp = state.get("cdp_url")
        ssh = state.get("ssh_config")
        lines = [
            "SESSION CONTEXT (execution flags — use these to pick the right tool):",
            f"- local_test_enabled: {bool(state.get('local_test_enabled'))}",
            f"- remote_test_enabled: {bool(state.get('remote_test_enabled'))}",
            f"- cdp_url: {cdp or '(none)'}",
            f"- ssh_config: {'provided' if ssh else '(none)'}",
        ]
        persona = state.get("user_persona")
        if persona:
            lines.append(f"- user_persona: {persona}")
        return "\n".join(lines)

    def _format_wizard_state(self, ws) -> str:
        if not isinstance(ws, dict) or not ws.get("active"):
            return ""
        bc = ws.get("bound_context") or {}
        round_n = ws.get("round_n", 1)
        rounds = ws.get("rounds") or []

        def _fmt_bound(key: str) -> str:
            v = bc.get(key)
            if v is None or v == "":
                return "(unset)"
            if isinstance(v, bool):
                return "true" if v else "false"
            return str(v)

        lines = [
            "WIZARD STATE — read this BEFORE deciding the next round:",
            f"- current round_n: {round_n}",
            "- bound_context (already resolved; do NOT re-ask these):",
            f"    url: {_fmt_bound('url')}",
            f"    test_env: {_fmt_bound('test_env')}",
            f"    persona: {_fmt_bound('persona')}",
            f"    ssh_config_present: {_fmt_bound('ssh_config_present')}",
            f"    cdp_url_present: {_fmt_bound('cdp_url_present')}",
            f"    client_agent_connected: {_fmt_bound('client_agent_connected')}",
            f"    cdp_browser_reachable: {_fmt_bound('cdp_browser_reachable')}",
        ]
        if rounds:
            lines.append("- prior rounds (n / round_label / question → answer):")
            for r in rounds:
                ans = r.get("answer")
                ans_str = (
                    f"\"{ans}\" ({r.get('answer_kind') or 'unanswered'})"
                    if ans is not None else "(unanswered — currently pending)"
                )
                q = (r.get("question") or "")[:80]
                lines.append(
                    f"    R{r.get('n')} [{r.get('round_label') or 'other'}] "
                    f"{q!r} → {ans_str}"
                )
        else:
            lines.append("- prior rounds: (none yet — this is the first round)")
        lines.append(
            "Next-round rules: skip rounds whose slot is already in bound_context; "
            "do NOT re-ask anything in 'prior rounds' that is answered; advance "
            "toward the R5 confirm round."
        )
        return "\n".join(lines)

    def _emit(self, event_dict: dict[str, str]) -> Event:
        return Event(
            invocation_id="planner",
            author=self.name,
            content=types.Content(parts=[types.Part(text=json.dumps(event_dict))]),
        )
