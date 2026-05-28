"""Sequentially run the 4 exploration phases, sharing one browser session."""
from __future__ import annotations

import logging
from typing import Any, Awaitable, Callable, Protocol

from web_ui_phases.budget import allocate_phase_budgets
from web_ui_phases.parser import extract_json_tail
from web_ui_phases.prompts import (
    build_auth_prompt,
    build_bug_hunt_prompt,
    build_discovery_prompt,
    build_features_prompt,
)
from web_ui_phases.state import PhaseResult, PhaseState

logger = logging.getLogger("WebUIPhases")


class AgentFactory(Protocol):
    """Callable that produces a browser-use Agent-like object.

    The real factory (in web_ui_runner.py) returns `browser_use.Agent(...)`
    bound to a shared browser_session. Tests inject fakes.
    """
    def __call__(self, task: str, **kwargs: Any) -> Any: ...


PhaseStartHook = Callable[[str, int], Awaitable[None]] | None
StepEndHook = Callable[[Any], Awaitable[None]] | None


async def _run_single_phase(
    *,
    phase_name: str,
    prompt: str,
    budget: int,
    agent_factory: AgentFactory,
    on_step_end: StepEndHook,
) -> PhaseResult:
    """Spawn one Agent, run it, return the parsed PhaseResult."""
    agent = agent_factory(task=prompt)
    kwargs: dict[str, Any] = {"max_steps": budget}
    if on_step_end is not None:
        kwargs["on_step_end"] = on_step_end
    history = await agent.run(**kwargs)

    try:
        raw = history.final_result() or ""
    except Exception:
        hist_list = getattr(history, "history", []) or []
        last = hist_list[-1] if hist_list else None
        raw = str(getattr(last, "result", "") or "") if last else ""

    steps_used = len(getattr(history, "history", []) or [])
    parsed = extract_json_tail(raw)
    if not parsed:
        logger.warning("Phase %s returned no parseable JSON tail", phase_name)
    return PhaseResult(phase=phase_name, raw_output=raw, parsed=parsed, steps_used=steps_used)


async def run_all_phases(
    *,
    state: PhaseState,
    max_steps: int,
    agent_factory: AgentFactory,
    on_phase_start: PhaseStartHook = None,
    on_step_end: StepEndHook = None,
) -> None:
    """Drive the 4-phase pipeline, mutating `state` in place."""
    has_creds = bool(state.credentials)
    budgets = allocate_phase_budgets(max_steps=max_steps, has_credentials=has_creds)

    if has_creds and budgets["auth"] > 0:
        if on_phase_start:
            await on_phase_start("auth", budgets["auth"])
        state.auth = await _run_single_phase(
            phase_name="auth",
            prompt=build_auth_prompt(state, budgets["auth"]),
            budget=budgets["auth"],
            agent_factory=agent_factory,
            on_step_end=on_step_end,
        )

    if on_phase_start:
        await on_phase_start("discovery", budgets["discovery"])
    state.discovery = await _run_single_phase(
        phase_name="discovery",
        prompt=build_discovery_prompt(state, budgets["discovery"]),
        budget=budgets["discovery"],
        agent_factory=agent_factory,
        on_step_end=on_step_end,
    )

    if on_phase_start:
        await on_phase_start("features", budgets["features"])
    features_result = await _run_single_phase(
        phase_name="features",
        prompt=build_features_prompt(state, budgets["features"]),
        budget=budgets["features"],
        agent_factory=agent_factory,
        on_step_end=on_step_end,
    )
    state.feature_results = features_result.parsed.get("features_tested", []) or []

    if on_phase_start:
        await on_phase_start("bug_hunt", budgets["bug_hunt"])
    bug_result = await _run_single_phase(
        phase_name="bug_hunt",
        prompt=build_bug_hunt_prompt(state, budgets["bug_hunt"]),
        budget=budgets["bug_hunt"],
        agent_factory=agent_factory,
        on_step_end=on_step_end,
    )
    state.bugs = bug_result.parsed.get("bugs", []) or []
