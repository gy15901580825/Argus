"""Pure-function transitions on WizardState. No DB, no network.

The router layer reads current state from DB, calls these, writes the result
back. This keeps transitions unit-testable without a running Postgres."""

from __future__ import annotations

from typing import Any, Literal, Optional

from models import (
    BoundContext, WizardInput, WizardRound, WizardState,
)


class StaleRoundError(Exception):
    """wizardInput.roundN does not match current wizard_state.round_n."""


class InvalidTransitionError(Exception):
    """Transition is not permitted in the current state (e.g., back at round_n=1)."""


def initialize_wizard_state(
    *,
    test_env: Optional[Literal["cloud", "my_machine", "remote_ssh"]],
    ssh_config_present: bool,
    cdp_url_present: bool,
    persona: Optional[str],
    url: Optional[str],
    client_agent_connected: bool = False,
    cdp_browser_reachable: bool = False,
) -> WizardState:
    return WizardState(
        active=True,
        round_n=1,
        rounds=[],
        bound_context=BoundContext(
            url=url,
            test_env=test_env,
            ssh_config_present=ssh_config_present,
            cdp_url_present=cdp_url_present,
            persona=persona,
            client_agent_connected=client_agent_connected,
            cdp_browser_reachable=cdp_browser_reachable,
        ),
        dispatched=False,
    )


def synthesize_fast_forward(
    *,
    bound_context: BoundContext,
    parsed_slots: dict[str, str],
    now: float,
) -> WizardState:
    """Pre-populate rounds[0..3] when the user's first message + bound_context
    cover all four pre-confirm slots. Each round gets answer_kind=
    'bound_context_skip' (when the slot was bound from a UI toggle) or
    'parsed_from_text' (when derived from the message). round_n is set to 5
    so the planner immediately emits R5 confirm.

    Bound values always win over parsed values for the same slot.
    """
    SLOT_TO_LABEL: list[tuple[str, str, str]] = [
        ("intent", "intent", "What would you like to do?"),
        ("run_where", "run_where", "Where does it run?"),
        ("persona", "persona", "Persona?"),
        ("target_url", "target_url", "Target URL?"),
    ]
    bound_for_slot: dict[str, Optional[str]] = {
        "run_where": bound_context.test_env,
        "persona": bound_context.persona,
        "target_url": bound_context.url,
    }
    rounds: list[WizardRound] = []
    for n, (slot, label, question) in enumerate(SLOT_TO_LABEL, start=1):
        bound_val = bound_for_slot.get(slot)
        if bound_val:
            answer = bound_val
            kind: Literal["parsed_from_text", "bound_context_skip"] = "bound_context_skip"
        else:
            answer = parsed_slots.get(slot, "")
            kind = "parsed_from_text"
        rounds.append(WizardRound(
            n=n,
            question=question,
            options=[],
            allow_free_text=False,
            round_label=label,  # type: ignore[arg-type]
            answer=answer,
            answer_kind=kind,
            answered_at=now,
        ))
    return WizardState(
        active=True,
        round_n=5,
        rounds=rounds,
        bound_context=bound_context,
        dispatched=False,
    )


def apply_wizard_input(
    state: WizardState, user_input: WizardInput, *, now: float,
) -> WizardState:
    # abort short-circuits
    if user_input.kind == "abort":
        return state.model_copy(update={
            "active": False, "rounds": [], "round_n": 0,
        })

    if user_input.roundN != state.round_n:
        raise StaleRoundError(
            f"input roundN={user_input.roundN} != state.round_n={state.round_n}"
        )

    if user_input.kind == "back":
        target_idx = _latest_click_index(state)
        if target_idx is None:
            raise InvalidTransitionError(
                "No prior clicked round to back to; back must be hidden here."
            )
        truncated = state.rounds[:target_idx]
        target_round = state.rounds[target_idx].model_copy(update={
            "answer": None, "answer_kind": None, "answered_at": None,
        })
        new_rounds = [*truncated, target_round]
        return state.model_copy(update={
            "rounds": new_rounds, "round_n": target_idx + 1,
        })

    # Literal must match the W3 option label in
    # orchestrator/orchestrator/planner/prompts.py SYSTEM_PROMPT_WIZARD.
    # "Switch to cloud mode" forward-overwrite (spec §6.3 W3):
    # When user clicks this option in a local_setup_check round, rewrite the
    # earlier run_where round's answer to "cloud" so the planner stops
    # re-entering local_setup_check on the next turn. Does NOT rewind round_n —
    # this is forward progress, not a back action.
    if (
        user_input.kind == "option_click"
        and user_input.value == "Switch to cloud mode"
        and state.rounds
        and state.rounds[-1].n == state.round_n
        and state.rounds[-1].round_label == "local_setup_check"
    ):
        new_rounds = list(state.rounds)
        rewritten = False
        for i, r in enumerate(new_rounds[:-1]):
            if r.round_label == "run_where":
                new_rounds[i] = r.model_copy(update={
                    "answer": "cloud",
                    "answer_kind": "option_click",
                    "answered_at": now,
                })
                rewritten = True
                break
        if not rewritten:
            raise InvalidTransitionError(
                "'Switch to cloud mode' clicked but no prior run_where round "
                "to rewrite; planner should not have emitted local_setup_check "
                "without a prior run_where round."
            )
        new_rounds[-1] = new_rounds[-1].model_copy(update={
            "answer": user_input.value,
            "answer_kind": "option_click",
            "answered_at": now,
        })
        return state.model_copy(update={
            "rounds": new_rounds,
            "round_n": state.round_n + 1,
        })

    # option_click / free_text
    if not state.rounds or state.rounds[-1].n != state.round_n:
        raise InvalidTransitionError(
            f"no pending round at round_n={state.round_n}; "
            f"orchestrator has not emitted wizard_round yet"
        )

    kind: Literal["option_click", "free_text"] = user_input.kind  # type: ignore[assignment]
    pending = state.rounds[-1].model_copy(update={
        "answer": user_input.value,
        "answer_kind": kind,
        "answered_at": now,
    })
    return state.model_copy(update={
        "rounds": [*state.rounds[:-1], pending],
        "round_n": state.round_n + 1,
    })


def append_round_from_event(
    state: WizardState, event_payload: dict[str, Any],
) -> WizardState:
    """Called when the orchestrator emits a wizard_round SSE event."""
    new_round = WizardRound(
        n=event_payload["round_n"],
        question=event_payload["question"],
        options=list(event_payload.get("options") or []),
        allow_free_text=bool(event_payload.get("allow_free_text", False)),
        round_label=event_payload["round_label"],
    )
    # Replace the trailing pending round if round_n matches (re-emit on back);
    # otherwise append.
    if state.rounds and state.rounds[-1].n == new_round.n:
        return state.model_copy(update={
            "rounds": [*state.rounds[:-1], new_round],
        })
    return state.model_copy(update={
        "rounds": [*state.rounds, new_round],
    })


def set_dispatched(
    state: WizardState, *, tool: str, now: float,
) -> WizardState:
    return state.model_copy(update={
        "dispatched": True,
        "active": False,
        "dispatched_tool": tool,
        "dispatched_at": now,
    })


def _latest_click_index(state: WizardState) -> Optional[int]:
    for i in range(state.round_n - 2, -1, -1):
        if i >= len(state.rounds):
            continue
        r = state.rounds[i]
        if r.answer_kind in ("option_click", "free_text"):
            return i
    return None
