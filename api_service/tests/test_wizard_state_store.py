import pytest

from models import BoundContext, WizardInput, WizardRound, WizardState
from wizard_state_store import (
    initialize_wizard_state,
    apply_wizard_input,
    append_round_from_event,
    set_dispatched,
    synthesize_fast_forward,
    StaleRoundError,
    InvalidTransitionError,
)


def _minimal_state(round_n=1, rounds=None, bound=None, active=True):
    return WizardState(
        active=active, round_n=round_n,
        rounds=rounds or [],
        bound_context=bound or BoundContext(),
    )


def test_initialize_with_cloud_toggle_sets_bound_context():
    ws = initialize_wizard_state(
        test_env="cloud", ssh_config_present=False,
        cdp_url_present=False, persona=None, url="https://example.com",
    )
    assert ws.active is True
    assert ws.round_n == 1
    assert ws.rounds == []
    assert ws.bound_context.test_env == "cloud"
    assert ws.bound_context.url == "https://example.com"
    assert ws.dispatched is False


def test_apply_option_click_writes_answer_and_increments_round():
    r1 = WizardRound(
        n=1, question="?", options=["a", "b"], allow_free_text=False,
        round_label="intent",
    )
    ws = _minimal_state(round_n=1, rounds=[r1])
    new_ws = apply_wizard_input(
        ws, WizardInput(roundN=1, kind="option_click", value="a"),
        now=100.0,
    )
    assert new_ws.rounds[0].answer == "a"
    assert new_ws.rounds[0].answer_kind == "option_click"
    assert new_ws.rounds[0].answered_at == 100.0
    assert new_ws.round_n == 2


def test_apply_stale_round_n_raises_stale_error():
    ws = _minimal_state(round_n=2)
    with pytest.raises(StaleRoundError):
        apply_wizard_input(
            ws, WizardInput(roundN=1, kind="option_click", value="x"),
            now=100.0,
        )


def test_apply_back_skips_bound_context_skip_rounds():
    rounds = [
        WizardRound(n=1, question="q1", options=[], allow_free_text=True,
                    round_label="intent", answer="Web UI test",
                    answer_kind="option_click", answered_at=1.0),
        WizardRound(n=2, question="q2", options=[], allow_free_text=False,
                    round_label="run_where", answer="cloud",
                    answer_kind="bound_context_skip", answered_at=1.0),
        WizardRound(n=3, question="q3", options=[], allow_free_text=True,
                    round_label="persona", answer=None,
                    answer_kind=None, answered_at=None),
    ]
    ws = _minimal_state(round_n=3, rounds=rounds)
    new_ws = apply_wizard_input(
        ws, WizardInput(roundN=3, kind="back"), now=2.0,
    )
    assert new_ws.round_n == 1
    assert new_ws.rounds[0].answer is None
    # rounds 2, 3 cleared
    assert len(new_ws.rounds) == 1


def test_apply_back_at_round_n_1_raises():
    rounds = [WizardRound(n=1, question="q", options=[], allow_free_text=True,
                          round_label="intent")]
    ws = _minimal_state(round_n=1, rounds=rounds)
    with pytest.raises(InvalidTransitionError):
        apply_wizard_input(
            ws, WizardInput(roundN=1, kind="back"), now=2.0,
        )


def test_apply_abort_clears_rounds_and_deactivates():
    rounds = [WizardRound(n=1, question="q", options=[], allow_free_text=True,
                          round_label="intent", answer="x",
                          answer_kind="option_click", answered_at=1.0)]
    ws = _minimal_state(round_n=2, rounds=rounds)
    new_ws = apply_wizard_input(
        ws, WizardInput(roundN=2, kind="abort"), now=2.0,
    )
    assert new_ws.active is False
    assert new_ws.rounds == []


def test_append_round_from_event_adds_pending_round():
    ws = _minimal_state(round_n=2, rounds=[
        WizardRound(n=1, question="q1", options=[], allow_free_text=True,
                    round_label="intent", answer="x",
                    answer_kind="option_click", answered_at=1.0),
    ])
    event_payload = {
        "round_n": 2, "question": "Q2", "options": ["a"],
        "allow_free_text": False, "round_label": "persona",
    }
    new_ws = append_round_from_event(ws, event_payload)
    assert len(new_ws.rounds) == 2
    assert new_ws.rounds[1].n == 2
    assert new_ws.rounds[1].answer is None


def test_set_dispatched_marks_inactive():
    ws = _minimal_state(round_n=5)
    new_ws = set_dispatched(ws, tool="run_web_ui_cloud", now=10.0)
    assert new_ws.dispatched is True
    assert new_ws.active is False
    assert new_ws.dispatched_tool == "run_web_ui_cloud"
    assert new_ws.dispatched_at == 10.0


def test_switch_to_cloud_rewrites_run_where_answer():
    """When user clicks 'Switch to cloud mode' in a local_setup_check round,
    rounds[1] (run_where) is rewritten to 'cloud' in place; current
    local_setup_check round is also marked answered; round_n increments."""
    state = WizardState(
        active=True,
        round_n=3,
        rounds=[
            WizardRound(n=1, question="What to do?", options=["Web UI test"],
                        allow_free_text=False, round_label="intent",
                        answer="Web UI test", answer_kind="option_click",
                        answered_at=1.0),
            WizardRound(n=2, question="Where?", options=["cloud", "my_machine"],
                        allow_free_text=False, round_label="run_where",
                        answer="my_machine", answer_kind="option_click",
                        answered_at=2.0),
            WizardRound(n=3, question="client_agent not connected",
                        options=["Show setup guide", "I've installed it — recheck",
                                 "Switch to cloud mode"],
                        allow_free_text=False, round_label="local_setup_check"),
        ],
        bound_context=BoundContext(
            url="https://example.com", test_env="my_machine",
            ssh_config_present=False, cdp_url_present=False,
            persona=None, client_agent_connected=False,
            cdp_browser_reachable=False,
        ),
        dispatched=False,
    )
    next_state = apply_wizard_input(
        state,
        WizardInput(roundN=3, kind="option_click", value="Switch to cloud mode"),
        now=3.0,
    )
    # run_where (rounds[1]) rewritten in place
    assert next_state.rounds[1].answer == "cloud"
    assert next_state.rounds[1].answer_kind == "option_click"
    # local_setup_check round itself is consumed (answered)
    assert next_state.rounds[2].answer == "Switch to cloud mode"
    assert next_state.rounds[2].answer_kind == "option_click"
    # round_n moves forward (no rewind)
    assert next_state.round_n == 4
    assert next_state.active is True


def test_switch_to_cloud_only_triggers_in_local_setup_check_round():
    """Same value clicked in a non-local_setup_check round behaves as ordinary
    click — does NOT touch rounds[1]."""
    state = WizardState(
        active=True,
        round_n=2,
        rounds=[
            WizardRound(n=1, question="What to do?", options=["Web UI test"],
                        allow_free_text=False, round_label="intent",
                        answer="Web UI test", answer_kind="option_click",
                        answered_at=1.0),
            WizardRound(n=2, question="Where?",
                        options=["cloud", "my_machine", "Switch to cloud mode"],
                        allow_free_text=False, round_label="run_where"),
        ],
        bound_context=BoundContext(
            url=None, test_env=None, ssh_config_present=False,
            cdp_url_present=False, persona=None,
            client_agent_connected=False, cdp_browser_reachable=False,
        ),
        dispatched=False,
    )
    next_state = apply_wizard_input(
        state,
        WizardInput(roundN=2, kind="option_click", value="Switch to cloud mode"),
        now=2.0,
    )
    # Ordinary click: this round answered, no special rewrite.
    assert next_state.rounds[1].answer == "Switch to cloud mode"
    assert next_state.rounds[1].answer_kind == "option_click"
    assert next_state.round_n == 3


def test_synthesize_fast_forward_fills_all_four_slots():
    """User typed a fully-specified message; bound_context has none of the
    slots. All 4 pre-confirm rounds get answer_kind='parsed_from_text'."""
    bc = BoundContext(
        url=None, test_env=None, ssh_config_present=False,
        cdp_url_present=False, persona=None,
        client_agent_connected=False, cdp_browser_reachable=False,
    )
    state = synthesize_fast_forward(
        bound_context=bc,
        parsed_slots={
            "intent": "Web UI test",
            "run_where": "cloud",
            "persona": "new_user",
            "target_url": "https://example.com",
        },
        now=1.0,
    )
    assert state.round_n == 5
    assert len(state.rounds) == 4
    labels = [r.round_label for r in state.rounds]
    assert labels == ["intent", "run_where", "persona", "target_url"]
    kinds = [r.answer_kind for r in state.rounds]
    assert kinds == ["parsed_from_text"] * 4


def test_try_parse_full_spec_message_returns_all_slots():
    """A user message containing intent, run_where, persona, and target_url
    should yield a full slot dict."""
    from routers.orchestrator import _try_parse_message_into_slots
    parsed = _try_parse_message_into_slots(
        message="Run a web ui test on cloud as new_user against https://example.com",
        bound_context_args={
            "test_env": None, "ssh_config_present": False,
            "cdp_url_present": False, "persona": None, "url": None,
            "client_agent_connected": False, "cdp_browser_reachable": False,
        },
    )
    assert parsed is not None
    assert parsed["intent"] == "Web UI test"
    assert parsed["run_where"] == "cloud"
    assert parsed["persona"] == "new_user"
    assert parsed["target_url"] == "https://example.com"


def test_try_parse_ambiguous_message_returns_none():
    """A vague message that doesn't clearly fill all four slots returns None."""
    from routers.orchestrator import _try_parse_message_into_slots
    parsed = _try_parse_message_into_slots(
        message="hi can you help me test something",
        bound_context_args={
            "test_env": None, "ssh_config_present": False,
            "cdp_url_present": False, "persona": None, "url": None,
            "client_agent_connected": False, "cdp_browser_reachable": False,
        },
    )
    assert parsed is None


def test_try_parse_with_bound_url_fills_target_slot_from_bound():
    """When bound_context.url is set, the parser does not need to find a URL
    in the message — bound wins, and the resulting parsed dict should still
    cover all four slots so fast-forward can fire."""
    from routers.orchestrator import _try_parse_message_into_slots, _all_slots_filled
    bca = {
        "test_env": "cloud", "ssh_config_present": False,
        "cdp_url_present": False, "persona": "new_user",
        "url": "https://example.com",
        "client_agent_connected": False, "cdp_browser_reachable": False,
    }
    parsed = _try_parse_message_into_slots(
        message="run a web ui test", bound_context_args=bca,
    )
    assert parsed is not None
    assert _all_slots_filled(parsed, bca) is True


def test_synthesize_fast_forward_marks_bound_slots_as_skip():
    """When bound_context already has run_where, that round's answer_kind
    must be 'bound_context_skip' (not 'parsed_from_text')."""
    bc = BoundContext(
        url=None, test_env="cloud", ssh_config_present=False,
        cdp_url_present=False, persona=None,
        client_agent_connected=False, cdp_browser_reachable=False,
    )
    state = synthesize_fast_forward(
        bound_context=bc,
        parsed_slots={
            "intent": "Web UI test",
            "run_where": "cloud",
            "persona": "new_user",
            "target_url": "https://example.com",
        },
        now=1.0,
    )
    run_where_round = next(r for r in state.rounds if r.round_label == "run_where")
    assert run_where_round.answer_kind == "bound_context_skip"
    assert run_where_round.answer == "cloud"


def test_switch_to_cloud_without_run_where_round_raises():
    """Sanity guard: spec invariant says local_setup_check only follows an
    answered run_where round. If somehow that invariant is violated, raise
    rather than silently no-op."""
    state = WizardState(
        active=True,
        round_n=2,
        rounds=[
            WizardRound(n=1, question="Intent?", options=["x"],
                        allow_free_text=False, round_label="intent",
                        answer="x", answer_kind="option_click", answered_at=1.0),
            WizardRound(n=2, question="agent down",
                        options=["Switch to cloud mode"],
                        allow_free_text=False, round_label="local_setup_check"),
        ],
        bound_context=BoundContext(
            url=None, test_env=None, ssh_config_present=False,
            cdp_url_present=False, persona=None,
            client_agent_connected=False, cdp_browser_reachable=False,
        ),
        dispatched=False,
    )
    with pytest.raises(InvalidTransitionError):
        apply_wizard_input(
            state,
            WizardInput(roundN=2, kind="option_click", value="Switch to cloud mode"),
            now=2.0,
        )
