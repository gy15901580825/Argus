from pydantic import ValidationError
import pytest

from models import (
    BoundContext, WizardRound, WizardState, WizardInput,
)


def test_bound_context_defaults_for_empty_session():
    bc = BoundContext()
    assert bc.url is None
    assert bc.test_env is None
    assert bc.ssh_config_present is False
    assert bc.cdp_url_present is False
    assert bc.persona is None
    assert bc.client_agent_connected is False
    assert bc.cdp_browser_reachable is False


def test_wizard_round_valid_option_click():
    r = WizardRound(
        n=1, question="q", options=["a", "b"],
        allow_free_text=False, round_label="intent",
        answer="a", answer_kind="option_click", answered_at=1.0,
    )
    assert r.n == 1


def test_wizard_round_rejects_invalid_answer_kind():
    with pytest.raises(ValidationError):
        WizardRound(
            n=1, question="q", options=[], allow_free_text=True,
            round_label="intent",
            answer="x", answer_kind="telepathy", answered_at=1.0,
        )


def test_wizard_state_invariants_len_equals_round_n():
    ws = WizardState(
        active=True, round_n=1,
        rounds=[WizardRound(
            n=1, question="q", options=[], allow_free_text=True,
            round_label="intent", answer=None, answer_kind=None,
            answered_at=None,
        )],
        bound_context=BoundContext(), dispatched=False,
    )
    assert len(ws.rounds) == ws.round_n


def test_wizard_input_option_click_requires_value():
    with pytest.raises(ValidationError):
        WizardInput(roundN=1, kind="option_click")


def test_wizard_input_back_requires_no_value():
    wi = WizardInput(roundN=2, kind="back")
    assert wi.value is None
