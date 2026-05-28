"""Unit tests for PlannerAgent._build_user_message / _format_context_flags.

The planner reads execution flags from ctx.session.state and injects a
structured SESSION CONTEXT block into the user message. This keeps routing
decisions independent of upstream stringification of the context dict.
"""
from __future__ import annotations

from orchestrator.planner.agent import PlannerAgent


class _Session:
    def __init__(self, state):
        self.id = "s"
        self.state = state


class _Ctx:
    def __init__(self, user_text, state):
        self.session = _Session(state)
        if user_text is not None:
            self.user_content = type("C", (), {
                "parts": [type("P", (), {"text": user_text})()]
            })()
        else:
            self.user_content = None


def _agent():
    return PlannerAgent(name="PlannerAgent")


def test_flags_block_reflects_local_test_enabled_true():
    ctx = _Ctx("Testing target: www.example.com",
               {"local_test_enabled": True, "cdp_url": "http://localhost:9222"})
    msg = _agent()._build_user_message(ctx)
    assert "Testing target: www.example.com" in msg
    assert "local_test_enabled: True" in msg
    assert "cdp_url: http://localhost:9222" in msg
    assert "remote_test_enabled: False" in msg
    assert "ssh_config: (none)" in msg


def test_flags_block_defaults_when_state_empty():
    ctx = _Ctx("hello", {})
    msg = _agent()._build_user_message(ctx)
    assert "hello" in msg
    assert "local_test_enabled: False" in msg
    assert "remote_test_enabled: False" in msg
    assert "cdp_url: (none)" in msg
    assert "ssh_config: (none)" in msg


def test_flags_block_reports_remote_and_ssh():
    ctx = _Ctx("Run API test on my VM",
               {"remote_test_enabled": True,
                "ssh_config": {"host": "1.2.3.4"}})
    msg = _agent()._build_user_message(ctx)
    assert "remote_test_enabled: True" in msg
    assert "ssh_config: provided" in msg


def test_persona_included_when_set():
    ctx = _Ctx("t", {"user_persona": "buyer"})
    msg = _agent()._build_user_message(ctx)
    assert "user_persona: buyer" in msg


def test_no_user_text_still_emits_flags():
    ctx = _Ctx(None, {"local_test_enabled": True})
    msg = _agent()._build_user_message(ctx)
    assert "local_test_enabled: True" in msg


def test_wizard_block_absent_when_no_wizard_state():
    ctx = _Ctx("hello", {})
    msg = _agent()._build_user_message(ctx)
    assert "WIZARD STATE" not in msg


def test_wizard_block_absent_when_inactive():
    ctx = _Ctx("hello", {"wizard_state": {"active": False}})
    msg = _agent()._build_user_message(ctx)
    assert "WIZARD STATE" not in msg


def test_wizard_block_renders_bound_context_and_prior_rounds():
    """Regression: without the wizard block the LLM had no record of
    earlier rounds and re-emitted offer_choices for round_label='intent'
    forever, never advancing to run_where/persona/target_url/confirm.
    The user message must surface bound_context AND the rounds[] list
    so the LLM can pick the next round correctly."""
    ws = {
        "active": True,
        "round_n": 2,
        "rounds": [
            {
                "n": 1, "round_label": "intent",
                "question": "What kind of test do you want to run?",
                "options": ["Web UI test", "API test"],
                "allow_free_text": False,
                "answer": "Web UI test", "answer_kind": "option_click",
                "answered_at": 0.0,
            },
        ],
        "bound_context": {
            "url": None, "test_env": "cloud", "persona": None,
            "ssh_config_present": False, "cdp_url_present": False,
            "client_agent_connected": False, "cdp_browser_reachable": False,
        },
        "dispatched": False,
    }
    ctx = _Ctx("", {"wizard_state": ws})
    msg = _agent()._build_user_message(ctx)
    assert "WIZARD STATE" in msg
    assert "current round_n: 2" in msg
    assert "test_env: cloud" in msg
    assert "url: (unset)" in msg
    assert "persona: (unset)" in msg
    # The prior round must be visible with its answer
    assert "R1" in msg
    assert "intent" in msg
    assert '"Web UI test"' in msg
    assert "option_click" in msg


def test_wizard_block_marks_pending_round_unanswered():
    ws = {
        "active": True,
        "round_n": 1,
        "rounds": [
            {
                "n": 1, "round_label": "intent",
                "question": "What kind of test?",
                "options": ["Web UI test"],
                "allow_free_text": False,
                "answer": None, "answer_kind": None, "answered_at": None,
            },
        ],
        "bound_context": {
            "url": None, "test_env": None, "persona": None,
            "ssh_config_present": False, "cdp_url_present": False,
            "client_agent_connected": False, "cdp_browser_reachable": False,
        },
        "dispatched": False,
    }
    ctx = _Ctx("", {"wizard_state": ws})
    msg = _agent()._build_user_message(ctx)
    assert "currently pending" in msg
