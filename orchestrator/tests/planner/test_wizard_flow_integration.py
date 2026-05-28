"""Integration tests for PlannerAgent wizard flows.

Stubs the Anthropic client and drives _run_async_impl through four scripted
scenarios (Flow A, Flow B, Flow C, local_setup_check).

Run with:
    pytest tests/planner/test_wizard_flow_integration.py -v -p no:playwright
"""

from __future__ import annotations

import json
import pytest

from orchestrator.planner.agent import PlannerAgent


# ---------------------------------------------------------------------------
# Stub Anthropic stream / client
# ---------------------------------------------------------------------------

class _StubStream:
    """Async context-manager + async iterator that yields no streaming deltas
    but returns a canned final message."""

    def __init__(self, canned_final):
        self._final = canned_final

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        pass

    def __aiter__(self):
        return self

    async def __anext__(self):
        raise StopAsyncIteration

    async def get_final_message(self):
        return self._final


class _StubClient:
    """Minimal Anthropic client stub.  `messages.stream()` pops from a queue."""

    def __init__(self, queue):
        self._queue = queue
        self.messages = self

    def stream(self, **kwargs):
        final = self._queue.pop(0)
        return _StubStream(final)


# ---------------------------------------------------------------------------
# Canned final-message builders
# ---------------------------------------------------------------------------

def _tool_use(name, inp, *, stop_reason="tool_use"):
    """Return a fake Anthropic final message with a single tool_use block."""

    class _Block:
        def __init__(self, name, inp):
            self.type = "tool_use"
            self.id = "tool-1"
            self.name = name
            self.input = inp

    class _Final:
        def __init__(self):
            self.content = [_Block(name, inp)]
            self.stop_reason = stop_reason
            self.usage = None

    return _Final()


def _end_turn(text):
    """Return a fake Anthropic final message with a single text block."""

    class _Block:
        def __init__(self, text):
            self.type = "text"
            self.text = text

    class _Final:
        def __init__(self, text):
            self.content = [_Block(text)]
            self.stop_reason = "end_turn"
            self.usage = None

    return _Final(text)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

async def _async_return(x):
    return x


def _collect_events(raw_events):
    """Parse all Event objects emitted by _run_async_impl into plain dicts."""
    return [json.loads(e.content.parts[0].text) for e in raw_events]


# ---------------------------------------------------------------------------
# Flow A — intent round (cloud, round_n=1)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_flow_a_web_ui_cloud_intent_round_emits_wizard_round(
    monkeypatch, mock_invocation_context,
):
    """PlannerAgent wizard mode: first intent round emits a wizard_round event."""
    agent = PlannerAgent(name="planner")
    ctx = mock_invocation_context
    ctx.session.state["user_id"] = "u1"
    ctx.session.state["wizard_state"] = {
        "active": True,
        "round_n": 1,
        "rounds": [],
        "bound_context": {"test_env": "cloud", "url": "https://example.com"},
        "dispatched": False,
    }

    monkeypatch.setattr("orchestrator.planner.agent.WIZARD_MODE_ENABLED", True)
    monkeypatch.setattr(
        "orchestrator.planner.agent.load_core_history",
        lambda **_: _async_return([]),
    )
    monkeypatch.setattr(
        "orchestrator.planner.agent.create_client",
        lambda: _StubClient([
            _tool_use("offer_choices", {
                "question": "What would you like to do?",
                "options": ["Web UI test", "API test"],
                "allow_free_text": False,
                "round_label": "intent",
            }),
        ]),
    )

    events = _collect_events([e async for e in agent._run_async_impl(ctx)])

    wr = next(e for e in events if e["event_type"] == "wizard_round")
    payload = json.loads(wr["payload"])
    assert payload["round_label"] == "intent"
    assert payload["options"] == ["Web UI test", "API test"]
    assert payload["round_n"] == 1
    assert payload["allow_back"] is False  # no prior answered rounds


# ---------------------------------------------------------------------------
# Flow B — back navigation from round 3
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_flow_b_back_from_r3(monkeypatch, mock_invocation_context):
    """When there are prior answered rounds, allow_back must be True in the
    emitted wizard_round payload."""
    agent = PlannerAgent(name="planner")
    ctx = mock_invocation_context
    ctx.session.state["user_id"] = "u1"
    # Seed with 3 prior answered rounds so _allow_back() returns True
    ctx.session.state["wizard_state"] = {
        "active": True,
        "round_n": 3,
        "rounds": [
            {"round_label": "intent",   "answer_kind": "option_click", "answer": "Web UI test"},
            {"round_label": "run_where","answer_kind": "option_click", "answer": "Cloud"},
            {"round_label": "target_url","answer_kind": "free_text",   "answer": "https://app.com"},
        ],
        "bound_context": {"test_env": "cloud", "url": "https://app.com"},
        "dispatched": False,
    }

    monkeypatch.setattr("orchestrator.planner.agent.WIZARD_MODE_ENABLED", True)
    monkeypatch.setattr(
        "orchestrator.planner.agent.load_core_history",
        lambda **_: _async_return([]),
    )
    monkeypatch.setattr(
        "orchestrator.planner.agent.create_client",
        lambda: _StubClient([
            _tool_use("offer_choices", {
                "question": "Please confirm your target URL:",
                "options": ["Confirm", "Go back"],
                "allow_free_text": True,
                "round_label": "confirm",
            }),
        ]),
    )

    events = _collect_events([e async for e in agent._run_async_impl(ctx)])

    wr = next(e for e in events if e["event_type"] == "wizard_round")
    # Double-encoded: passthrough_event wraps already-JSON-encoded payload string
    payload = json.loads(wr["payload"])
    # offer_choices reads wizard_state from ctx to compute allow_back
    assert payload["allow_back"] is True
    assert payload["round_n"] == 3


# ---------------------------------------------------------------------------
# Flow C — fast-forward to round 5 (confirm round)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_flow_c_fast_forward_to_r5(monkeypatch, mock_invocation_context):
    """Planner fast-forwarded past earlier rounds; wizard_round payload
    must reflect round_n=5 and round_label='confirm'.

    Spec §7.3: when api_service detects that the user's first message +
    bound_context cover all four pre-confirm slots, it synthesizes
    rounds[0..3] with answer_kind in {parsed_from_text, bound_context_skip}
    and sets round_n=5. This test seeds that synthesized state directly and
    asserts both (a) the planner emits R5 confirm and (b) the synthesized
    pre-confirm rounds carry the spec-mandated answer_kinds and labels.
    """
    agent = PlannerAgent(name="planner")
    ctx = mock_invocation_context
    ctx.session.state["user_id"] = "u1"
    ctx.session.state["wizard_state"] = {
        "active": True,
        "round_n": 5,
        "rounds": [
            # All four slots synthesized: intent + persona from message text,
            # run_where + target_url from the UI bound_context.
            {"n": 1, "question": "What would you like to do?", "options": [],
             "allow_free_text": False, "round_label": "intent",
             "answer_kind": "parsed_from_text", "answer": "Web UI test",
             "answered_at": 1.0},
            {"n": 2, "question": "Where does it run?", "options": [],
             "allow_free_text": False, "round_label": "run_where",
             "answer_kind": "bound_context_skip", "answer": "cloud",
             "answered_at": 1.0},
            {"n": 3, "question": "Persona?", "options": [],
             "allow_free_text": False, "round_label": "persona",
             "answer_kind": "parsed_from_text", "answer": "end_user",
             "answered_at": 1.0},
            {"n": 4, "question": "Target URL?", "options": [],
             "allow_free_text": False, "round_label": "target_url",
             "answer_kind": "bound_context_skip", "answer": "https://app.com",
             "answered_at": 1.0},
        ],
        "bound_context": {
            "test_env": "cloud",
            "url": "https://app.com",
            "user_persona": "end_user",
        },
        "dispatched": False,
    }

    monkeypatch.setattr("orchestrator.planner.agent.WIZARD_MODE_ENABLED", True)
    monkeypatch.setattr(
        "orchestrator.planner.agent.load_core_history",
        lambda **_: _async_return([]),
    )
    monkeypatch.setattr(
        "orchestrator.planner.agent.create_client",
        lambda: _StubClient([
            _tool_use("offer_choices", {
                "question": "Ready to run the test?",
                "options": ["Yes, run it", "Edit settings"],
                "allow_free_text": False,
                "round_label": "confirm",
            }),
        ]),
    )

    events = _collect_events([e async for e in agent._run_async_impl(ctx)])

    wr = next(e for e in events if e["event_type"] == "wizard_round")
    # Double-encoded: passthrough_event wraps already-JSON-encoded payload string
    payload = json.loads(wr["payload"])
    assert payload["round_n"] == 5
    assert payload["round_label"] == "confirm"
    # Spec §7.3 + offer_choices._allow_back: after fast-forward, all four
    # pre-confirm rounds are synthesized (parsed_from_text /
    # bound_context_skip) — none are option_click/free_text — so allow_back
    # is False (consistent with test_allow_back_false_after_fast_forward in
    # test_tool_offer_choices.py).
    assert payload["allow_back"] is False

    # Spec §7.3 hardening: assert the synthesized pre-confirm rounds carry
    # the spec-mandated answer_kinds and cover all four slot labels.
    final_state = ctx.session.state["wizard_state"]
    assert final_state["round_n"] == 5
    assert len(final_state["rounds"]) >= 4
    pre_confirm = final_state["rounds"][:4]
    assert all(
        r["answer_kind"] in ("parsed_from_text", "bound_context_skip")
        for r in pre_confirm
    )
    assert {r["round_label"] for r in pre_confirm} >= {
        "intent", "run_where", "persona", "target_url",
    }


# ---------------------------------------------------------------------------
# Flow D — local_setup_check (client agent not connected)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_local_setup_check_when_client_agent_down(
    monkeypatch, mock_invocation_context,
):
    """When test_env='my_machine' and client_agent_connected=False, the planner
    should emit a wizard_round with round_label='local_setup_check'."""
    agent = PlannerAgent(name="planner")
    ctx = mock_invocation_context
    ctx.session.state["user_id"] = "u1"
    ctx.session.state["wizard_state"] = {
        "active": True,
        "round_n": 2,
        "rounds": [
            {"round_label": "intent", "answer_kind": "option_click", "answer": "Web UI test"},
        ],
        "bound_context": {
            "test_env": "my_machine",
            "client_agent_connected": False,
        },
        "dispatched": False,
    }

    monkeypatch.setattr("orchestrator.planner.agent.WIZARD_MODE_ENABLED", True)
    monkeypatch.setattr(
        "orchestrator.planner.agent.load_core_history",
        lambda **_: _async_return([]),
    )
    monkeypatch.setattr(
        "orchestrator.planner.agent.create_client",
        lambda: _StubClient([
            _tool_use("offer_choices", {
                "question": "Your client agent is not connected. What would you like to do?",
                "options": [
                    "Show setup instructions",
                    "Switch to cloud testing",
                    "Retry connection",
                ],
                "allow_free_text": False,
                "round_label": "local_setup_check",
            }),
        ]),
    )

    events = _collect_events([e async for e in agent._run_async_impl(ctx)])

    wr = next(e for e in events if e["event_type"] == "wizard_round")
    # Double-encoded: passthrough_event wraps already-JSON-encoded payload string
    payload = json.loads(wr["payload"])
    assert payload["round_label"] == "local_setup_check"
    # Diagnostic options must all be present
    assert "Show setup instructions" in payload["options"]
    assert "Switch to cloud testing" in payload["options"]
    assert "Retry connection" in payload["options"]
    # allow_back is True because there is one prior answered round
    assert payload["allow_back"] is True
