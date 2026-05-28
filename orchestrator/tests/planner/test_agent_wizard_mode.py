import pytest

from orchestrator.planner.agent import PlannerAgent


@pytest.fixture
def agent():
    return PlannerAgent(name="planner")


@pytest.mark.parametrize("ws,flag,expected", [
    (None,                            False, "free_text"),
    (None,                            True,  "wizard"),
    ({"active": True,  "round_n": 1}, False, "wizard"),
    ({"active": True,  "round_n": 1}, True,  "wizard"),
    ({"active": False, "round_n": 3, "dispatched": True}, True, "free_text"),
    ({"active": False, "round_n": 3, "dispatched": True}, False, "free_text"),
])
def test_mode_selector_matrix(agent, ws, flag, expected):
    assert agent._select_mode(wizard_state=ws, flag_enabled=flag) == expected


def test_select_prompt_and_tools_wizard():
    from orchestrator.planner.prompts import (
        SYSTEM_PROMPT_WIZARD, WIZARD_TOOL_SCHEMAS,
    )
    agent = PlannerAgent(name="planner")
    prompt, tools = agent._select_prompt_and_tools("wizard")
    assert prompt == SYSTEM_PROMPT_WIZARD
    assert tools == WIZARD_TOOL_SCHEMAS


def test_select_prompt_and_tools_free_text():
    from orchestrator.planner.prompts import SYSTEM_PROMPT, TOOL_SCHEMAS
    agent = PlannerAgent(name="planner")
    prompt, tools = agent._select_prompt_and_tools("free_text")
    assert prompt == SYSTEM_PROMPT
    assert tools == TOOL_SCHEMAS


# ---------------------------------------------------------------------------
# Helpers reused from test_wizard_flow_integration.py pattern
# ---------------------------------------------------------------------------

class _StubStream:
    """Async context-manager + async iterator; returns a canned final message."""

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


class _CapturingStubClient:
    """Stub client that pops from a queue and records kwargs passed to stream()."""

    def __init__(self, queue):
        self._queue = queue
        self.messages = self
        self.captured_kwargs = []  # records kwargs for each stream() call

    def stream(self, **kwargs):
        self.captured_kwargs.append(kwargs)
        final = self._queue.pop(0)
        return _StubStream(final)


def _bad_offer_choices_turn():
    """Canned LLM turn: call offer_choices with no options and allow_free_text=False."""

    class _Block:
        def __init__(self):
            self.type = "tool_use"
            self.id = "tool-bad"
            self.name = "offer_choices"
            self.input = {
                "question": "What do you want?",
                "options": [],
                "allow_free_text": False,
                "round_label": "intent",
            }

    class _Final:
        def __init__(self):
            self.content = [_Block()]
            self.stop_reason = "tool_use"
            self.usage = None

    return _Final()


def _end_turn_msg(text="Done."):
    """Canned LLM turn: end_turn with text."""

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


async def _async_return(x):
    return x


# ---------------------------------------------------------------------------
# Downgrade integration test
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_two_offer_choices_validation_errors_downgrade_to_ask_user(
    monkeypatch, mock_invocation_context, caplog,
):
    """After two consecutive offer_choices tool_validation_error responses
    in the same planner turn, the agent must log 'wizard_validation_exhausted'
    and inject a synthetic user message telling the LLM to switch to ask_user."""
    import logging

    agent = PlannerAgent(name="planner")
    ctx = mock_invocation_context
    ctx.session.state["user_id"] = "u1"
    ctx.session.state["wizard_state"] = {
        "active": True,
        "round_n": 1,
        "rounds": [],
        "bound_context": {},
        "dispatched": False,
    }

    # 3 LLM turns:
    #   Turn 1 — bad offer_choices (no options, allow_free_text=False) → validation error
    #   Turn 2 — bad offer_choices again                                → validation error #2
    #   Turn 3 — end_turn (LLM gave up after seeing the injected message)
    stub_client = _CapturingStubClient([
        _bad_offer_choices_turn(),
        _bad_offer_choices_turn(),
        _end_turn_msg("I'll ask the user instead."),
    ])

    monkeypatch.setattr("orchestrator.planner.agent.WIZARD_MODE_ENABLED", True)
    monkeypatch.setattr(
        "orchestrator.planner.agent.load_core_history",
        lambda **_: _async_return([]),
    )
    monkeypatch.setattr(
        "orchestrator.planner.agent.create_client",
        lambda: stub_client,
    )

    with caplog.at_level(logging.INFO, logger="orchestrator.planner.agent"):
        _events = [e async for e in agent._run_async_impl(ctx)]

    # 1. wizard_validation_exhausted must have been logged
    assert any(
        "wizard_validation_exhausted" in r.message
        for r in caplog.records
    ), "Expected 'wizard_validation_exhausted' in log records"

    # 2. The 3rd LLM turn (index 2) must have received the synthetic downgrade message
    assert len(stub_client.captured_kwargs) == 3, (
        f"Expected exactly 3 LLM calls, got {len(stub_client.captured_kwargs)}"
    )
    third_turn_messages = stub_client.captured_kwargs[2]["messages"]
    downgrade_msg = next(
        (
            m for m in third_turn_messages
            if m.get("role") == "user"
            and isinstance(m.get("content"), str)
            and "Stop calling offer_choices" in m["content"]
            and "respond directly" in m["content"].lower()
        ),
        None,
    )
    assert downgrade_msg is not None, (
        "Expected synthetic downgrade user message in 3rd LLM turn's messages list; "
        f"got: {[m for m in third_turn_messages if m.get('role') == 'user']}"
    )
    # Spec §6.1: ask_user is not in WIZARD_TOOL_SCHEMAS, so the synthetic
    # message must NOT instruct the LLM to call ask_user as a tool.
    assert "ask_user" not in downgrade_msg["content"], (
        "Synthetic downgrade message must not name ask_user (not in wizard schema)"
    )
