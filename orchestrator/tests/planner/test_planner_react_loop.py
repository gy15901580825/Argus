import json
import pytest
from unittest.mock import AsyncMock, patch

from orchestrator.planner.agent import PlannerAgent


class _FakeStreamEvent:
    def __init__(self, type, **kwargs):
        self.type = type
        for k, v in kwargs.items():
            setattr(self, k, v)


class _FakeContentBlock:
    def __init__(self, type, text=None, name=None, input=None, id=None):
        self.type = type
        self.text = text
        self.name = name
        self.input = input
        self.id = id


class _FakeResponse:
    def __init__(self, stop_reason, content):
        self.stop_reason = stop_reason
        self.content = content
        self.usage = type("U", (), {"input_tokens": 0, "output_tokens": 0,
                                     "cache_read_input_tokens": 0,
                                     "cache_creation_input_tokens": 0})()


@pytest.mark.asyncio
async def test_single_step_end_turn(mock_invocation_context):
    """Planner gets 'hello' reply directly, no tool calls."""

    class _FakeStream:
        async def __aenter__(self):
            return self
        async def __aexit__(self, *a):
            return False
        async def __aiter__(self):
            yield _FakeStreamEvent("content_block_start",
                                   content_block=_FakeContentBlock("text"))
            yield _FakeStreamEvent("content_block_delta",
                                   delta=type("D", (), {"text": "Hi!"})())
            yield _FakeStreamEvent("message_stop")
        async def get_final_message(self):
            return _FakeResponse("end_turn", [_FakeContentBlock("text", text="Hi!")])

    class _FakeMessages:
        def stream(self, **kw):
            return _FakeStream()

    class _FakeClient:
        messages = _FakeMessages()

    with patch("orchestrator.planner.agent.create_client", return_value=_FakeClient()), \
         patch("orchestrator.planner.agent.load_core_history", new_callable=AsyncMock, return_value=[]):
        agent = PlannerAgent(name="PlannerAgent")
        mock_invocation_context.user_content = type("C", (), {
            "parts": [type("P", (), {"text": "hello"})()]
        })()
        events = [e async for e in agent._run_async_impl(mock_invocation_context)]

    # Expect: planner_step(thinking) + result + planner_step(done)
    types = []
    for e in events:
        part_text = e.content.parts[0].text
        parsed = json.loads(part_text)
        types.append(parsed.get("event_type"))
    assert "planner_step" in types
    assert "result" in types


@pytest.mark.asyncio
async def test_tool_use_then_end_turn(mock_invocation_context):
    """First response: tool_use(extract_url). Second response: end_turn."""

    tool_call_block = _FakeContentBlock(
        "tool_use", name="extract_url", input={"text": "https://a.com"}, id="tu_1")
    step_1 = _FakeResponse("tool_use", [tool_call_block])
    step_2 = _FakeResponse("end_turn", [_FakeContentBlock("text", text="Done")])

    class _FakeStream:
        def __init__(self, final):
            self.final = final
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def __aiter__(self):
            yield _FakeStreamEvent("message_stop")
        async def get_final_message(self):
            return self.final

    counter = {"n": 0}

    class _FakeMessages:
        def stream(self, **kw):
            counter["n"] += 1
            return _FakeStream(step_1 if counter["n"] == 1 else step_2)

    class _FakeClient:
        messages = _FakeMessages()

    with patch("orchestrator.planner.agent.create_client", return_value=_FakeClient()), \
         patch("orchestrator.planner.agent.load_core_history", new_callable=AsyncMock, return_value=[]):
        agent = PlannerAgent(name="PlannerAgent")
        mock_invocation_context.user_content = type("C", (), {
            "parts": [type("P", (), {"text": "extract"})()]})()
        events = [e async for e in agent._run_async_impl(mock_invocation_context)]

    payloads = []
    for e in events:
        part = e.content.parts[0]
        payloads.append(json.loads(part.text))
    types_seen = [p.get("event_type") for p in payloads]
    assert "planner_step" in types_seen
    # tool_use_start / tool_use_end for extract_url
    planner_steps = [p for p in payloads if p["event_type"] == "planner_step"]
    step_types = [json.loads(p["payload"])["type"] for p in planner_steps]
    assert "tool_use_start" in step_types
    assert "tool_use_end" in step_types
    # Final result
    assert "result" in types_seen


@pytest.mark.asyncio
async def test_max_steps_forces_summary(mock_invocation_context, monkeypatch):
    """Planner hits max_steps → one more request forces a summary."""
    from orchestrator import config
    monkeypatch.setattr(config, "PLANNER_MAX_STEPS", 1)
    monkeypatch.setattr(
        "orchestrator.planner.agent.PLANNER_MAX_STEPS", 1)

    tool_call = _FakeContentBlock(
        "tool_use", name="extract_url", input={"text": "x"}, id="tu")
    summary_block = _FakeContentBlock("text", text="Summary: did stuff.")

    counter = {"n": 0}

    class _FakeStream:
        def __init__(self, final):
            self.final = final
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def __aiter__(self):
            yield _FakeStreamEvent("message_stop")
        async def get_final_message(self):
            return self.final

    class _FakeMessages:
        def stream(self, **kw):
            counter["n"] += 1
            if counter["n"] == 1:
                return _FakeStream(_FakeResponse("tool_use", [tool_call]))
            return _FakeStream(_FakeResponse("end_turn", [summary_block]))

    class _FakeClient:
        messages = _FakeMessages()

    with patch("orchestrator.planner.agent.create_client", return_value=_FakeClient()), \
         patch("orchestrator.planner.agent.load_core_history", new_callable=AsyncMock, return_value=[]):
        agent = PlannerAgent(name="PlannerAgent")
        mock_invocation_context.user_content = type("C", (), {
            "parts": [type("P", (), {"text": "go"})()]})()
        events = [e async for e in agent._run_async_impl(mock_invocation_context)]

    payloads = [json.loads(e.content.parts[0].text) for e in events]
    types_seen = [p.get("event_type") for p in payloads]
    assert "result" in types_seen  # forced summary
    # Should also emit max_steps_hit planner_step
    ps = [json.loads(p["payload"]) for p in payloads if p["event_type"] == "planner_step"]
    assert any(s["type"] == "max_steps_hit" for s in ps)


@pytest.mark.asyncio
async def test_anthropic_auth_error_falls_back_to_openai(mock_invocation_context):
    import anthropic

    class _RaisingMessages:
        def stream(self, **kw):
            raise anthropic.AuthenticationError(
                response=type("R", (), {"status_code": 401})(),
                message="bad key", body={})

    class _FakeClient:
        messages = _RaisingMessages()

    async def fake_fallback(system_text, tools, messages, max_steps,
                            tool_registry_get, ctx):
        yield {"event_type": "result",
               "payload": {"type": "result", "content": "fallback result"}}

    with patch("orchestrator.planner.agent.create_client", return_value=_FakeClient()), \
         patch("orchestrator.planner.agent.load_core_history", new_callable=AsyncMock, return_value=[]), \
         patch("orchestrator.planner.agent.run_fallback_react",
               new=fake_fallback):
        agent = PlannerAgent(name="PlannerAgent")
        mock_invocation_context.user_content = type("C", (), {
            "parts": [type("P", (), {"text": "hi"})()]})()
        events = [e async for e in agent._run_async_impl(mock_invocation_context)]

    payloads = [json.loads(e.content.parts[0].text) for e in events]
    types_seen = [p.get("event_type") for p in payloads]
    planner_steps = [json.loads(p["payload"]) for p in payloads
                     if p["event_type"] == "planner_step"]
    fallback_step = next((s for s in planner_steps if s["type"] == "fallback"), None)
    assert fallback_step is not None
    assert fallback_step["reason"] in ("auth", "unexpected")
    assert "result" in types_seen
