import json
import pytest
from orchestrator.planner.tools.ask_user import ask_user


@pytest.mark.asyncio
async def test_ask_user_yields_clarification_then_terminates():
    events = [e async for e in ask_user(question="Which URL?", ctx=None)]
    assert len(events) == 2
    assert events[0]["is_terminal"] is False
    assert events[0]["event_type"] == "log"
    payload = events[0]["payload"]
    assert payload["category"] == "clarification_needed"
    assert payload["question"] == "Which URL?"
    assert events[1]["is_terminal"] is True
    assert "Which URL?" in events[1]["result"]
