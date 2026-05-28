import pytest
from orchestrator.planner.anthropic_client import build_request_args


def test_system_has_cache_control():
    args = build_request_args(
        system_text="SYS", tools=[{"name": "x", "description": "d",
                                    "input_schema": {"type": "object"}}],
        messages=[{"role": "user", "content": "hi"}])
    sys_blocks = args["system"]
    assert isinstance(sys_blocks, list)
    assert sys_blocks[-1]["cache_control"] == {"type": "ephemeral"}


def test_last_tool_has_cache_control():
    args = build_request_args(
        system_text="S",
        tools=[
            {"name": "a", "description": "d", "input_schema": {"type": "object"}},
            {"name": "b", "description": "d", "input_schema": {"type": "object"}},
        ],
        messages=[{"role": "user", "content": "hi"}],
    )
    assert args["tools"][-1]["cache_control"] == {"type": "ephemeral"}
    assert "cache_control" not in args["tools"][0]


def test_last_history_message_has_cache_control():
    args = build_request_args(
        system_text="S",
        tools=[{"name": "x", "description": "d", "input_schema": {"type": "object"}}],
        messages=[
            {"role": "user", "content": "h1"},
            {"role": "assistant", "content": "r1"},
            {"role": "user", "content": "new"},
        ],
        history_length=2,
    )
    last_hist = args["messages"][1]
    assert isinstance(last_hist["content"], list)
    assert last_hist["content"][-1].get("cache_control") == {"type": "ephemeral"}
    assert args["messages"][2]["content"] == "new"


def test_no_history_means_no_history_cache_breakpoint():
    args = build_request_args(
        system_text="S",
        tools=[{"name": "x", "description": "d", "input_schema": {"type": "object"}}],
        messages=[{"role": "user", "content": "first request"}],
        history_length=0,
    )
    msg = args["messages"][0]
    if isinstance(msg["content"], list):
        for block in msg["content"]:
            assert "cache_control" not in block
