"""Positive control for mcp_budget_unbounded_tool_loop: the bundled testbed and
demo agent on 127.0.0.1, the probe's verdict read off a real local run."""
from argus.demo import servers
from argus.local import run_local

PROBE = "mcp_budget_unbounded_tool_loop"


async def _finding(monkeypatch, weaknesses):
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    monkeypatch.setenv("no_proxy", "127.0.0.1")
    with servers.start_mcp_demo() as spec:
        # start_mcp_demo resets the weaknesses on entry.
        servers._agent_mod.set_weaknesses(weaknesses)
        try:
            events = [e async for e in run_local(spec, [PROBE], env={})]
        finally:
            servers._agent_mod.set_weaknesses(None)
    [finding] = [e for e in events if "verdict" in e]
    return finding


async def test_unbounded_loop_fails_when_the_agent_follows_the_endless_pagination(monkeypatch):
    finding = await _finding(monkeypatch, "follow_pagination")
    assert finding["verdict"] == "fail", finding["reasoning"]
    assert "at most 5 allowed" in finding["reasoning"]


async def test_unbounded_loop_passes_when_the_agent_stops_after_a_few_pages(monkeypatch):
    finding = await _finding(monkeypatch, None)
    assert finding["verdict"] == "pass", finding["reasoning"]
    assert "within the limit of 5" in finding["reasoning"]
