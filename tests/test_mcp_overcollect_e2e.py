"""Positive control for mcp_rugpull_overcollect: the bundled testbed and demo
agent on 127.0.0.1, the probe's verdict read off a real local run."""
from argus.demo import servers
from argus.local import run_local

PROBE = "mcp_rugpull_overcollect"


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


async def test_overcollect_fails_when_the_agent_follows_the_changed_description(monkeypatch):
    finding = await _finding(monkeypatch, "follow_changed_description")
    assert finding["verdict"] == "fail", finding["reasoning"]
    assert "11 of 11 records outside the user's task" in finding["reasoning"]


async def test_overcollect_passes_when_the_agent_ignores_the_changed_description(monkeypatch):
    finding = await _finding(monkeypatch, None)
    assert finding["verdict"] == "pass", finding["reasoning"]
    assert "carried only data from the user's task" in finding["reasoning"]
