"""The mcp_agent adapter: session lifecycle and the sandbox guard."""

from __future__ import annotations

import json
from types import SimpleNamespace

import httpx
import pytest

from orchestrator.redteam.targets import build_target
from orchestrator.redteam.targets import mcp_agent as mcp_agent_mod

INNER = {"kind": "openai_compat", "endpoint_url": "https://x/v1/chat/completions", "model": "m"}


def _spec(**kw):
    base = {"kind": "mcp_agent", "testbed_url": "http://tb", "inner": INNER,
            "script": {"scenario": "tool_poisoning"}, "sandbox": True}
    base.update(kw)
    return base


def test_sandbox_false_is_refused_structurally():
    """一次能连到真 MCP server 的红队运行不是我们要从中恢复的配置错误。"""
    with pytest.raises(ValueError, match="sandbox"):
        build_target(_spec(sandbox=False))


def test_missing_testbed_url_is_refused():
    with pytest.raises(ValueError):
        build_target(_spec(testbed_url=""))


def test_compatible_classes_is_exactly_mcp_agent():
    assert build_target(_spec()).compatible_classes == frozenset({"mcp_agent"})


def test_collect_evidence_is_empty_before_any_session():
    import asyncio
    assert asyncio.run(build_target(_spec()).collect_evidence()) == {}


# --------------------------------------------------------------------------
# httpx stubbing, mirroring tests/test_redteam_targets_payment.py.
# --------------------------------------------------------------------------
def test_send_prompt_opens_a_session_and_substitutes_the_mcp_url():
    import asyncio

    calls = {}

    class FakeInner:
        supports_history = True

        async def send_prompt(self, prompt, history=()):
            calls["prompt"] = prompt
            return "ok", 3.0

    t = build_target(_spec())
    t._inner = FakeInner()

    async def fake_open():
        t._session = {"session_id": "sid1", "mcp_url": "http://tb/s/sid1/mcp"}
        return t._session

    t._open_session = fake_open
    text, _ = asyncio.run(t.send_prompt("Reach {mcp_url} and enumerate its tools."))
    assert text == "ok"
    assert "http://tb/s/sid1/mcp" in calls["prompt"]
    assert "{mcp_url}" not in calls["prompt"]


class FakeTestbed:
    """A stand-in for the hostile MCP testbed. The only property that matters
    here is the real one's: each session is a separate slice of state, and
    evidence is read per session id."""

    def __init__(self) -> None:
        self.sessions: dict[str, dict] = {}
        self.opened_scripts: list[dict] = []
        self.closed: list[str] = []
        self._n = 0

    def record_tool_call(self, sid: str, tool: str, arguments: dict | None = None) -> None:
        s = self.sessions[sid]
        s["tool_calls"].append({
            "seq": len(s["tool_calls"]) + 1, "tool": tool,
            "arguments": arguments or {}, "after_description_change": False,
        })
        s["interaction_count"] += 1

    def handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.method == "POST" and path == "/sessions":
            self._n += 1
            sid = f"sid{self._n}"
            script = json.loads(request.content.decode() or "{}")
            self.opened_scripts.append(script)
            self.sessions[sid] = {"tool_calls": [], "interaction_count": 0}
            return httpx.Response(
                201,
                json={"session_id": sid, "mcp_url": f"http://tb/s/{sid}/mcp", "script": script},
            )
        if request.method == "DELETE" and path.startswith("/sessions/"):
            sid = path.rsplit("/", 1)[-1]
            self.closed.append(sid)
            self.sessions.pop(sid, None)
            return httpx.Response(204)
        if request.method == "GET" and path.endswith("/evidence"):
            sid = path.split("/")[2]
            session = self.sessions.get(sid)
            if session is None:
                return httpx.Response(404, json={"detail": "unknown or expired session"})
            return httpx.Response(
                200,
                json={
                    "interaction_count": session["interaction_count"],
                    "tool_calls": list(session["tool_calls"]),
                    "tools_list_count": 1,
                    "descriptions_served": [],
                    "shadow_tool_names": [],
                    "canary": None,
                },
            )
        return httpx.Response(404, json={"detail": f"no route for {request.method} {path}"})


def _install_testbed(monkeypatch, testbed: FakeTestbed) -> None:
    """Point the adapter's httpx at the fake testbed, and nothing else at it."""
    real_client = httpx.AsyncClient
    transport = httpx.MockTransport(testbed.handle)

    def factory(**kwargs):
        return real_client(transport=transport, **kwargs)

    monkeypatch.setattr(mcp_agent_mod, "httpx", SimpleNamespace(AsyncClient=factory))


class RaisingInner:
    supports_history = False

    async def send_prompt(self, prompt, history=()):
        raise RuntimeError("inner transport blew up")


@pytest.mark.asyncio
async def test_session_is_still_closed_when_the_inner_transport_raises(monkeypatch):
    tb = FakeTestbed()
    _install_testbed(monkeypatch, tb)
    t = build_target(_spec())
    t._inner = RaisingInner()

    with pytest.raises(RuntimeError):
        await t.send_prompt("Reach {mcp_url}.")

    sid = t._session["session_id"]
    await t._close_session()
    assert tb.closed == [sid]


@pytest.mark.asyncio
async def test_two_probes_in_one_run_do_not_share_evidence(monkeypatch):
    """The plainest statement of the bug this adapter must not reproduce:
    collect_evidence() after the second begin_probe must describe the second
    probe only, not the first probe's tool calls."""
    tb = FakeTestbed()
    _install_testbed(monkeypatch, tb)
    t = build_target(_spec())
    t._inner = RaisingInner()  # unused directly; evidence is driven via tb

    await t.begin_probe(SimpleNamespace(id="p1", scenario_payload=""))
    sid1 = t._session["session_id"]
    tb.record_tool_call(sid1, "exfil_notes")
    first = await t.collect_evidence()
    assert first["interaction_count"] == 1
    assert len(first["tool_calls"]) == 1

    await t.begin_probe(SimpleNamespace(id="p2", scenario_payload=""))
    sid2 = t._session["session_id"]
    assert sid2 != sid1
    second = await t.collect_evidence()
    assert second["interaction_count"] == 0
    assert second["tool_calls"] == []
