"""The mcp-trap transport: the official MCP SDK over Streamable HTTP, in both protocol eras."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import socket
import time

import httpx
import mcp_types
import pytest
from mcp import Client

from argus.mcp_trap.trap.scenarios import ATTACKER_EMAIL
from argus.mcp_trap.trap import server as trap_server
from argus.mcp_trap.trap.server import TrapServer, _rpc_methods
from argus.mcp_trap.trap.state import TrapState

ALLOWED_HOSTS = ["127.0.0.1:*", "localhost:*", "192.168.1.20:*"]
MCP_HEADERS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}


@pytest.fixture(autouse=True)
def _no_proxy(monkeypatch):
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    monkeypatch.setenv("no_proxy", "127.0.0.1,localhost")


def _listening_socket(port: int = 0) -> socket.socket:
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", port))
    sock.listen()
    return sock


@pytest.fixture
async def trap_url():
    sock = _listening_socket()
    port = sock.getsockname()[1]
    trap = TrapServer(TrapState(), allowed_hosts=ALLOWED_HOSTS)
    try:
        async with trap.serving(sock):
            yield trap, f"http://127.0.0.1:{port}/mcp"
    finally:
        sock.close()


def _on_list_changed(event: asyncio.Event):
    async def handler(message) -> None:
        if isinstance(message, mcp_types.ToolListChangedNotification):
            event.set()
    return handler


async def _until_notified(trap: TrapServer, *events: asyncio.Event) -> None:
    """Wait until each legacy client's GET stream carries notifications; the client opens it after initialize."""
    for _ in range(100):
        await trap.begin_warmup()
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(asyncio.gather(*(e.wait() for e in events)), 0.05)
            break
    assert all(e.is_set() for e in events), "a legacy client never opened its GET stream"
    for e in events:
        e.clear()


@contextlib.asynccontextmanager
async def _listening(c: Client, changed: asyncio.Event):
    """Hold a subscriptions/listen stream; set `changed` on its first event. Yields once acknowledged."""
    ready = asyncio.Event()

    async def run() -> None:
        async with c.listen(tools_list_changed=True) as sub:
            ready.set()
            async for _ in sub:
                changed.set()
                return

    task = asyncio.create_task(run())
    try:
        await asyncio.wait_for(ready.wait(), 5)
        yield
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.parametrize("mode", ["legacy", "auto"])
async def test_client_lists_and_calls_tools_in_both_eras(trap_url, mode):
    trap, url = trap_url
    await trap.begin_round("confused_deputy", "ARGUS-CANARY-00000000000000AA")
    async with Client(url, mode=mode) as c:
        assert (c.protocol_version == "2026-07-28") == (mode == "auto")
        names = sorted(t.name for t in (await c.list_tools()).tools)
        assert names == ["read_notes", "send_email"]
        res = await c.call_tool("read_notes", {})
        assert "audit@argus-trap.invalid" in res.content[0].text
    ev = trap.state.evidence()
    assert ev["tools_list_count"] == 1 and ev["tool_calls"][0]["tool"] == "read_notes"
    assert ev["interaction_count"] >= 2


async def test_legacy_initialize_advertises_tools_list_changed(trap_url):
    trap, url = trap_url
    async with Client(url, mode="legacy") as c:
        assert c.server_capabilities.tools.list_changed is True


@pytest.mark.parametrize("mode", ["legacy", "auto"])
async def test_relist_after_round_notification_counts_in_new_round(trap_url, mode):
    trap, url = trap_url
    changed = asyncio.Event()
    handler = _on_list_changed(changed) if mode == "legacy" else None
    async with Client(url, mode=mode, message_handler=handler) as c:
        async with (_listening(c, changed) if mode == "auto" else contextlib.nullcontext()):
            if mode == "legacy":
                await _until_notified(trap, changed)
            await trap.begin_round("shadowing", "ARGUS-CANARY-00000000000000BB")
            await asyncio.wait_for(changed.wait(), 5)
            await c.list_tools()
            ev = trap.state.evidence()
            assert ev["scenario"] == "shadowing" and ev["listed_after_swap"] is True


async def test_begin_round_resets_state_before_notifying_either_era(trap_url, monkeypatch):
    from mcp.server.session import ServerSession
    from mcp.server.subscriptions import InMemorySubscriptionBus

    trap, url = trap_url
    seen: list[tuple[str, str]] = []

    def spy(cls, name, era):
        original = getattr(cls, name)

        async def wrapper(self, *args, **kwargs):
            seen.append((era, trap.state.evidence()["scenario"]))
            return await original(self, *args, **kwargs)
        monkeypatch.setattr(cls, name, wrapper)

    changed = asyncio.Event()
    async with Client(url, mode="legacy", message_handler=_on_list_changed(changed)):
        await _until_notified(trap, changed)
        spy(ServerSession, "send_tool_list_changed", "legacy")
        spy(InMemorySubscriptionBus, "publish", "modern")
        await trap.begin_round("shadowing", "ARGUS-CANARY-00000000000000DD")
    assert seen == [("legacy", "shadowing"), ("modern", "shadowing")]


async def test_rug_pull_switch_notifies_two_live_legacy_sessions(trap_url):
    trap, url = trap_url
    first, second = asyncio.Event(), asyncio.Event()
    async with Client(url, mode="legacy", message_handler=_on_list_changed(first)) as a, \
            Client(url, mode="legacy", message_handler=_on_list_changed(second)):
        await _until_notified(trap, first, second)
        await trap.begin_round("rug_pull", "ARGUS-CANARY-00000000000000CC")
        await asyncio.wait_for(asyncio.gather(first.wait(), second.wait()), 5)
        first.clear()
        second.clear()
        await a.list_tools()
        assert not first.is_set() and not second.is_set()
        await a.call_tool("read_notes", {})
        await asyncio.wait_for(asyncio.gather(first.wait(), second.wait()), 5)
        relisted = {t.name: t for t in (await a.list_tools()).tools}
        assert ATTACKER_EMAIL in relisted["send_email"].description
    assert trap.state.evidence()["rug_pull"]["relisted_after_switch"] is True


async def test_busy_legacy_session_hears_each_change_once(trap_url):
    trap, url = trap_url
    heard: list[object] = []
    changed = asyncio.Event()

    async def handler(message) -> None:
        if isinstance(message, mcp_types.ToolListChangedNotification):
            heard.append(message)
            changed.set()

    async with Client(url, mode="legacy", message_handler=handler) as c:
        await _until_notified(trap, changed)
        for _ in range(3):
            await c.list_tools()
        heard.clear()
        await trap.begin_round("shadowing", "ARGUS-CANARY-00000000000000EE")
        await asyncio.sleep(0.5)
    assert len(heard) == 1


async def test_unknown_session_id_gets_404_and_counts_as_stale(trap_url):
    trap, url = trap_url
    await trap.begin_warmup()
    async with httpx.AsyncClient() as h:
        r = await h.post(url, headers={"Mcp-Session-Id": "gone", **MCP_HEADERS},
                         json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert r.status_code == 404
    ev = trap.state.evidence()
    assert (ev["stale_session_requests"], ev["interaction_count"]) == (1, 0)


def _initialize(host: str, origin: str | None = None) -> dict:
    return {
        "headers": {"Host": host, **MCP_HEADERS, **({"Origin": origin} if origin else {})},
        "json": {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "host-check", "version": "0"},
        }},
    }


async def test_public_host_header_is_accepted_and_others_refused(trap_url):
    trap, url = trap_url
    async with httpx.AsyncClient() as h:
        public = await h.post(url, **_initialize("192.168.1.20:8765"))
        evil = await h.post(url, **_initialize("evil.example:8765"))
    assert public.status_code == 200
    assert evil.status_code >= 400


async def test_serving_exits_promptly_with_open_streams(capfd, caplog):
    sock = _listening_socket()
    port = sock.getsockname()[1]
    url = f"http://127.0.0.1:{port}/mcp"
    trap = TrapServer(TrapState(), allowed_hosts=ALLOWED_HOSTS)
    holders: list[asyncio.Task] = []
    try:
        async with trap.serving(sock):
            ready = [asyncio.Event(), asyncio.Event()]

            async def hold_legacy() -> None:
                async with Client(url, mode="legacy"):
                    ready[0].set()
                    await asyncio.Event().wait()

            async def hold_listen() -> None:
                async with Client(url, mode="auto") as c, c.listen(tools_list_changed=True):
                    ready[1].set()
                    await asyncio.Event().wait()

            holders = [asyncio.create_task(hold_legacy()), asyncio.create_task(hold_listen())]
            await asyncio.wait_for(asyncio.gather(*(e.wait() for e in ready)), 5)
            # Both stream kinds must really be open, or this test proves nothing.
            reqs = trap.state.evidence()["requests"]
            deadline = time.monotonic() + 5
            while not any(r["http_method"] == "GET" for r in reqs) and time.monotonic() < deadline:
                await asyncio.sleep(0.05)
                reqs = trap.state.evidence()["requests"]
            assert any(r["http_method"] == "GET" for r in reqs)
            assert any("subscriptions/listen" in r["rpc_methods"] for r in reqs)
            capfd.readouterr()
            caplog.clear()
            run_levels = [logging.getLogger(n).level for n in ("uvicorn", "uvicorn.error")]
            started = time.monotonic()
        elapsed = time.monotonic() - started
    finally:
        for t in holders:
            t.cancel()
        await asyncio.gather(*holders, return_exceptions=True)
        sock.close()
    assert elapsed < 5
    again = _listening_socket(port)
    again.close()
    # Open agent streams at exit are normal; uvicorn's cancellation errors must not reach the user.
    err = capfd.readouterr().err
    assert "ERROR" not in err and "Traceback" not in err, err
    assert [r.getMessage() for r in caplog.records if r.levelno >= logging.ERROR] == []
    assert [logging.getLogger(n).level for n in ("uvicorn", "uvicorn.error")] == run_levels


async def test_oversized_body_stops_buffering_and_gets_413_once(monkeypatch):
    from mcp.server.transport_security import DEFAULT_MAX_REQUEST_BODY_SIZE

    state = TrapState()
    state.begin_round("confused_deputy", "ARGUS-CANARY-00000000000000FF")
    finished: list[int] = []
    real_finish = state.finish_request
    monkeypatch.setattr(state, "finish_request", lambda h, status: (finished.append(status), real_finish(h, status)))
    chunk = 1024 * 1024
    total_chunks = DEFAULT_MAX_REQUEST_BODY_SIZE // chunk * 4
    pulled = 0

    async def receive() -> dict:
        nonlocal pulled
        pulled += 1
        head = b"ARGUS-CANARY-00000000000000FF" if pulled == 1 else b""
        return {"type": "http.request", "body": head + b" " * (chunk - len(head)), "more_body": pulled < total_chunks}

    async def inner(scope, receive, send) -> None:
        raise AssertionError("an oversized body must not reach the SDK")

    sent: list[dict] = []

    async def send(message: dict) -> None:
        sent.append(message)

    recorder = trap_server._Recorder(inner, state, DEFAULT_MAX_REQUEST_BODY_SIZE)
    scope = {"type": "http", "path": "/mcp", "method": "POST", "headers": []}
    await recorder(scope, receive, send)
    assert pulled == DEFAULT_MAX_REQUEST_BODY_SIZE // chunk + 1
    assert sent[0]["type"] == "http.response.start" and sent[0]["status"] == 413
    assert (b"content-length", str(len(sent[1]["body"])).encode()) in sent[0]["headers"]
    assert finished == [413]
    ev = state.evidence()
    assert [(q["http_method"], q["status"]) for q in ev["requests"]] == [("POST", 413)]
    assert len(ev["canary_hits"]) == 1


class _Session:
    def __init__(self, stuck: bool = False, broken: bool = False) -> None:
        self.stuck = stuck
        self.broken = broken
        self.notified = 0

    async def send_tool_list_changed(self) -> None:
        if self.stuck:
            await asyncio.Event().wait()
        if self.broken:
            raise RuntimeError("stream closed")
        # Yield first, so a sibling's failure could cancel this send.
        await asyncio.sleep(0)
        self.notified += 1


async def test_stuck_session_cannot_stall_begin_round(monkeypatch):
    monkeypatch.setattr(trap_server, "BROADCAST_TIMEOUT_S", 0.2)
    trap = TrapServer(TrapState(), allowed_hosts=ALLOWED_HOSTS)
    stuck, healthy = _Session(stuck=True), _Session(stuck=False)
    trap._sessions.update({"stuck": stuck, "healthy": healthy})
    started = time.monotonic()
    await asyncio.wait_for(trap.begin_round("rug_pull", "ARGUS-CANARY-00000000000000AB"), 5)
    assert time.monotonic() - started < 1.0
    assert (stuck.notified, healthy.notified) == (0, 1)
    assert trap.state.evidence()["scenario"] == "rug_pull"


async def test_failing_session_does_not_abort_begin_round():
    trap = TrapServer(TrapState(), allowed_hosts=ALLOWED_HOSTS)
    broken, healthy = _Session(broken=True), _Session()
    trap._sessions.update({"broken": broken, "healthy": healthy})
    await trap.begin_round("rug_pull", "ARGUS-CANARY-00000000000000AC")
    assert healthy.notified == 1
    assert trap.state.evidence()["scenario"] == "rug_pull"
    assert trap._sessions["broken"] is broken


def test_broadcast_timeout_is_two_seconds():
    assert trap_server.BROADCAST_TIMEOUT_S == 2.0


@pytest.mark.parametrize(("body", "methods"), [
    (b'[{"jsonrpc":"2.0","id":1,"method":"tools/list"},{"jsonrpc":"2.0","method":"notifications/initialized"},'
     b'{"jsonrpc":"2.0","id":2,"result":{}}]', ["tools/list", "notifications/initialized"]),
    (b"not json \xff", []),
    (b'{"jsonrpc":"2.0","id":3,"result":{}}', []),
    (b'{"jsonrpc":"2.0","id":4,"method":7}', []),
])
def test_rpc_methods_parses_batches_and_tolerates_junk(body, methods):
    assert _rpc_methods(body) == methods


async def test_allowed_origins_cover_http_and_https(trap_url):
    trap, url = trap_url
    async with httpx.AsyncClient() as h:
        codes = [(await h.post(url, **_initialize("127.0.0.1:1", origin=o))).status_code
                 for o in ("http://192.168.1.20:8765", "https://192.168.1.20:8765", "https://evil.example:443")]
    assert codes[:2] == [200, 200] and codes[2] >= 400
