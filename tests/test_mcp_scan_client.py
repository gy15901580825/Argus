"""scan-mcp client: Streamable HTTP and stdio-on-host against hostile fixture servers, with every cap."""
from __future__ import annotations

import json
import os
import re
import secrets
import socket
import sys
import threading
import time
from contextlib import contextmanager

import pytest

pytest.importorskip("mcp")

import anyio  # noqa: E402

from argus.mcp_scan import client as client_module  # noqa: E402
from argus.mcp_scan import rules  # noqa: E402
from argus.mcp_scan.client import (  # noqa: E402
    LIST_PAGES_MAX,
    NOTIFICATIONS_MAX,
    TOOLS_MAX,
    _http_client,
    _HttpState,
    ConnectError,
    HttpServer,
    StdioServer,
    host_env,
    keep_text,
    open_session,
)
from argus.mcp_scan.models import TEXT_KEEP, ServerInfo  # noqa: E402
from argus.mcp_scan.stdio import STDERR_KEEP  # noqa: E402
from mcp_scan_harness import serve_http, stdio_argv  # noqa: E402

T = 10.0


@pytest.fixture(autouse=True)
def _no_proxy(monkeypatch):
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    monkeypatch.setenv("no_proxy", "127.0.0.1,localhost")


def _stdio(name: str, passthrough: tuple[str, ...] = ()) -> StdioServer:
    return StdioServer(argv=stdio_argv(name), env=host_env(passthrough))


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _gone(pid: int, within_s: float = 3.0) -> bool:
    # A killed grandchild is reaped by init, not by us; give it a moment.
    deadline = time.monotonic() + within_s
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        time.sleep(0.05)
    return False


async def _connect_error(target, timeout_s: float = T) -> ConnectError:
    with pytest.raises(ConnectError) as e:
        async with open_session(target, timeout_s=timeout_s):
            pass
    return e.value


# --- listing and server info ---------------------------------------------------------------------------------


async def test_http_lists_tools_and_server_info():
    with serve_http("basic") as url:
        async with open_session(HttpServer(url), timeout_s=T) as s:
            tools, notes = await s.list_tools()
            assert s.alive
            assert s.session_id
    assert {t.name: t.read_only for t in tools} == {"read_env": True, "echo": False}
    assert notes == []
    assert s.server_info == ServerInfo("argus-fixture-basic", "1.0.0")
    assert tools[0].input_schema == {"type": "object", "properties": {}}
    assert tools[0].raw["outputSchema"]["required"] == ["count"]


async def test_stdio_lists_tools_and_server_info():
    async with open_session(_stdio("basic"), timeout_s=T) as s:
        tools, notes = await s.list_tools()
        assert s.session_id is None
    assert {t.name: t.read_only for t in tools} == {"read_env": True, "echo": False}
    assert notes == []
    assert s.server_info == ServerInfo("argus-fixture-basic", "1.0.0")


# --- auth ------------------------------------------------------------------------------------------------------


async def test_http_401_raises_auth_error_with_header_hint():
    tok = "fixture-" + secrets.token_hex(8)
    with serve_http("basic", require_header=("Authorization", "Bearer " + tok)) as url:
        err = await _connect_error(HttpServer(url))
        assert err.code == "auth"
        assert "--header" in str(err) and "401" in str(err)
        assert "OAuth" not in str(err)
        assert tok not in str(err)

        wrong = await _connect_error(HttpServer(url, headers=(("Authorization", "Bearer wrong-" + tok),)))
        assert wrong.code == "auth" and "403" in str(wrong) and tok not in str(wrong)

        async with open_session(HttpServer(url, headers=(("Authorization", "Bearer " + tok),)), timeout_s=T) as s:
            tools, _ = await s.list_tools()
    assert len(tools) == 2


async def test_oauth_401_mentions_oauth_is_not_supported():
    with serve_http("basic", oauth=True) as url:
        err = await _connect_error(HttpServer(url))
    assert err.code == "auth"
    assert "--header" in str(err)
    assert "OAuth" in str(err) and "not supported" in str(err)


async def test_connection_refused_is_refused():
    tok = secrets.token_hex(8)
    err = await _connect_error(HttpServer(f"http://u:{tok}@127.0.0.1:{_free_port()}/mcp?token={tok}"))
    assert err.code == "refused"
    assert tok not in str(err)
    assert err.__cause__ is None and err.__suppress_context__


async def test_stdio_process_that_exits_is_died_with_stderr():
    argv = (sys.executable, "-c", "import sys; sys.stderr.write('boom-marker'); sys.exit(3)")
    err = await _connect_error(StdioServer(argv=argv, env=host_env([])))
    assert err.code == "died" and "exit code 3" in str(err)
    assert "boom-marker" in err.stderr_tail


async def test_stdio_command_that_cannot_start_is_died(tmp_path):
    err = await _connect_error(StdioServer(argv=(str(tmp_path / "no-such-server"),), env=host_env([])))
    assert err.code == "died" and "Could not start" in str(err)


async def test_http_endpoint_that_is_not_mcp_is_protocol():
    with serve_http("basic") as url:
        err = await _connect_error(HttpServer(url.replace("/mcp", "/not-mcp")))
    assert err.code == "protocol" and "HTTP 404" in str(err)


@contextmanager
def _session_id_then_silence():
    """A raw HTTP server: SSE headers and a session id for the first POST, then nothing on any request."""
    release = threading.Event()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    sock.listen()

    def handle(conn):
        with conn:
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(65536)
                if not chunk:
                    return
                data += chunk
            if data.startswith(b"POST"):
                conn.sendall(b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\nmcp-session-id: abc\r\n"
                             b"transfer-encoding: chunked\r\n\r\n")
            release.wait(30)

    def serve():
        while not release.is_set():
            try:
                conn, _ = sock.accept()
            except OSError:
                return
            threading.Thread(target=handle, args=(conn,), daemon=True).start()

    threading.Thread(target=serve, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{sock.getsockname()[1]}/mcp"
    finally:
        release.set()
        sock.close()


async def test_http_server_that_never_answers_after_session_id_times_out(monkeypatch):
    monkeypatch.setattr(client_module, "_CLOSE_WAIT_S", 2.0)
    with _session_id_then_silence() as url:
        start = time.monotonic()
        with anyio.fail_after(20):
            err = await _connect_error(HttpServer(url), timeout_s=1)
    assert err.code == "timeout"
    assert time.monotonic() - start < 8


async def test_exception_in_body_leaves_bare():
    for exc in (ValueError("body"), ConnectError("died", "tools/list failed.")):
        with pytest.raises(type(exc)) as e:
            async with open_session(_stdio("basic"), timeout_s=T):
                raise exc
        assert e.value is exc


async def test_list_tools_failure_in_body_is_a_connect_error():
    with pytest.raises(ConnectError) as e:
        async with open_session(_stdio("huge_result"), timeout_s=T) as s:
            assert (await s.call("huge", {})).status == "too_large"
            await s.list_tools()
    assert e.value.code == "died"


async def test_stdio_server_that_stops_reading_is_connection_closed():
    script = (
        "import json, os, sys, time\n"
        "req = json.loads(sys.stdin.readline())\n"
        "res = {'protocolVersion': req['params']['protocolVersion'], 'capabilities': {},"
        " 'serverInfo': {'name': 'closer', 'version': '1'}}\n"
        "sys.stdout.write(json.dumps({'jsonrpc': '2.0', 'id': req['id'], 'result': res}) + '\\n')\n"
        "sys.stdout.flush()\n"
        "sys.stdin.readline()\n"
        "os.close(0)\n"
        "sys.stderr.write('stdin-closed\\n')\n"
        "sys.stderr.flush()\n"
        "time.sleep(30)\n")
    async with open_session(StdioServer(argv=(sys.executable, "-c", script), env=host_env([])), timeout_s=T) as s:
        with anyio.fail_after(5):  # a request written before the close would sit in the pipe until it times out
            while "stdin-closed" not in s.stderr_tail:
                await anyio.sleep(0.01)
        r = await s.call("anything", {})
        assert r.status == "transport_error"
        assert r.detail == "the connection closed"
        assert s.alive is False


async def test_http_client_honours_env_proxy(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example.invalid:3128")
    client = _http_client(HttpServer("https://mcp.example.invalid/mcp"), 5.0, _HttpState())
    try:
        assert any(pattern.pattern == "https://" and transport is not None
                   for pattern, transport in client._mounts.items())
    finally:
        await client.aclose()


# --- hangs -----------------------------------------------------------------------------------------------------


async def test_stdio_never_answers_initialize_times_out_and_kills():
    start = time.monotonic()
    err = await _connect_error(_stdio("slow_init"), timeout_s=1)
    assert err.code == "timeout"
    assert time.monotonic() - start < 6
    m = re.search(r"pid=(\d+) child=(\d+)", err.stderr_tail)
    assert m, err.stderr_tail
    assert _gone(int(m.group(1))), "the server process is still alive"
    assert _gone(int(m.group(2))), "the server's child process is still alive"


async def test_call_timeout_is_a_result_not_an_exception():
    async with open_session(_stdio("hang_tool"), timeout_s=1) as s:
        start = time.monotonic()
        r = await s.call("hang", {})
        assert r.status == "timeout"
        assert time.monotonic() - start < 4
        assert s.alive
        tools, _ = await s.list_tools()
    assert [t.name for t in tools] == ["hang"]


# --- environment -----------------------------------------------------------------------------------------------


async def test_stdio_child_gets_only_the_minimal_env(monkeypatch):
    monkeypatch.setenv("FOO", "foo-value")
    monkeypatch.setenv("ARGUS_TEST_SECRET", "s3cret")
    monkeypatch.setenv("USER", "someone")
    monkeypatch.setenv("SHELL", "/bin/sh")
    async with open_session(_stdio("basic", ("FOO",)), timeout_s=T) as s:
        r = await s.call("read_env", {})
    assert r.status == "ok"
    names = set(json.loads(r.text.split("\n")[0]))
    assert "FOO" in names
    # Python itself may set LC_CTYPE (PEP 538 locale coercion).
    assert names <= {"PATH", "HOME", "LANG", "TMPDIR", "FOO", "LC_CTYPE"}
    assert not names & {"USER", "SHELL", "ARGUS_TEST_SECRET"}


def test_host_env_keeps_only_the_base_and_named(monkeypatch):
    monkeypatch.setenv("PATH", "/usr/bin")
    monkeypatch.setenv("HOME", "/home/x")
    monkeypatch.delenv("LANG", raising=False)
    monkeypatch.setenv("TMPDIR", "/tmp/x")
    monkeypatch.setenv("FOO", "1")
    monkeypatch.setenv("BAR", "2")
    assert host_env(["FOO"]) == {"PATH": "/usr/bin", "HOME": "/home/x", "TMPDIR": "/tmp/x", "FOO": "1"}


def test_host_env_unset_name_is_an_error(monkeypatch):
    monkeypatch.delenv("ARGUS_NOT_SET", raising=False)
    with pytest.raises(ValueError, match="ARGUS_NOT_SET"):
        host_env(["ARGUS_NOT_SET"])


# --- floods and size caps --------------------------------------------------------------------------------------


async def test_oversize_stdio_line_kills_session():
    async with open_session(_stdio("huge_result"), timeout_s=T) as s:
        start = time.monotonic()
        r = await s.call("huge", {})
        assert r.status == "too_large"
        assert s.alive is False
        assert time.monotonic() - start < 8
        again = await s.call("huge", {})
        assert again.status == "transport_error"
    async with open_session(_stdio("huge_result"), timeout_s=T) as fresh:
        tools, _ = await fresh.list_tools()
    assert [t.name for t in tools] == ["huge"]


# SSE is the SDK server's default; a JSON body takes a different path through the client.
@pytest.mark.parametrize("json_response", [False, True], ids=["sse", "json"])
async def test_oversize_http_body_fails_call_not_scan(json_response):
    with serve_http("huge_result", json_response=json_response) as url:
        async with open_session(HttpServer(url), timeout_s=T) as s:
            r = await s.call("huge", {})
            assert r.status == "too_large", r
            assert r.text == ""
        async with open_session(HttpServer(url), timeout_s=T) as fresh:
            tools, _ = await fresh.list_tools()
    assert [t.name for t in tools] == ["huge"]


async def test_endless_cursor_stops_at_page_cap():
    async with open_session(_stdio("many_pages"), timeout_s=T) as s:
        tools, notes = await s.list_tools()
    assert LIST_PAGES_MAX == 20
    assert len(tools) == 20
    assert notes == ["tools/list stopped after 20 pages"]


async def test_tool_count_capped():
    async with open_session(_stdio("many_tools"), timeout_s=T) as s:
        tools, notes = await s.list_tools()
    assert TOOLS_MAX == 1000
    assert len(tools) == 1000
    assert [t.name for t in tools[:2]] == ["tool_0", "tool_1"]
    assert notes == ["tools/list returned 5000 tools; kept the first 1000"]


# unknown_flood uses a method the SDK drops before its message handler; the cap must still count it.
@pytest.mark.parametrize("fixture", ["notify_flood", "unknown_flood"])
@pytest.mark.parametrize("transport", ["stdio", "http"])
async def test_notification_flood_closes_session(transport, fixture):
    assert NOTIFICATIONS_MAX == 1000
    with serve_http(fixture) as url:
        target = _stdio(fixture) if transport == "stdio" else HttpServer(url)
        async with open_session(target, timeout_s=T) as s:
            r = await s.call("flood", {})
            assert r.status == "transport_error"
            assert "1000 notifications" in r.detail
            assert s.alive is False
            again = await s.call("flood", {})
            assert again.status == "transport_error"


# --- results ---------------------------------------------------------------------------------------------------


async def test_output_schema_mismatch_still_returns_result():
    with serve_http("basic") as url:
        async with open_session(HttpServer(url), timeout_s=T) as s:
            await s.list_tools()
            r = await s.call("read_env", {})
    assert r.status == "ok" and r.is_error is False
    lines = r.text.split("\n")
    assert isinstance(json.loads(lines[0]), list)
    assert json.loads(lines[1]) == {"count": "many"}


async def test_list_changed_notification_is_recorded():
    async with open_session(_stdio("basic"), timeout_s=T) as s:
        await s.list_tools()
        assert s.list_changed is False
        r = await s.call("echo", {"text": "hello"})
        assert r.status == "ok" and r.text == "hello"
        assert s.list_changed is True


async def test_stderr_is_kept_not_printed(capfd):
    async with open_session(_stdio("basic"), timeout_s=T) as s:
        await s.list_tools()
        with anyio.fail_after(5):
            while "basic-ready" not in s.stderr_tail:
                await anyio.sleep(0.01)
        tail = s.stderr_tail
    out, err = capfd.readouterr()
    assert "basic-ready" not in out + err
    assert "xxxxxxxx" not in out + err
    assert tail.endswith("basic-ready\n")
    assert len(tail.encode()) <= STDERR_KEEP
    assert tail.count("x") < 6000


async def test_unknown_tool_is_a_result():
    async with open_session(_stdio("basic"), timeout_s=T) as s:
        r = await s.call("no_such_tool", {})
    assert r.status == "ok" and r.is_error is True


# --- TEXT_KEEP cut (controller amendment 1) ------------------------------------------------------------------


def _no_prefix(stored: str, secret: str) -> bool:
    return not any(secret[:k] in stored for k in range(4, len(secret) + 1))


def test_cut_drops_a_token_split_by_the_boundary():
    secret = "gh" + "p_" + "Ab3" * 12  # built at runtime: no literal token in the repo
    text = ("word " * ((TEXT_KEEP - 10) // 5)).ljust(TEXT_KEEP - 10) + secret + " tail"
    stored = keep_text(text)
    assert len(stored) <= TEXT_KEEP
    assert _no_prefix(stored, secret)
    assert stored.endswith(" ")


def test_cut_drops_a_secret_value_with_slashes_split_by_the_boundary():
    value = "Zq8vLm2NqTx4" + "/Rk7pWc/Hy5Bd" + "Fg3Js9Ke"
    lead = "aws_secret_access_key="
    pad = ("word " * (TEXT_KEEP // 5))[: TEXT_KEEP - len(lead) - 16].rstrip() + " "
    text = pad.rjust(TEXT_KEEP - len(lead) - 16) + lead + value + " tail"
    stored = keep_text(text)
    assert _no_prefix(stored, value)
    assert rules.secret_hits(stored) == []


def test_cut_without_a_delimiter_keeps_the_hard_cut():
    tags = "\U000E0041" * (TEXT_KEEP + 1)
    assert keep_text(tags) == tags[:TEXT_KEEP]
    long_token = "w " + "z" * (TEXT_KEEP + 10)
    assert len(keep_text(long_token)) == TEXT_KEEP


def test_cut_keeps_text_under_the_limit():
    assert keep_text("short") == "short"
    whole = "a" * (TEXT_KEEP - 1) + " "
    assert keep_text(whole + "b") == whole
