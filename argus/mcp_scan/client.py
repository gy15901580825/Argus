"""The scan-mcp MCP client over Streamable HTTP or stdio-on-host, with a cap on every wait, read and list.

The `mcp` SDK and `httpx2` are optional and imported inside functions only.
"""
from __future__ import annotations

import json
import os
import re
import time
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import dataclass
from typing import Any, AsyncIterator, Literal, Mapping, Sequence

from argus.mcp_scan import rules
from argus.mcp_scan.models import TEXT_KEEP, CallResult, ServerInfo, ToolInfo
from argus.mcp_scan.stdio import StdioProcess, stdio_streams

LIST_PAGES_MAX = 20
TOOLS_MAX = 1000
MESSAGE_BYTES_MAX = 2_000_000
NOTIFICATIONS_MAX = 1000

_BASE_ENV = ("PATH", "HOME", "LANG", "TMPDIR")
# The SDK's own read timeout fires first; this backstop also covers a write the server never reads.
_GRACE_S = 1.0
_CLOSE_WAIT_S = 10.0
_DETAIL_KEEP = 300
# A cut result ends at one of these, so no partial token, and no secret prefix, survives the cut.
_CUT_AT = re.compile(r"[\s\"',;&=:/]")
_CUT_WINDOW = 16_384


@dataclass(frozen=True)
class HttpServer:
    url: str
    headers: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class StdioServer:
    argv: tuple[str, ...]
    env: Mapping[str, str]
    cwd: str | None = None


class ConnectError(Exception):
    def __init__(self, code: Literal["auth", "refused", "timeout", "protocol", "died"], message: str,
                 stderr_tail: str = "") -> None:
        super().__init__(message)
        self.code = code
        self.stderr_tail = stderr_tail


def host_env(passthrough: Sequence[str]) -> dict[str, str]:
    """The minimal environment for a server run on the host: PATH, HOME, LANG, TMPDIR, plus each named variable."""
    env = {name: os.environ[name] for name in _BASE_ENV if name in os.environ}
    for name in passthrough:
        if name not in os.environ:
            raise ValueError(f"--env {name}: the variable is not set in this environment")
        env[name] = os.environ[name]
    return env


def keep_text(text: str) -> str:
    """Cut result text to TEXT_KEEP, then back to a token boundary and to before any secret the cut would split."""
    if len(text) <= TEXT_KEEP:
        return text
    lo = max(0, TEXT_KEEP - _CUT_WINDOW)
    cut = TEXT_KEEP
    for _, s, e in rules.secret_hits(text[lo:TEXT_KEEP + _CUT_WINDOW]):
        if lo + s < cut < lo + e:
            cut = lo + s
    if not _CUT_AT.match(text, cut):
        while cut and not _CUT_AT.match(text, cut - 1):
            cut -= 1
    return text[:cut]


def _result_text(result: Any) -> str:
    parts = [c.text for c in result.content if getattr(c, "type", None) == "text"]
    if result.structured_content is not None:
        # ensure_ascii=False keeps hidden characters visible to the checks.
        parts.append(json.dumps(result.structured_content, ensure_ascii=False))
    return keep_text("\n".join(parts))


def _detail(text: str) -> str:
    return rules.redact(text)[:_DETAIL_KEEP]


def _tool_info(tool: Any) -> ToolInfo:
    raw = tool.model_dump(by_alias=True, mode="json", exclude_none=True)
    return ToolInfo(name=tool.name, title=tool.title or "", description=tool.description or "",
                    input_schema=raw.get("inputSchema"), annotations=raw.get("annotations") or {}, raw=raw)


@dataclass
class _HttpState:
    """What the response hook saw; the SDK turns every non-2xx without a JSON-RPC body into one generic error."""
    auth_status: int | None = None
    oauth: bool = False
    error_status: int | None = None
    session_id: str | None = None
    body_too_large: bool = False


def _http_client(target: HttpServer, timeout_s: float, state: _HttpState) -> Any:
    import httpx2

    class BodyTooLarge(httpx2.StreamError):
        pass

    class CappedStream(httpx2.AsyncByteStream):
        def __init__(self, inner: Any) -> None:
            self._inner = inner

        async def __aiter__(self) -> Any:
            size = 0
            async for part in self._inner:
                size += len(part)
                if size > MESSAGE_BYTES_MAX:
                    state.body_too_large = True
                    raise BodyTooLarge(f"response body passed {MESSAGE_BYTES_MAX} bytes")
                yield part

        async def aclose(self) -> None:
            await self._inner.aclose()

    class CappedTransport(httpx2.AsyncHTTPTransport):
        async def handle_async_request(self, request: Any) -> Any:
            response = await super().handle_async_request(request)
            # An event stream is capped per event by the SDK (max_sse_event_size), not as a whole.
            if not response.headers.get("content-type", "").lower().startswith("text/event-stream"):
                response.stream = CappedStream(response.stream)
            return response

    async def record(response: Any) -> None:
        status = response.status_code
        if status in (401, 403) and state.auth_status is None:
            state.auth_status = status
            state.oauth = status == 401 and bool(response.headers.get("www-authenticate"))
        elif status >= 400:
            state.error_status = status
        if session_id := response.headers.get("mcp-session-id"):
            state.session_id = session_id

    # Read timeout off: it would keep cutting the standing GET stream; requests are bounded by the session.
    return httpx2.AsyncClient(headers=dict(target.headers), timeout=httpx2.Timeout(timeout_s, read=None),
                              event_hooks={"response": [record]}, transport=CappedTransport())


def _leaves(exc: BaseException) -> list[BaseException]:
    if isinstance(exc, BaseExceptionGroup):
        return [leaf for sub in exc.exceptions for leaf in _leaves(sub)]
    return [exc]


class McpSession:
    """One MCP session, owned by a background task so a transport crash ends the session, not the scan."""

    def __init__(self, target: HttpServer | StdioServer, timeout_s: float) -> None:
        import anyio

        self.server_info: ServerInfo | None = None
        self.list_changed = False
        self.alive = True
        self._target = target
        self._timeout_s = timeout_s
        self._http = _HttpState()
        self._proc: StdioProcess | None = None
        self._session: Any = None
        self._notifications = 0
        self._death = ""
        self._scope: Any = None
        self._connect_error: ConnectError | None = None
        self._ready = anyio.Event()
        self._stop = anyio.Event()
        self._done = anyio.Event()

    @property
    def session_id(self) -> str | None:
        return self._http.session_id if isinstance(self._target, HttpServer) else None

    @property
    def stderr_tail(self) -> str:
        return self._proc.stderr_tail if self._proc is not None else ""

    # --- lifecycle -----------------------------------------------------------------------------------------------

    async def _own(self) -> None:
        import anyio
        from mcp.client.session import ClientSession
        from mcp.client.streamable_http import streamable_http_client

        try:
            async with AsyncExitStack() as stack:
                if isinstance(self._target, HttpServer):
                    client = await stack.enter_async_context(_http_client(self._target, self._timeout_s, self._http))
                    read, write = await stack.enter_async_context(streamable_http_client(
                        self._target.url, http_client=client, max_sse_event_size=MESSAGE_BYTES_MAX))
                else:
                    read, write, self._proc = await stack.enter_async_context(
                        stdio_streams(self._target, line_max=MESSAGE_BYTES_MAX))
                session = await stack.enter_async_context(ClientSession(
                    read, write, read_timeout_seconds=self._timeout_s, message_handler=self._on_message))
                with anyio.fail_after(self._timeout_s):
                    init = await session.initialize()
                self._session = session
                self.server_info = ServerInfo(init.server_info.name, init.server_info.version)
                self._ready.set()
                await self._stop.wait()
        except Exception as exc:
            if self._ready.is_set():
                self._end(f"the connection failed ({type(exc).__name__})")
            else:
                self._connect_error = self._classify(exc)
        finally:
            self.alive = False
            self._done.set()
            self._ready.set()

    def _classify(self, exc: BaseException) -> ConnectError:
        import httpx2
        from mcp.shared.exceptions import MCPError
        from mcp_types import CONNECTION_CLOSED, REQUEST_TIMEOUT

        tail = self.stderr_tail
        if self._http.auth_status is not None:
            status = self._http.auth_status
            if self._http.oauth:
                return ConnectError("auth", f"The server answered HTTP {status} and asks for OAuth, which is not "
                                            "supported; pass a token with --header 'Authorization: Bearer <token>'.")
            return ConnectError("auth", f"The server answered HTTP {status}; pass the credentials its clients send "
                                        "with --header 'Name: value'.")
        leaves = _leaves(exc)
        for leaf in leaves:
            if isinstance(leaf, (TimeoutError, httpx2.TimeoutException)) or (
                    isinstance(leaf, MCPError) and leaf.code == REQUEST_TIMEOUT):
                return ConnectError("timeout", f"The server did not finish the MCP handshake within "
                                               f"{self._timeout_s:g} s.", tail)
        for leaf in leaves:
            if isinstance(leaf, httpx2.ConnectError):
                return ConnectError("refused", "Could not connect to the server (connection refused or host "
                                               "not found).")
            if isinstance(leaf, OSError) and self._proc is None and isinstance(self._target, StdioServer):
                return ConnectError("died", f"Could not start the server command: {leaf.strerror or leaf}.")
            if isinstance(leaf, MCPError) and leaf.code == CONNECTION_CLOSED and self._proc is not None:
                return ConnectError("died", "The server process exited before the MCP handshake finished "
                                            f"(exit code {self._proc.returncode}).", tail)
        # Server-supplied text stays out of the message: it could echo a credential.
        if self._http.error_status is not None:
            reason = f"HTTP {self._http.error_status}"
        else:
            reason = next((f"JSON-RPC error {leaf.code}" for leaf in leaves if isinstance(leaf, MCPError)),
                          type(leaves[0]).__name__)
        return ConnectError("protocol", f"The server did not complete the MCP handshake ({reason}).", tail)

    def _end(self, reason: str) -> None:
        if self.alive:
            self.alive = False
            self._death = reason
        if self._scope is not None:
            self._scope.cancel()
        self._stop.set()

    async def _on_message(self, message: Any) -> None:
        import mcp_types

        if isinstance(message, Exception):
            return
        self._notifications += 1
        if isinstance(message, mcp_types.ToolListChangedNotification):
            self.list_changed = True
        if self._notifications > NOTIFICATIONS_MAX and self.alive:
            self._end(f"the server sent more than {NOTIFICATIONS_MAX} notifications; the session was closed")

    # --- requests ------------------------------------------------------------------------------------------------

    async def _send(self, request: Any, result_type: Any) -> tuple[Any, tuple[str, str] | None]:
        """(result, None), or (None, (status, detail)) for any failure; never raises for the server's sake."""
        import anyio
        from mcp.shared.exceptions import MCPError
        from pydantic import ValidationError

        if not self.alive:
            return None, ("transport_error", self._death or "the session is closed")
        failure: tuple[str, str] | None = None
        self._http.body_too_large = False
        with anyio.move_on_after(self._timeout_s + _GRACE_S) as scope:
            self._scope = scope
            try:
                return await self._session.send_request(
                    request, result_type, request_read_timeout_seconds=self._timeout_s), None
            except MCPError as exc:
                failure = self._failure(exc)
            except ValidationError:
                failure = ("rpc_error", "the reply did not match the MCP schema")
            except (anyio.ClosedResourceError, anyio.BrokenResourceError, anyio.EndOfStream):
                self._end("the connection closed")
                failure = ("transport_error", self._death)
            finally:
                self._scope = None
        if failure is None:  # the scope was cancelled: a flood closed the session, or the backstop fired
            failure = ("transport_error", self._death) if not self.alive else (
                "timeout", f"no reply within {self._timeout_s:g} s")
        return None, failure

    def _failure(self, exc: Any) -> tuple[str, str]:
        from mcp_types import CONNECTION_CLOSED, PARSE_ERROR, REQUEST_TIMEOUT

        if exc.code == REQUEST_TIMEOUT:
            return "timeout", f"no reply within {self._timeout_s:g} s"
        too_large = f"a message from the server passed {MESSAGE_BYTES_MAX} bytes"
        if self._proc is not None and exc.code == CONNECTION_CLOSED:
            if self._proc.line_too_long:
                self._end(too_large + "; the session was closed")
                return "too_large", self._death
            if self.alive:
                rc = self._proc.returncode
                self._end("the server process exited" + (f" (exit code {rc})" if rc is not None else ""))
            return "transport_error", self._death
        if self._http.body_too_large and exc.code == PARSE_ERROR:
            return "too_large", too_large
        if exc.code == CONNECTION_CLOSED:
            # The SDK's text for an SSE event past max_sse_event_size (httpx2 SSEError).
            if "byte limit" in exc.message:
                return "too_large", too_large
            if exc.message == "Connection closed":  # the session itself is gone, not one response stream
                self._end("the connection closed")
                return "transport_error", self._death
            return "transport_error", _detail(exc.message)
        return "rpc_error", _detail(f"JSON-RPC error {exc.code}: {exc.message}")

    async def list_tools(self) -> tuple[list[ToolInfo], list[str]]:
        import mcp_types

        tools: list[ToolInfo] = []
        notes: list[str] = []
        cursor: str | None = None
        seen = 0
        for _ in range(LIST_PAGES_MAX):
            params = mcp_types.PaginatedRequestParams(cursor=cursor) if cursor else None
            result, failure = await self._send(mcp_types.ListToolsRequest(params=params), mcp_types.ListToolsResult)
            if failure is not None:
                status, detail = failure
                code = {"timeout": "timeout", "transport_error": "died"}.get(status, "protocol")
                raise ConnectError(code, f"tools/list failed: {detail}.", self.stderr_tail)
            seen += len(result.tools)
            tools.extend(_tool_info(t) for t in result.tools[:TOOLS_MAX - len(tools)])
            cursor = result.next_cursor
            if not cursor or len(tools) >= TOOLS_MAX:
                break
        else:
            notes.append(f"tools/list stopped after {LIST_PAGES_MAX} pages")
        if seen > TOOLS_MAX:
            notes.append(f"tools/list returned {seen} tools; kept the first {TOOLS_MAX}")
        elif cursor and len(tools) >= TOOLS_MAX:
            notes.append(f"tools/list has more than {TOOLS_MAX} tools; kept the first {TOOLS_MAX}")
        return tools, notes

    async def call(self, name: str, arguments: dict) -> CallResult:
        import mcp_types

        start = time.monotonic()
        request = mcp_types.CallToolRequest(params=mcp_types.CallToolRequestParams(name=name, arguments=arguments))
        # Not ClientSession.call_tool: it re-validates against outputSchema and raises, losing the result.
        result, failure = await self._send(request, mcp_types.CallToolResult)
        latency_ms = (time.monotonic() - start) * 1000
        if failure is not None:
            return CallResult(status=failure[0], is_error=False, text="", detail=failure[1], latency_ms=latency_ms)
        return CallResult(status="ok", is_error=bool(result.is_error), text=_result_text(result), detail="",
                          latency_ms=latency_ms)


@asynccontextmanager
async def open_session(target: HttpServer | StdioServer, *, timeout_s: float) -> AsyncIterator[McpSession]:
    """Connect and run the handshake-era `initialize`; raises ConnectError when the session cannot start."""
    import anyio

    session = McpSession(target, timeout_s)
    async with anyio.create_task_group() as tg:
        tg.start_soon(session._own)
        await session._ready.wait()
        if session._connect_error is None:
            try:
                yield session
            finally:
                session._stop.set()
                with anyio.move_on_after(_CLOSE_WAIT_S, shield=True):
                    await session._done.wait()
                tg.cancel_scope.cancel()
    if session._connect_error is not None:
        raise session._connect_error from None
