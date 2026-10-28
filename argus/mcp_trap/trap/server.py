"""The trap's MCP endpoint: the official MCP SDK over Streamable HTTP, behind a request recorder."""

from __future__ import annotations

import asyncio
import contextlib
import json
from collections.abc import AsyncIterator, Sequence
from typing import Any

from argus.mcp_trap.trap.state import TrapState

SERVER_NAME = "argus-mcp-trap"
SHUTDOWN_GRACE_S = 2.0
MCP_PATH = "/mcp"


def _rpc_methods(body: bytes) -> list[str]:
    try:
        payload = json.loads(body)
    except ValueError:
        return []
    messages = payload if isinstance(payload, list) else [payload]
    return [m["method"] for m in messages if isinstance(m, dict) and isinstance(m.get("method"), str)]


class _Recorder:
    """Records every /mcp request in TrapState, including ones the SDK rejects before any handler."""

    def __init__(self, app: Any, state: TrapState) -> None:
        self._app = app
        self._state = state

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http" or scope["path"] != MCP_PATH:
            await self._app(scope, receive, send)
            return

        chunks: list[bytes] = []
        pending: list[dict] = []
        while True:
            message = await receive()
            if message["type"] != "http.request":
                pending.append(message)
                break
            chunks.append(message.get("body", b""))
            if not message.get("more_body", False):
                break
        body = b"".join(chunks)
        pending.insert(0, {"type": "http.request", "body": body, "more_body": False})

        async def replay() -> Any:
            # After the body, defer to the real receive: SSE responses wait on it to see the disconnect.
            return pending.pop(0) if pending else await receive()

        handle = self._state.start_request(
            http_method=scope["method"],
            rpc_methods=_rpc_methods(body),
            has_session_id=any(k.lower() == b"mcp-session-id" for k, _ in scope["headers"]),
            body=body.decode("utf-8", "replace"),
        )
        finished = False

        async def record_status(message: dict) -> None:
            nonlocal finished
            # Finish at response start: SSE responses stay open long after.
            if message["type"] == "http.response.start" and not finished:
                finished = True
                self._state.finish_request(handle, message["status"])
            await send(message)

        try:
            await self._app(scope, replay, record_status)
        finally:
            if not finished:
                # uvicorn answers 500 when the app ends without starting a response.
                self._state.finish_request(handle, 500)


def _tool_server_class() -> type:
    from mcp.server import NotificationOptions, Server

    class _ToolsChangedServer(Server):
        # The session manager builds init options without NotificationOptions; advertise listChanged anyway.
        def create_initialization_options(self, notification_options=None, *args: Any, **kwargs: Any) -> Any:
            return super().create_initialization_options(
                notification_options or NotificationOptions(tools_changed=True), *args, **kwargs)

    return _ToolsChangedServer


class TrapServer:
    def __init__(self, state: TrapState, *, allowed_hosts: Sequence[str]) -> None:
        import mcp_types
        from mcp.server.subscriptions import InMemorySubscriptionBus, ListenHandler

        self.state = state
        self._allowed_hosts = list(allowed_hosts)
        self._bus = InMemorySubscriptionBus()
        # Handshake-era sessions by Mcp-Session-Id; ctx.session is rebuilt per message, so keep the latest.
        self._sessions: dict[str, Any] = {}
        self._server = _tool_server_class()(
            SERVER_NAME,
            on_list_tools=self._on_list_tools,
            on_call_tool=self._on_call_tool,
            on_subscriptions_listen=ListenHandler(self._bus),
        )
        self._server.add_notification_handler(
            "notifications/initialized", mcp_types.NotificationParams, self._on_initialized)

    def _remember(self, ctx: Any) -> None:
        from mcp_types.version import HANDSHAKE_PROTOCOL_VERSIONS

        if ctx.protocol_version not in HANDSHAKE_PROTOCOL_VERSIONS or ctx.request is None:
            return
        session_id = ctx.request.headers.get("mcp-session-id")
        if session_id:
            self._sessions[session_id] = ctx.session

    async def _on_initialized(self, ctx: Any, params: Any) -> None:
        # An idle client never calls a tool handler, but must still hear about list changes.
        self._remember(ctx)

    async def _on_list_tools(self, ctx: Any, params: Any) -> Any:
        import mcp_types

        self._remember(ctx)
        tools = [mcp_types.Tool.model_validate(t) for t in self.state.on_tools_list()]
        return mcp_types.ListToolsResult(tools=tools)

    async def _on_call_tool(self, ctx: Any, params: Any) -> Any:
        import mcp_types

        self._remember(ctx)
        text, is_error, list_changed = self.state.on_tool_call(params.name, dict(params.arguments or {}))
        if list_changed:
            await self._broadcast()
        return mcp_types.CallToolResult(content=[mcp_types.TextContent(type="text", text=text)], is_error=is_error)

    # Reset first, then notify: a re-list sent in reply must count for the new round.
    async def begin_warmup(self) -> None:
        self.state.begin_warmup()
        await self._broadcast()

    async def begin_round(self, scenario: str, canary: str) -> None:
        self.state.begin_round(scenario, canary)
        await self._broadcast()

    async def _broadcast(self) -> None:
        from mcp.server.subscriptions import ToolsListChanged

        for session in list(self._sessions.values()):
            await session.send_tool_list_changed()
        await self._bus.publish(ToolsListChanged())

    def asgi_app(self) -> Any:
        from mcp.server.transport_security import TransportSecuritySettings

        security = TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=self._allowed_hosts,
            allowed_origins=[f"http://{h}" for h in self._allowed_hosts],
        )
        app = self._server.streamable_http_app(streamable_http_path=MCP_PATH, transport_security=security)
        return _Recorder(app, self.state)

    @contextlib.asynccontextmanager
    async def serving(self, sock: Any) -> AsyncIterator[None]:
        import uvicorn

        server = uvicorn.Server(uvicorn.Config(
            self.asgi_app(), log_level="warning", lifespan="on", timeout_graceful_shutdown=SHUTDOWN_GRACE_S))
        task = asyncio.create_task(server.serve(sockets=[sock]))
        try:
            deadline = asyncio.get_running_loop().time() + 10
            while not server.started:
                if task.done():
                    exc = None if task.cancelled() else task.exception()
                    raise RuntimeError(f"trap server failed to start: {exc!r}") from exc
                if asyncio.get_running_loop().time() > deadline:
                    raise RuntimeError("trap server did not start within 10 s")
                await asyncio.sleep(0.01)
            yield
        finally:
            server.should_exit = True
            # Open SSE streams can outlast uvicorn's graceful timeout; never hang the caller on them.
            done, _ = await asyncio.wait({task}, timeout=SHUTDOWN_GRACE_S + 3)
            if not done:
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)
