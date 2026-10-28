"""Hostile MCP fixture servers for the scan-mcp client tests. They make no outbound requests.

`build(name)` returns an SDK server for the HTTP harness; `python servers.py <name>` serves it over stdio.
"""
from __future__ import annotations

import json
import os
import sys
import time
from typing import Any

SERVER_VERSION = "1.0.0"
HUGE_BYTES = 50 * 1024 * 1024
MANY_TOOLS = 5000
FLOOD = 5000
STDERR_NOISE = 6000
READY_MARK = "basic-ready"


def _schema(**props: Any) -> dict:
    return {"type": "object", "properties": props}


def _tools(name: str) -> list[dict]:
    if name == "basic":
        return [
            {"name": "read_env", "description": "Lists the names of the server's environment variables.",
             "inputSchema": _schema(),
             # The result's structuredContent breaks this schema on purpose.
             "outputSchema": {"type": "object", "properties": {"count": {"type": "integer"}}, "required": ["count"]},
             "annotations": {"readOnlyHint": True}},
            {"name": "echo", "description": "Echoes its text argument.",
             "inputSchema": _schema(text={"type": "string"})},
        ]
    if name == "hang_tool":
        return [{"name": "hang", "description": "Never returns.", "inputSchema": _schema(),
                 "annotations": {"readOnlyHint": True}}]
    if name == "huge_result":
        return [{"name": "huge", "description": "Returns 50 MB of text.", "inputSchema": _schema(),
                 "annotations": {"readOnlyHint": True}}]
    if name == "many_tools":
        return [{"name": f"tool_{i}", "description": "One of many.", "inputSchema": _schema()} for i in range(MANY_TOOLS)]
    if name == "notify_flood":
        return [{"name": "flood", "description": "Sends notifications before answering.", "inputSchema": _schema(),
                 "annotations": {"readOnlyHint": True}}]
    raise ValueError(f"unknown fixture server: {name}")


def build(name: str) -> Any:
    import anyio
    import mcp_types
    from mcp.server import NotificationOptions, Server

    class _Server(Server):
        def create_initialization_options(self, notification_options=None, *args: Any, **kwargs: Any) -> Any:
            return super().create_initialization_options(
                notification_options or NotificationOptions(tools_changed=True), *args, **kwargs)

    tools = [] if name == "many_pages" else [mcp_types.Tool.model_validate(t) for t in _tools(name)]

    async def on_list_tools(ctx: Any, params: Any) -> Any:
        if name == "many_pages":
            # Every page points at another one.
            n = int(params.cursor) if params is not None and params.cursor else 0
            page = [mcp_types.Tool(name=f"page_tool_{n}", input_schema=_schema())]
            return mcp_types.ListToolsResult(tools=page, next_cursor=str(n + 1))
        return mcp_types.ListToolsResult(tools=tools)

    def text(value: str, **kw: Any) -> Any:
        return mcp_types.CallToolResult(content=[mcp_types.TextContent(type="text", text=value)], **kw)

    async def on_call_tool(ctx: Any, params: Any) -> Any:
        args = dict(params.arguments or {})
        if params.name == "read_env":
            return text(json.dumps(sorted(os.environ)), structured_content={"count": "many"})
        if params.name == "echo":
            # On the request's own stream, so the client sees it before the result.
            await ctx.session.send_notification(mcp_types.ToolListChangedNotification(),
                                                related_request_id=ctx.request_id)
            return text(str(args.get("text", "")))
        if params.name == "hang":
            await anyio.sleep_forever()
        if params.name == "huge":
            return text("A" * HUGE_BYTES)
        if params.name == "flood":
            for i in range(FLOOD):
                await ctx.session.send_notification(
                    mcp_types.LoggingMessageNotification(
                        params=mcp_types.LoggingMessageNotificationParams(level="info", data=f"flood {i}")),
                    related_request_id=ctx.request_id)
            return text("done")
        return text(f"unknown tool {params.name}", is_error=True)

    return _Server(f"argus-fixture-{name}", version=SERVER_VERSION, on_list_tools=on_list_tools,
                   on_call_tool=on_call_tool)


def _slow_init() -> None:
    # Not an MCP server: it never reads stdin or answers, and keeps a child in its process group.
    import subprocess

    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    sys.stderr.write(f"pid={os.getpid()} child={child.pid}\n")
    sys.stderr.flush()
    while True:
        time.sleep(1)


async def _serve_stdio(name: str) -> None:
    from mcp.server.stdio import stdio_server

    server = build(name)
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


def main(name: str) -> None:
    if name == "slow_init":
        _slow_init()
        return
    if name == "basic":
        sys.stderr.write("x" * STDERR_NOISE + f"\n{READY_MARK}\n")
        sys.stderr.flush()
    import anyio

    anyio.run(_serve_stdio, name)


if __name__ == "__main__":
    main(sys.argv[1])
