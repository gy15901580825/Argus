"""fetch_page tool — thin wrapper around the MCP web fetch service."""

from __future__ import annotations

import json
import os
from typing import Any, AsyncGenerator


class _WebFetchClient:
    """Opens a fresh SSE session per call against the internal web fetch MCP."""

    def __init__(self, url: str):
        self._url = url

    async def call_tool(self, tool_name: str, arguments: dict) -> Any:
        from mcp import ClientSession
        from mcp.client.sse import sse_client

        async with sse_client(self._url) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                return await session.call_tool(tool_name, arguments)


def _get_mcp_toolset():
    """Lazy construct so tests can patch this easily."""
    url = os.getenv("MCP_WEB_FETCH_URL") or (
        "http://argus-testing-web-fetch-service.default.svc.cluster.local:8001/sse"
    )
    return _WebFetchClient(url)


async def fetch_page(*, url: str, ctx: Any) -> AsyncGenerator[dict, None]:
    try:
        toolset = _get_mcp_toolset()
        result = await toolset.call_tool("fetch_internal_page", {"url": url})
    except Exception as e:
        yield {"is_terminal": True, "result": json.dumps({"error": str(e), "content": ""})}
        return

    text = ""
    if hasattr(result, "content"):
        for block in result.content:
            t = getattr(block, "text", None)
            if t:
                text += t
    yield {"is_terminal": True, "result": json.dumps({"content": text[:20000]})}
