import json
import pytest
from unittest.mock import patch, AsyncMock

from orchestrator.planner.tools.fetch_page import fetch_page


@pytest.mark.asyncio
async def test_fetch_page_returns_terminal_content():
    class _ToolResult:
        content = [type("T", (), {"text": "hello world"})()]

    class _FakeToolset:
        def __init__(self):
            self.call_tool = AsyncMock(return_value=_ToolResult())

    with patch("orchestrator.planner.tools.fetch_page._get_mcp_toolset",
               return_value=_FakeToolset()):
        events = [e async for e in fetch_page(url="https://x.com", ctx=None)]
    assert events[-1]["is_terminal"] is True
    out = json.loads(events[-1]["result"])
    assert out["content"] == "hello world"
