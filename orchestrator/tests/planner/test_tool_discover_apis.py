import json
import pytest
from unittest.mock import patch

from orchestrator.planner.tools.discover_apis import discover_apis


@pytest.mark.asyncio
async def test_discover_apis_yields_progress_then_terminal():
    fake_result = {"requests": [{"url": "https://a.com/api", "method": "GET"}]}

    def fake_dynamic_discovery(base_url, auth, progress_callback, max_response_chars):
        progress_callback("crawl_start", "Starting crawl", {"url": base_url})
        return fake_result

    with patch("orchestrator.planner.tools.discover_apis.api_discover") as mod:
        mod.AuthConfig = lambda **kw: kw
        mod.dynamic_discovery = fake_dynamic_discovery
        mod.filter_dynamic_requests_by_domain = lambda r, d: r["dynamic"]["requests"]
        events = [e async for e in discover_apis(url="https://a.com", ctx=None)]

    assert events[-1]["is_terminal"] is True
    parsed = json.loads(events[-1]["result"])
    assert parsed["apis"][0]["url"] == "https://a.com/api"
    assert any(not e["is_terminal"] for e in events)
    progress = [e for e in events if not e["is_terminal"]][0]
    assert progress["event_type"] == "log"
