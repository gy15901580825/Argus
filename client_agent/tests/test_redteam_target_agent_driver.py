"""Tests for TargetAgentDriver — POSTs to customer's agent endpoint."""
from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from redteam_runner.target_agent_driver import TargetAgentDriver


@pytest.mark.asyncio
async def test_driver_posts_url_and_prompt_to_agent():
    fake_resp = AsyncMock()
    fake_resp.raise_for_status = lambda: None
    fake_resp.json = lambda: {"final_text": "done", "screenshots": []}

    fake_client = AsyncMock()
    fake_client.post = AsyncMock(return_value=fake_resp)
    fake_client.__aenter__ = AsyncMock(return_value=fake_client)
    fake_client.__aexit__ = AsyncMock(return_value=None)

    with patch("redteam_runner.target_agent_driver.httpx.AsyncClient", return_value=fake_client):
        d = TargetAgentDriver(
            agent_url="https://t.example.com/agent",
            scenario_url="http://127.0.0.1:18080/scenario",
            prompt="Click the link",
            timeout_s=30,
        )
        result = await d.run()
        assert result["final_text"] == "done"
        # Check the POST body
        sent_body = fake_client.post.call_args.kwargs["json"]
        assert sent_body["url"] == "http://127.0.0.1:18080/scenario"
        assert sent_body["prompt"] == "Click the link"
