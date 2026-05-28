import pytest
from unittest.mock import AsyncMock, patch

from orchestrator.planner.memory import load_core_history


@pytest.mark.asyncio
async def test_load_core_history_returns_compact_pairs():
    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.json = lambda: {
        "messages": [
            {"role": "user", "content": "Test https://a.com"},
            {"role": "assistant", "content": "Tests done. Found 3 bugs."},
            {"role": "user", "content": "Now test https://b.com"},
            {"role": "assistant", "content": "Tests done. No bugs."},
        ]
    }
    with patch("orchestrator.planner.memory.httpx.AsyncClient") as mock_client:
        instance = mock_client.return_value.__aenter__.return_value
        instance.get.return_value = mock_response
        out = await load_core_history(
            session_id="s1", user_id="u1", limit=5,
            api_service_base_url="http://api:8881",
            service_secret="secret",
        )
    assert len(out) == 4
    assert out[0]["role"] == "user"
    assert out[0]["content"] == "Test https://a.com"
    assert out[-1]["role"] == "assistant"


@pytest.mark.asyncio
async def test_load_core_history_truncates_content_over_500_chars():
    big = "x" * 1000
    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.json = lambda: {"messages": [{"role": "assistant", "content": big}]}
    with patch("orchestrator.planner.memory.httpx.AsyncClient") as mock_client:
        instance = mock_client.return_value.__aenter__.return_value
        instance.get.return_value = mock_response
        out = await load_core_history(
            session_id="s1", user_id="u1", limit=5,
            api_service_base_url="http://api:8881",
            service_secret="secret",
        )
    assert len(out[0]["content"]) == 500


@pytest.mark.asyncio
async def test_load_core_history_returns_empty_on_api_failure():
    with patch("orchestrator.planner.memory.httpx.AsyncClient") as mock_client:
        instance = mock_client.return_value.__aenter__.return_value
        instance.get.side_effect = Exception("boom")
        out = await load_core_history(
            session_id="s1", user_id="u1", limit=5,
            api_service_base_url="http://api:8881",
            service_secret="secret",
        )
    assert out == []
