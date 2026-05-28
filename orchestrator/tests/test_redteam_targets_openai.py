"""Tests for the OpenAI-compatible chat target adapter."""

import pytest
from unittest.mock import AsyncMock, patch

from orchestrator.redteam.targets.openai_compat import OpenAICompatSpec, OpenAICompatTarget


def test_target_spec_validates_required_fields():
    with pytest.raises(ValueError, match="endpoint_url"):
        OpenAICompatSpec(endpoint_url="", model="gpt-4")
    with pytest.raises(ValueError, match="model"):
        OpenAICompatSpec(endpoint_url="https://x.com/v1/chat/completions", model="")


def test_target_spec_defaults():
    spec = OpenAICompatSpec(endpoint_url="https://api.example.com/v1/chat/completions", model="gpt-4")
    assert spec.kind == "openai_compat"
    assert spec.timeout_s == 30.0


@pytest.mark.asyncio
async def test_send_prompt_returns_assistant_text():
    spec = OpenAICompatSpec(
        endpoint_url="https://api.example.com/v1/chat/completions",
        model="gpt-4",
        api_key="sk-test",
    )
    target = OpenAICompatTarget(spec)
    fake_response = {
        "choices": [{"message": {"role": "assistant", "content": "Hello!"}}],
        "usage": {"prompt_tokens": 5, "completion_tokens": 2},
    }
    mock_client = AsyncMock()
    mock_client.post.return_value.json = lambda: fake_response
    mock_client.post.return_value.raise_for_status = lambda: None
    with patch("orchestrator.redteam.targets.openai_compat.httpx.AsyncClient") as mc:
        mc.return_value.__aenter__.return_value = mock_client
        text, latency_ms = await target.send_prompt("Say hi")
        assert text == "Hello!"
        assert latency_ms > 0


@pytest.mark.asyncio
async def test_send_prompt_falls_back_to_refusal_then_empty_string():
    spec = OpenAICompatSpec(
        endpoint_url="https://api.example.com/v1/chat/completions",
        model="gpt-4",
        api_key="sk-test",
    )
    target = OpenAICompatTarget(spec)

    # 1. content=None, refusal present → returns refusal
    refusal_response = {
        "choices": [{"message": {"role": "assistant", "content": None, "refusal": "I cannot help with that."}}],
        "usage": {"prompt_tokens": 5, "completion_tokens": 2},
    }
    mock_client_a = AsyncMock()
    mock_client_a.post.return_value.json = lambda: refusal_response
    mock_client_a.post.return_value.raise_for_status = lambda: None
    with patch("orchestrator.redteam.targets.openai_compat.httpx.AsyncClient") as mc:
        mc.return_value.__aenter__.return_value = mock_client_a
        text, _ = await target.send_prompt("anything")
        assert text == "I cannot help with that."

    # 2. content=None, no refusal → returns ""
    null_response = {
        "choices": [{"message": {"role": "assistant", "content": None}}],
        "usage": {"prompt_tokens": 5, "completion_tokens": 0},
    }
    mock_client_b = AsyncMock()
    mock_client_b.post.return_value.json = lambda: null_response
    mock_client_b.post.return_value.raise_for_status = lambda: None
    with patch("orchestrator.redteam.targets.openai_compat.httpx.AsyncClient") as mc:
        mc.return_value.__aenter__.return_value = mock_client_b
        text, _ = await target.send_prompt("anything")
        assert text == ""


def test_extra_headers_coerces_list_of_lists_to_tuple():
    """JSON serialization gives list-of-2-element-lists; spec coerces to tuple-of-tuples."""
    spec = OpenAICompatSpec(
        kind="openai_compat",
        endpoint_url="https://x",
        model="y",
        extra_headers=[["X-Foo", "bar"], ["X-Baz", "qux"]],
    )
    assert isinstance(spec.extra_headers, tuple)
    assert all(isinstance(h, tuple) for h in spec.extra_headers)
    assert ("X-Foo", "bar") in spec.extra_headers


@pytest.mark.asyncio
async def test_send_prompt_propagates_http_error():
    import httpx

    spec = OpenAICompatSpec(
        endpoint_url="https://api.example.com/v1/chat/completions",
        model="gpt-4",
        api_key="sk-test",
    )
    target = OpenAICompatTarget(spec)
    mock_client = AsyncMock()
    err = httpx.HTTPStatusError("boom", request=None, response=None)

    def _raise():
        raise err

    mock_client.post.return_value.raise_for_status = _raise
    with patch("orchestrator.redteam.targets.openai_compat.httpx.AsyncClient") as mc:
        mc.return_value.__aenter__.return_value = mock_client
        with pytest.raises(httpx.HTTPStatusError):
            await target.send_prompt("anything")
