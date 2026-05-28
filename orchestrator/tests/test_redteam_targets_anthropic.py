"""Tests for the Anthropic native messages target adapter."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from orchestrator.redteam.targets import build_target
from orchestrator.redteam.targets.anthropic_native import AnthropicNativeSpec, AnthropicNativeTarget


@pytest.mark.asyncio
async def test_anthropic_native_calls_messages_create():
    spec = AnthropicNativeSpec(kind="anthropic_native", model="claude-haiku-4-5-20251001", api_key="k")
    target = AnthropicNativeTarget(spec)
    fake_client = MagicMock()
    fake_client.messages.create = AsyncMock(return_value=MagicMock(
        content=[MagicMock(text="hello world")]
    ))
    with patch("orchestrator.redteam.targets.anthropic_native.AsyncAnthropic", return_value=fake_client):
        text, latency_ms = await target.send_prompt("hi")
    assert text == "hello world"
    assert latency_ms > 0
    fake_client.messages.create.assert_awaited_once()
    kwargs = fake_client.messages.create.await_args.kwargs
    assert kwargs["model"] == "claude-haiku-4-5-20251001"
    assert kwargs["messages"] == [{"role": "user", "content": "hi"}]


def test_factory_builds_anthropic_native():
    target = build_target({"kind": "anthropic_native", "model": "claude-haiku-4-5-20251001", "api_key": "k"})
    assert isinstance(target, AnthropicNativeTarget)


def test_anthropic_spec_requires_model_and_key():
    with pytest.raises(ValueError, match="model"):
        AnthropicNativeSpec(kind="anthropic_native", model="", api_key="k")
    with pytest.raises(ValueError, match="api_key"):
        AnthropicNativeSpec(kind="anthropic_native", model="x", api_key="")


def test_anthropic_spec_rejects_wrong_kind():
    """Per T1 review-fix pattern: spec validates kind matches its class."""
    with pytest.raises(ValueError, match="kind must be"):
        AnthropicNativeSpec(kind="wrong", model="x", api_key="k")
