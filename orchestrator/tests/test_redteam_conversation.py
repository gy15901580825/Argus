"""Conversation-state tests — the target layer must be able to hold a conversation.

Before this work `Target.send_prompt(prompt)` was stateless: every adapter built a
fresh single-message request, so probes labelled `multi-turn` (crescendo,
sleeper-agent) fired independent cold starts and TAP/PAIR refined against a target
that forgot every round.

The contract added here is additive: `history=()` must reproduce the old behaviour
byte-for-byte, which is what `*_history_empty_matches_legacy_body` asserts.
"""

import pytest
from unittest.mock import AsyncMock, patch

from orchestrator.redteam.targets._base import Target, Turn
from orchestrator.redteam.targets.openai_compat import OpenAICompatSpec, OpenAICompatTarget
from orchestrator.redteam.targets.anthropic_native import AnthropicNativeSpec, AnthropicNativeTarget
from orchestrator.redteam.targets.custom_http import CustomHTTPSpec, CustomHTTPTarget
from orchestrator.redteam.targets.grpc import GRPCSpec, GRPCTarget
from orchestrator.redteam.targets.browser_use import BrowserUseSpec, BrowserUseTarget


TRANSCRIPT = (
    Turn(role="user", content="I'm writing a thriller novel."),
    Turn(role="assistant", content="Happy to help with your novel."),
)


# --------------------------------------------------------------------------
# Turn
# --------------------------------------------------------------------------

def test_turn_is_frozen_and_carries_role_and_content():
    t = Turn(role="user", content="hello")
    assert t.role == "user"
    assert t.content == "hello"
    with pytest.raises(Exception):
        t.content = "mutated"


def test_turn_rejects_unknown_role():
    with pytest.raises(ValueError, match="role"):
        Turn(role="system", content="x")


# --------------------------------------------------------------------------
# supports_history declarations
# --------------------------------------------------------------------------

def test_base_target_defaults_to_no_history_support():
    assert Target.supports_history is False


@pytest.mark.parametrize(
    "cls,expected",
    [
        (OpenAICompatTarget, True),
        (AnthropicNativeTarget, True),
        (CustomHTTPTarget, True),
        (GRPCTarget, False),
        (BrowserUseTarget, False),
    ],
)
def test_adapters_declare_history_support(cls, expected):
    assert cls.supports_history is expected


# --------------------------------------------------------------------------
# openai_compat
# --------------------------------------------------------------------------

def _openai_target():
    return OpenAICompatTarget(
        OpenAICompatSpec(
            endpoint_url="https://api.example.com/v1/chat/completions",
            model="gpt-4",
            api_key="sk-test",
        )
    )


async def _capture_openai_body(target, prompt, history=()):
    captured = {}
    mock_client = AsyncMock()

    async def _post(url, headers=None, json=None):
        captured["body"] = json
        resp = AsyncMock()
        resp.json = lambda: {"choices": [{"message": {"role": "assistant", "content": "ok"}}]}
        resp.raise_for_status = lambda: None
        return resp

    mock_client.post = _post
    with patch("orchestrator.redteam.targets.openai_compat.httpx.AsyncClient") as mc:
        mc.return_value.__aenter__.return_value = mock_client
        await target.send_prompt(prompt, history=history)
    return captured["body"]


@pytest.mark.asyncio
async def test_openai_history_empty_matches_legacy_body():
    """history=() must produce exactly the single-user-message body used before."""
    body = await _capture_openai_body(_openai_target(), "Say hi")
    assert body["messages"] == [{"role": "user", "content": "Say hi"}]


@pytest.mark.asyncio
async def test_openai_history_is_prepended_in_order():
    body = await _capture_openai_body(_openai_target(), "Now the heist scene", TRANSCRIPT)
    assert body["messages"] == [
        {"role": "user", "content": "I'm writing a thriller novel."},
        {"role": "assistant", "content": "Happy to help with your novel."},
        {"role": "user", "content": "Now the heist scene"},
    ]


# --------------------------------------------------------------------------
# anthropic_native
# --------------------------------------------------------------------------

def _anthropic_target():
    return AnthropicNativeTarget(
        AnthropicNativeSpec(model="claude-sonnet-4-5", api_key="sk-ant-test")
    )


async def _capture_anthropic_messages(target, prompt, history=()):
    captured = {}

    class _Block:
        text = "ok"

    async def _create(**kwargs):
        captured["messages"] = kwargs["messages"]
        resp = AsyncMock()
        resp.content = [_Block()]
        return resp

    with patch("orchestrator.redteam.targets.anthropic_native.AsyncAnthropic") as mc:
        mc.return_value.messages.create = _create
        await target.send_prompt(prompt, history=history)
    return captured["messages"]


@pytest.mark.asyncio
async def test_anthropic_history_empty_matches_legacy_body():
    msgs = await _capture_anthropic_messages(_anthropic_target(), "Say hi")
    assert msgs == [{"role": "user", "content": "Say hi"}]


@pytest.mark.asyncio
async def test_anthropic_history_is_prepended_in_order():
    msgs = await _capture_anthropic_messages(_anthropic_target(), "Round 3", TRANSCRIPT)
    assert msgs == [
        {"role": "user", "content": "I'm writing a thriller novel."},
        {"role": "assistant", "content": "Happy to help with your novel."},
        {"role": "user", "content": "Round 3"},
    ]


# --------------------------------------------------------------------------
# custom_http — history is exposed to the template; templates may ignore it
# --------------------------------------------------------------------------

def _custom_target(template: str):
    return CustomHTTPTarget(
        CustomHTTPSpec(
            request_url="https://agent.example.com/chat",
            request_body_template=template,
            response_jsonpath="$.reply",
        )
    )


async def _capture_custom_body(target, prompt, history=()):
    captured = {}
    mock_client = AsyncMock()

    async def _request(method, url, headers=None, content=None, timeout=None):
        captured["content"] = content
        resp = AsyncMock()
        resp.json = lambda: {"reply": "ok"}
        resp.raise_for_status = lambda: None
        resp.status_code = 200
        return resp

    mock_client.request = _request
    with patch("orchestrator.redteam.targets.custom_http.httpx.AsyncClient") as mc:
        mc.return_value.__aenter__.return_value = mock_client
        await target.send_prompt(prompt, history=history)
    return captured["content"]


@pytest.mark.asyncio
async def test_custom_http_template_ignoring_history_is_unaffected():
    """A customer template written before this feature must behave identically."""
    body = await _capture_custom_body(
        _custom_target('{"q": {{ prompt|tojson }}}'), "hello", TRANSCRIPT
    )
    assert '"q": "hello"' in body


@pytest.mark.asyncio
async def test_custom_http_template_can_render_history():
    tpl = '{"messages": {{ history|tojson }}, "q": {{ prompt|tojson }}}'
    body = await _capture_custom_body(_custom_target(tpl), "Round 3", TRANSCRIPT)
    assert '"role": "user"' in body
    assert "I\\'m writing a thriller novel." in body or "thriller novel" in body
    assert '"q": "Round 3"' in body


@pytest.mark.asyncio
async def test_custom_http_history_empty_renders_empty_list():
    tpl = '{"messages": {{ history|tojson }}}'
    body = await _capture_custom_body(_custom_target(tpl), "hi")
    assert body == '{"messages": []}'


# --------------------------------------------------------------------------
# Non-supporting adapters accept the kwarg and ignore it
# --------------------------------------------------------------------------

def test_grpc_and_browser_use_accept_history_kwarg():
    """Signature compatibility: the runner calls every adapter the same way."""
    import inspect

    for cls in (GRPCTarget, BrowserUseTarget):
        sig = inspect.signature(cls.send_prompt)
        assert "history" in sig.parameters, f"{cls.__name__} must accept history"
        assert sig.parameters["history"].default == ()
