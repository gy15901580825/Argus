# tests/test_redteam_targets_custom_http.py
from __future__ import annotations
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from argus.targets.custom_http import CustomHTTPSpec, CustomHTTPTarget


@pytest.mark.asyncio
async def test_custom_http_renders_template_and_extracts_response():
    spec = CustomHTTPSpec(
        kind="custom_http",
        request_url="https://agent.example/chat",
        request_method="POST",
        request_headers=(("Authorization", "Bearer {{api_key}}"),),
        api_key="secret",
        request_body_template='{"input": {{prompt|tojson}}, "session": "abc"}',
        response_jsonpath="$.choices[0].message.content",
    )
    target = CustomHTTPTarget(spec)

    mock_resp = MagicMock(status_code=200)
    mock_resp.json.return_value = {"choices": [{"message": {"content": "agent reply"}}]}
    mock_resp.raise_for_status = MagicMock()

    fake_client = AsyncMock()
    fake_client.request = AsyncMock(return_value=mock_resp)
    with patch("argus.targets.custom_http.httpx.AsyncClient") as ClientCls:
        ClientCls.return_value.__aenter__.return_value = fake_client
        text, latency_ms = await target.send_prompt('he said "hi"')

    assert text == "agent reply"
    assert latency_ms > 0
    sent = fake_client.request.await_args.kwargs
    assert sent["method"] == "POST"
    assert sent["url"] == "https://agent.example/chat"
    assert sent["headers"]["Authorization"] == "Bearer secret"
    # The {{prompt|tojson}} step JSON-escapes the quotes
    assert '"he said \\"hi\\""' in sent["content"]


@pytest.mark.asyncio
async def test_custom_http_jsonpath_miss_returns_empty_string():
    spec = CustomHTTPSpec(
        kind="custom_http",
        request_url="https://x",
        request_body_template="{}",
        response_jsonpath="$.nonexistent.path",
    )
    mock_resp = MagicMock(status_code=200)
    mock_resp.json.return_value = {"unrelated": "data"}
    mock_resp.raise_for_status = MagicMock()
    fake_client = AsyncMock()
    fake_client.request = AsyncMock(return_value=mock_resp)
    with patch("argus.targets.custom_http.httpx.AsyncClient") as ClientCls:
        ClientCls.return_value.__aenter__.return_value = fake_client
        text, _ = await CustomHTTPTarget(spec).send_prompt("hi")
    assert text == ""


def test_custom_http_spec_requires_request_url_and_template():
    with pytest.raises(ValueError, match="request_url"):
        CustomHTTPSpec(kind="custom_http", request_url="", request_body_template="{}", response_jsonpath="$.x")
    with pytest.raises(ValueError, match="request_body_template"):
        CustomHTTPSpec(kind="custom_http", request_url="https://x", request_body_template="", response_jsonpath="$.x")
    with pytest.raises(ValueError, match="response_jsonpath"):
        CustomHTTPSpec(kind="custom_http", request_url="https://x", request_body_template="{}", response_jsonpath="")


def test_custom_http_spec_rejects_wrong_kind():
    with pytest.raises(ValueError, match="kind must be"):
        CustomHTTPSpec(kind="wrong", request_url="x", request_body_template="{}", response_jsonpath="$.x")


def test_request_headers_coerces_list_of_lists_to_tuple():
    """JSON serialization gives list-of-2-element-lists; spec coerces to tuple-of-tuples."""
    spec = CustomHTTPSpec(
        kind="custom_http",
        request_url="https://x",
        request_body_template="{}",
        response_jsonpath="$.x",
        request_headers=[["X-Foo", "bar"], ["X-Baz", "qux"]],
    )
    assert isinstance(spec.request_headers, tuple)
    assert all(isinstance(h, tuple) for h in spec.request_headers)
    assert ("X-Foo", "bar") in spec.request_headers


def test_factory_builds_custom_http():
    from argus.targets import build_target
    target = build_target({
        "kind": "custom_http",
        "request_url": "https://x",
        "request_body_template": "{}",
        "response_jsonpath": "$.x",
    })
    assert isinstance(target, CustomHTTPTarget)


def _conv_target(template='{"q": {{prompt|tojson}}, "c": "{{conversation_id}}"}', headers=()):
    return CustomHTTPTarget(CustomHTTPSpec(
        kind="custom_http",
        request_url="https://agent.example/chat",
        request_headers=headers,
        request_body_template=template,
        response_jsonpath="$.r",
    ))


async def _send(target, prompt="hi", history=()):
    """Send one prompt through a mocked client; return (body, headers) as sent."""
    mock_resp = MagicMock(status_code=200)
    mock_resp.json.return_value = {"r": "ok"}
    mock_resp.raise_for_status = MagicMock()
    fake_client = AsyncMock()
    fake_client.request = AsyncMock(return_value=mock_resp)
    with patch("argus.targets.custom_http.httpx.AsyncClient") as ClientCls:
        ClientCls.return_value.__aenter__.return_value = fake_client
        await target.send_prompt(prompt, history)
    kw = fake_client.request.call_args.kwargs
    return kw["content"], kw["headers"]


@pytest.mark.asyncio
async def test_conversation_id_is_fresh_per_conversation():
    import json
    import re
    target = _conv_target()
    first = json.loads((await _send(target))[0])["c"]
    second = json.loads((await _send(target))[0])["c"]
    assert re.fullmatch(r"[0-9a-f]{32}", first)
    assert re.fullmatch(r"[0-9a-f]{32}", second)
    assert first != second


@pytest.mark.asyncio
async def test_conversation_id_is_stable_within_a_conversation():
    import json
    from argus.targets._base import Turn
    target = _conv_target()
    first = json.loads((await _send(target))[0])["c"]
    later = json.loads((await _send(
        target, "next", (Turn("user", "a"), Turn("assistant", "b"))
    ))[0])["c"]
    assert first == later


@pytest.mark.asyncio
async def test_conversation_id_renders_in_headers():
    import json
    target = _conv_target(headers=(("X-Conv", "{{conversation_id}}"),))
    body, headers = await _send(target)
    cid = json.loads(body)["c"]
    assert cid and headers["X-Conv"] == cid


@pytest.mark.asyncio
async def test_conversation_id_minted_when_history_arrives_first():
    import json
    import re
    from argus.targets._base import Turn
    target = _conv_target()
    body, _ = await _send(target, "x", (Turn("user", "a"), Turn("assistant", "b")))
    assert re.fullmatch(r"[0-9a-f]{32}", json.loads(body)["c"])


@pytest.mark.asyncio
async def test_template_without_conversation_id_renders_unchanged():
    body, _ = await _send(_conv_target('{"input": {{prompt|tojson}}}'))
    assert body == '{"input": "hi"}'
