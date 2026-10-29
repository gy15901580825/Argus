"""Spec templates (custom_http, http_upload) render in a Jinja sandbox.

A template that reaches for unsafe attributes must fail as a spec error naming
the field; every template feature the target-spec cookbook documents must keep
working.
"""
from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from argus.targets import build_target
from argus.targets._base import Turn
from argus.targets.custom_http import CustomHTTPSpec, CustomHTTPTarget
from argus.targets.http_upload import HTTPUploadSpec, HTTPUploadTarget

# Plain Jinja renders this (a dict of module globals); the sandbox must refuse it.
UNSAFE = "{{ cycler.__init__.__globals__ }}"


def _custom(body='{"q": {{ prompt|tojson }}}', headers=(), api_key=None):
    return CustomHTTPTarget(CustomHTTPSpec(
        request_url="https://agent.example/chat",
        request_headers=headers,
        api_key=api_key,
        request_body_template=body,
        response_jsonpath="$.r",
    ))


async def _send_custom(target, prompt="hi", history=()):
    """Send through a mocked client; return (fake_client, body, headers)."""
    resp = MagicMock(status_code=200)
    resp.json.return_value = {"r": "ok"}
    resp.raise_for_status = MagicMock()
    client = AsyncMock()
    client.request = AsyncMock(return_value=resp)
    with patch("argus.targets.custom_http.httpx.AsyncClient") as cls:
        cls.return_value.__aenter__.return_value = client
        await target.send_prompt(prompt, history)
    kw = client.request.await_args.kwargs
    return client, kw["content"], kw["headers"]


# --------------------------------------------------------------------------
# custom_http: unsafe templates are spec errors, never executed
# --------------------------------------------------------------------------

def test_unsafe_body_template_is_a_spec_error_naming_the_field():
    with pytest.raises(ValueError, match="request_body_template"):
        _custom(body=UNSAFE)


def test_unsafe_dunder_class_access_is_refused():
    with pytest.raises(ValueError, match="request_body_template"):
        _custom(body="{{ prompt.__class__.__mro__ }}")


def test_unsafe_header_template_names_the_header():
    with pytest.raises(ValueError, match=r"request_headers\[X-Evil\]"):
        _custom(headers=(("X-Evil", UNSAFE),))


def test_template_syntax_error_is_a_spec_error_naming_the_field():
    with pytest.raises(ValueError, match="request_body_template"):
        _custom(body="{{ prompt ")


def test_build_target_rejects_unsafe_template():
    with pytest.raises(ValueError, match="request_body_template"):
        build_target({
            "kind": "custom_http",
            "request_url": "https://x",
            "request_body_template": UNSAFE,
            "response_jsonpath": "$.r",
        })


@pytest.mark.asyncio
async def test_unsafe_access_behind_a_history_branch_fails_at_send_without_sending():
    # The construction-time check renders with empty history, so this branch is
    # only reached at send time; the sandbox must still refuse it there.
    target = _custom(body="{% if history %}" + UNSAFE + "{% endif %}{}")
    client = AsyncMock()
    with patch("argus.targets.custom_http.httpx.AsyncClient") as cls:
        cls.return_value.__aenter__.return_value = client
        with pytest.raises(ValueError, match="request_body_template"):
            await target.send_prompt("x", (Turn("user", "a"), Turn("assistant", "b")))
    client.request.assert_not_called()


# --------------------------------------------------------------------------
# custom_http: documented template features still work in the sandbox
# --------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_plain_prompt_substitution():
    _, body, _ = await _send_custom(_custom(body="say {{prompt}}"), prompt="hello")
    assert body == "say hello"


@pytest.mark.asyncio
async def test_prompt_tojson_escapes_quotes():
    _, body, _ = await _send_custom(_custom(body='{"q": {{ prompt | tojson }}}'), prompt='he said "hi"')
    assert json.loads(body) == {"q": 'he said "hi"'}


@pytest.mark.asyncio
async def test_history_loop():
    tpl = (
        '{"messages": ['
        '{% for t in history %}{"role": {{ t.role|tojson }}, "content": {{ t.content|tojson }}},{% endfor %}'
        '{"role": "user", "content": {{ prompt|tojson }}}]}'
    )
    _, body, _ = await _send_custom(
        _custom(body=tpl), prompt="third", history=(Turn("user", "first"), Turn("assistant", "second")),
    )
    assert json.loads(body)["messages"] == [
        {"role": "user", "content": "first"},
        {"role": "assistant", "content": "second"},
        {"role": "user", "content": "third"},
    ]


@pytest.mark.asyncio
async def test_api_key_in_header_and_body():
    target = _custom(
        body='{"k": "{{api_key}}"}', headers=(("Authorization", "Bearer {{api_key}}"),), api_key="s3cret",
    )
    _, body, headers = await _send_custom(target)
    assert headers["Authorization"] == "Bearer s3cret"
    assert json.loads(body) == {"k": "s3cret"}


@pytest.mark.asyncio
async def test_conversation_id():
    _, body, headers = await _send_custom(
        _custom(body='{"c": "{{conversation_id}}"}', headers=(("X-Conv", "{{conversation_id}}"),)),
    )
    cid = json.loads(body)["c"]
    assert len(cid) == 32 and headers["X-Conv"] == cid


@pytest.mark.asyncio
async def test_env_substitution_from_spec_file(monkeypatch, tmp_path):
    from argus.cli.target_loader import load_target_spec

    monkeypatch.setenv("ARGUS_TEST_AGENT_TOKEN", "from-env")
    path = tmp_path / "t.json"
    path.write_text(json.dumps({
        "kind": "custom_http",
        "request_url": "https://agent.example/chat",
        "api_key": "${ARGUS_TEST_AGENT_TOKEN}",
        "request_headers": {"Authorization": "Bearer {{api_key}}"},
        "request_body_template": '{"q": {{prompt|tojson}}, "tenant": "${ARGUS_TEST_AGENT_TOKEN}"}',
        "response_jsonpath": "$.r",
    }))
    target = build_target(load_target_spec(str(path)))
    _, body, headers = await _send_custom(target, prompt="hi")
    assert headers["Authorization"] == "Bearer from-env"
    assert json.loads(body) == {"q": "hi", "tenant": "from-env"}


# --------------------------------------------------------------------------
# http_upload: header and form-field templates
# --------------------------------------------------------------------------

def _upload_spec(**kw):
    base = dict(upload_url="https://app.example/upload", render_url_jsonpath="$.url", api_key="s3cret")
    base.update(kw)
    return HTTPUploadSpec(**base)


@pytest.mark.parametrize("field", ["upload_headers", "render_headers", "extra_form_fields"])
def test_upload_unsafe_template_is_a_spec_error_naming_the_field(field):
    with pytest.raises(ValueError, match=rf"{field}\[X-Evil\]"):
        HTTPUploadTarget(_upload_spec(**{field: (("X-Evil", UNSAFE),)}))


@pytest.mark.asyncio
async def test_upload_api_key_renders_in_headers_and_form_fields():
    target = HTTPUploadTarget(_upload_spec(
        upload_headers=(("Authorization", "Bearer {{api_key}}"),),
        render_headers=(("Authorization", "Bearer {{ api_key }}"),),
        extra_form_fields=(("token", "{{api_key}}"),),
    ))
    up = MagicMock(spec=httpx.Response)
    up.json.return_value = {"url": "https://cdn.example/a.svg"}
    up.raise_for_status = MagicMock()
    rendered = MagicMock(spec=httpx.Response)
    rendered.text = "<svg/>"
    rendered.raise_for_status = MagicMock()
    client = AsyncMock()
    client.request = AsyncMock(side_effect=[up, rendered])
    with patch("argus.targets.http_upload.httpx.AsyncClient") as cls:
        cls.return_value.__aenter__.return_value = client
        await target.send_prompt("<svg/>")
    upload_call, render_call = (c.kwargs for c in client.request.await_args_list)
    assert upload_call["headers"]["Authorization"] == "Bearer s3cret"
    assert upload_call["data"] == {"token": "s3cret"}
    assert render_call["headers"]["Authorization"] == "Bearer s3cret"


# --------------------------------------------------------------------------
# server mode: an unsafe template is a 422 before any run starts
# --------------------------------------------------------------------------

def test_preflight_returns_422_for_unsafe_template(monkeypatch):
    from fastapi.testclient import TestClient
    from argus.server import app

    monkeypatch.delenv("ARGUS_SERVER_TOKEN", raising=False)
    resp = TestClient(app).post("/redteam/run/preflight", json={
        "target": {
            "kind": "custom_http",
            "request_url": "https://x",
            "request_body_template": UNSAFE,
            "response_jsonpath": "$.r",
        },
        "probe_ids": [],
    })
    assert resp.status_code == 422
    assert "request_body_template" in resp.json()["detail"]
