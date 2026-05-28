from __future__ import annotations
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from orchestrator.redteam.targets.http_upload import HTTPUploadSpec, HTTPUploadTarget


def _mock_resp(status: int = 200, *, json_body=None, text: str = "", headers: dict | None = None) -> MagicMock:
    r = MagicMock(spec=httpx.Response)
    r.status_code = status
    r.headers = headers or {}
    r.text = text
    if json_body is not None:
        r.json.return_value = json_body
    else:
        r.json.side_effect = ValueError("no json")
    r.raise_for_status = MagicMock()
    return r


@pytest.mark.asyncio
async def test_http_upload_jsonpath_url_then_renders():
    spec = HTTPUploadSpec(
        kind="http_upload",
        upload_url="https://app.example/upload",
        upload_headers=(("Authorization", "Bearer {{api_key}}"),),
        api_key="secret",
        upload_field_name="file",
        upload_filename="logo.svg",
        upload_content_type="image/svg+xml",
        render_url_jsonpath="$.url",
    )
    target = HTTPUploadTarget(spec)

    upload_resp = _mock_resp(json_body={"url": "https://cdn.example/u/abc.svg"})
    rendered_resp = _mock_resp(text='<svg><script>alert(1)</script></svg>')
    fake_client = AsyncMock()
    fake_client.request = AsyncMock(side_effect=[upload_resp, rendered_resp])

    with patch("orchestrator.redteam.targets.http_upload.httpx.AsyncClient") as ClientCls:
        ClientCls.return_value.__aenter__.return_value = fake_client
        body, latency_ms = await target.send_prompt("<svg>payload</svg>")

    assert body == '<svg><script>alert(1)</script></svg>'
    assert latency_ms > 0
    upload_call = fake_client.request.await_args_list[0].kwargs
    render_call = fake_client.request.await_args_list[1].kwargs
    assert upload_call["url"] == "https://app.example/upload"
    assert upload_call["headers"]["Authorization"] == "Bearer secret"
    sent_files = upload_call["files"]
    assert sent_files["file"][0] == "logo.svg"
    assert sent_files["file"][2] == "image/svg+xml"
    assert b"<svg>payload</svg>" == sent_files["file"][1]
    assert render_call["url"] == "https://cdn.example/u/abc.svg"
    assert render_call["method"] == "GET"


@pytest.mark.asyncio
async def test_http_upload_header_url_relative_resolves_against_upload_url():
    spec = HTTPUploadSpec(
        kind="http_upload",
        upload_url="https://app.example/api/upload",
        render_url_header="Location",
    )
    upload_resp = _mock_resp(status=201, headers={"Location": "/files/abc.svg"})
    rendered_resp = _mock_resp(text="<svg/>")
    fake_client = AsyncMock()
    fake_client.request = AsyncMock(side_effect=[upload_resp, rendered_resp])

    with patch("orchestrator.redteam.targets.http_upload.httpx.AsyncClient") as ClientCls:
        ClientCls.return_value.__aenter__.return_value = fake_client
        body, _ = await HTTPUploadTarget(spec).send_prompt("<svg/>")

    assert body == "<svg/>"
    render_call = fake_client.request.await_args_list[1].kwargs
    assert render_call["url"] == "https://app.example/files/abc.svg"


@pytest.mark.asyncio
async def test_http_upload_returns_upload_body_when_render_url_missing():
    spec = HTTPUploadSpec(
        kind="http_upload",
        upload_url="https://app.example/upload",
        render_url_jsonpath="$.url",
    )
    upload_resp = _mock_resp(json_body={"unrelated": "data"})
    fake_client = AsyncMock()
    fake_client.request = AsyncMock(return_value=upload_resp)
    upload_resp.text = '{"unrelated": "data"}'

    with patch("orchestrator.redteam.targets.http_upload.httpx.AsyncClient") as ClientCls:
        ClientCls.return_value.__aenter__.return_value = fake_client
        body, _ = await HTTPUploadTarget(spec).send_prompt("<svg/>")

    # Only the upload was attempted; no second call.
    assert fake_client.request.await_count == 1
    assert body == '{"unrelated": "data"}'


def test_http_upload_spec_requires_upload_url():
    with pytest.raises(ValueError, match="upload_url"):
        HTTPUploadSpec(kind="http_upload", upload_url="", render_url_jsonpath="$.x")


def test_http_upload_spec_requires_exactly_one_render_locator():
    with pytest.raises(ValueError, match="exactly one of"):
        HTTPUploadSpec(kind="http_upload", upload_url="https://x")
    with pytest.raises(ValueError, match="exactly one of"):
        HTTPUploadSpec(
            kind="http_upload",
            upload_url="https://x",
            render_url_jsonpath="$.url",
            render_url_header="Location",
        )


def test_http_upload_spec_rejects_wrong_kind():
    with pytest.raises(ValueError, match="kind must be"):
        HTTPUploadSpec(kind="wrong", upload_url="https://x", render_url_jsonpath="$.x")


def test_factory_builds_http_upload():
    from orchestrator.redteam.targets import build_target
    target = build_target({
        "kind": "http_upload",
        "upload_url": "https://x/upload",
        "render_url_jsonpath": "$.url",
    })
    assert isinstance(target, HTTPUploadTarget)


def test_compatible_classes_includes_http_upload():
    assert "http-upload" in HTTPUploadTarget.compatible_classes


def test_request_headers_coerces_list_of_lists_to_tuple():
    spec = HTTPUploadSpec(
        kind="http_upload",
        upload_url="https://x",
        render_url_jsonpath="$.url",
        upload_headers=[["X-Foo", "bar"]],
        extra_form_fields=[["album_id", "42"]],
        render_headers=[["X-Trace", "abc"]],
    )
    assert spec.upload_headers == (("X-Foo", "bar"),)
    assert spec.extra_form_fields == (("album_id", "42"),)
    assert spec.render_headers == (("X-Trace", "abc"),)
