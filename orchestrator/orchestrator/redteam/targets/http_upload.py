"""HTTP upload-and-render adapter — file-upload sink target.

Used by probes that test the *upload + inline-render* pathway (CVE-2026-42138
shape: unauthenticated file upload that is later served back with active
content). The probe's `prompt` is treated as the file body. The adapter
POSTs it as multipart/form-data, extracts the render URL from the upload
response (JSONPath into JSON body, or a response header like `Location`),
GETs that URL, and returns the rendered body so the judge can decide
whether the active payload survived sanitization.

Distinct from `custom_http` (single JSON request/response) because file-upload
sinks are a different attack surface — the value being smuggled isn't a chat
turn, it's a file body that ends up rendered to other users.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, ClassVar, Optional
from urllib.parse import urljoin

import httpx
from jinja2 import Environment
from jsonpath_ng import parse as jsonpath_parse

from orchestrator.redteam.targets._base import Target

_jinja = Environment(autoescape=False)


@dataclass(frozen=True)
class HTTPUploadSpec:
    kind: str = "http_upload"
    upload_url: str = ""
    upload_method: str = "POST"
    upload_headers: tuple[tuple[str, str], ...] = ()
    upload_field_name: str = "file"
    upload_filename: str = "payload.svg"
    upload_content_type: str = "image/svg+xml"
    extra_form_fields: tuple[tuple[str, str], ...] = ()
    # Exactly one of these two MUST be specified — how to derive the render URL
    # from the upload response.
    render_url_jsonpath: Optional[str] = None
    render_url_header: Optional[str] = None
    render_method: str = "GET"
    render_headers: tuple[tuple[str, str], ...] = ()
    api_key: Optional[str] = None
    timeout_s: float = 60.0

    def __post_init__(self) -> None:
        # Coerce dict OR list-of-2-element-lists → tuple-of-tuples for header/form fields.
        for fld in ("upload_headers", "extra_form_fields", "render_headers"):
            v = getattr(self, fld)
            if isinstance(v, dict):
                object.__setattr__(self, fld, tuple(v.items()))
            elif isinstance(v, list):
                object.__setattr__(self, fld, tuple(tuple(h) for h in v))
        if self.kind != "http_upload":
            raise ValueError(f"kind must be 'http_upload', got {self.kind!r}")
        if not self.upload_url:
            raise ValueError("upload_url is required")
        # XOR — exactly one of jsonpath / header must be set.
        if bool(self.render_url_jsonpath) == bool(self.render_url_header):
            raise ValueError(
                "exactly one of render_url_jsonpath or render_url_header must be specified"
            )


class HTTPUploadTarget(Target):
    compatible_classes: ClassVar[frozenset[str]] = frozenset({"http-upload"})

    def __init__(self, spec: HTTPUploadSpec) -> None:
        self.spec = spec
        self._render_jsonpath = (
            jsonpath_parse(spec.render_url_jsonpath) if spec.render_url_jsonpath else None
        )

    def _render_template_headers(
        self, headers: tuple[tuple[str, str], ...]
    ) -> dict[str, str]:
        ctx = {"api_key": self.spec.api_key or ""}
        out: dict[str, str] = {}
        for k, v in headers:
            out[k] = _jinja.from_string(v).render(**ctx)
        return out

    def _render_form_fields(self) -> dict[str, str]:
        ctx = {"api_key": self.spec.api_key or ""}
        out: dict[str, str] = {}
        for k, v in self.spec.extra_form_fields:
            out[k] = _jinja.from_string(v).render(**ctx)
        return out

    async def send_prompt(self, prompt: str) -> tuple[str, float]:
        # The probe's prompt IS the file body — encode as bytes for upload.
        file_bytes = prompt.encode("utf-8")
        files = {
            self.spec.upload_field_name: (
                self.spec.upload_filename,
                file_bytes,
                self.spec.upload_content_type,
            )
        }
        data = self._render_form_fields()
        upload_headers = self._render_template_headers(self.spec.upload_headers)

        start = time.monotonic()
        async with httpx.AsyncClient(timeout=self.spec.timeout_s) as client:
            up = await client.request(
                method=self.spec.upload_method,
                url=self.spec.upload_url,
                headers=upload_headers,
                files=files,
                data=data,
            )
            up.raise_for_status()

            render_url = self._extract_render_url(up)
            if not render_url:
                # Upload succeeded but we couldn't locate the render URL —
                # return upload body so judge can still inspect (likely a 'pass').
                latency_ms = (time.monotonic() - start) * 1000.0
                return up.text, latency_ms

            if not render_url.startswith(("http://", "https://")):
                render_url = urljoin(self.spec.upload_url, render_url)

            render_headers = self._render_template_headers(self.spec.render_headers)
            rendered = await client.request(
                method=self.spec.render_method,
                url=render_url,
                headers=render_headers,
            )
            rendered.raise_for_status()
            latency_ms = (time.monotonic() - start) * 1000.0
            return rendered.text, latency_ms

    def _extract_render_url(self, upload_response: httpx.Response) -> str:
        if self._render_jsonpath is not None:
            try:
                data: Any = upload_response.json()
            except Exception:
                return ""
            matches = self._render_jsonpath.find(data)
            return str(matches[0].value) if matches else ""
        # Header path
        return upload_response.headers.get(self.spec.render_url_header or "", "")
