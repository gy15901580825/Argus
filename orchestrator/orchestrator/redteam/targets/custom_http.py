"""Custom HTTP adapter — Jinja2 template + JSONPath response extraction.

Customer agents commonly expose their own HTTP shape rather than OpenAI-compat.
This adapter renders a JSON body template (with `{{prompt}}` and `{{api_key}}`
substitutions; `prompt|tojson` escapes any embedded quotes), POSTs (or other
method) to the configured URL, and extracts the response via a JSONPath query.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import ClassVar, Optional

import httpx
from jinja2 import Environment
from jsonpath_ng import parse as jsonpath_parse

from orchestrator.redteam.targets._base import Target, Turn

_jinja = Environment(autoescape=False)


@dataclass(frozen=True)
class CustomHTTPSpec:
    kind: str = "custom_http"
    request_url: str = ""
    request_method: str = "POST"
    request_headers: tuple[tuple[str, str], ...] = ()
    api_key: Optional[str] = None
    request_body_template: str = ""
    response_jsonpath: str = ""
    response_latency_jsonpath: Optional[str] = None
    timeout_s: float = 60.0

    def __post_init__(self) -> None:
        # Coerce dict OR list-of-2-element-lists → tuple-of-tuples
        # (model_dump() emits list-of-lists for tuple fields).
        hdrs = self.request_headers
        if isinstance(hdrs, dict):
            object.__setattr__(self, "request_headers", tuple(hdrs.items()))
        elif isinstance(hdrs, list):
            object.__setattr__(self, "request_headers", tuple(tuple(h) for h in hdrs))
        # Validate kind first.
        if self.kind != "custom_http":
            raise ValueError(f"kind must be 'custom_http', got {self.kind!r}")
        if not self.request_url:
            raise ValueError("request_url is required")
        if not self.request_body_template:
            raise ValueError("request_body_template is required")
        if not self.response_jsonpath:
            raise ValueError("response_jsonpath is required")


class CustomHTTPTarget(Target):
    supports_history: ClassVar[bool] = True

    # Plan 4 names + Plan 2 legacy aliases ("http-chat" / "tool-using" / "rag").
    compatible_classes: ClassVar[frozenset[str]] = frozenset({
        "llm_chat", "agent_with_tools", "agent_with_rag",
        "http-chat", "tool-using", "rag",
    })

    def __init__(self, spec: CustomHTTPSpec) -> None:
        self.spec = spec
        self._body_tpl = _jinja.from_string(spec.request_body_template)
        self._jsonpath = jsonpath_parse(spec.response_jsonpath)
        self._latency_jsonpath = (
            jsonpath_parse(spec.response_latency_jsonpath) if spec.response_latency_jsonpath else None
        )

    async def send_prompt(
        self, prompt: str, history: tuple[Turn, ...] = ()
    ) -> tuple[str, float]:
        # `history` is offered to the template as a list of {role, content} dicts.
        # Templates written before conversation support simply never reference it
        # and render exactly as they did before.
        ctx = {
            "prompt": prompt,
            "api_key": self.spec.api_key or "",
            "history": [{"role": t.role, "content": t.content} for t in history],
        }
        body = self._body_tpl.render(**ctx)

        # Render headers (api_key substitution allowed in header values too).
        headers = {}
        for k, v in self.spec.request_headers:
            headers[k] = _jinja.from_string(v).render(**ctx)

        # Set Content-Type to application/json if not already specified.
        ct = headers.get("Content-Type", "application/json")
        is_json = ct.startswith("application/json") or ct == ""
        if is_json:
            headers["Content-Type"] = "application/json"

        start = time.monotonic()
        async with httpx.AsyncClient(timeout=self.spec.timeout_s) as client:
            resp = await client.request(
                method=self.spec.request_method,
                url=self.spec.request_url,
                headers=headers,
                content=body,
            )
            resp.raise_for_status()
            data = resp.json() if is_json else {"_raw": resp.text}
        wall_latency_ms = (time.monotonic() - start) * 1000.0

        matches = self._jsonpath.find(data)
        text = str(matches[0].value) if matches else ""

        latency_ms = wall_latency_ms
        if self._latency_jsonpath is not None:
            latency_matches = self._latency_jsonpath.find(data)
            if latency_matches and isinstance(latency_matches[0].value, (int, float)):
                latency_ms = float(latency_matches[0].value)

        return text, latency_ms
