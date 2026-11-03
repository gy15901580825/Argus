"""Custom HTTP target with a shared transport and a legacy input boundary."""

from __future__ import annotations

import uuid
import warnings
from dataclasses import dataclass
from typing import ClassVar

import httpx

from argus_transport import (
    LegacyPreparedRequest,
    LegacyResponseSelector,
    TransportContext,
    TransportEngine,
    TransportOutcome,
    TransportSpec,
    TransportSpecV2,
    V2Run,
    parse_transport_spec,
    execution_policy,
)
from argus_transport.spec_v2 import _iter_expressions
from argus.targets._base import Target, TargetBlockedError, TargetTransportError, Turn
from argus.targets._template import compile_template, render

LEGACY_TRANSPORT_FIELDS = frozenset(
    {
        "request_url",
        "request_method",
        "request_headers",
        "api_key",
        "request_body_template",
        "response_jsonpath",
        "response_latency_jsonpath",
        "session_id_jsonpath",
        "run_id_jsonpath",
        "run_log_jsonpath",
        "timeout_s",
    }
)


def _dry_run_ctx() -> dict:
    return {"prompt": "", "api_key": "", "history": [], "conversation_id": ""}


def _uses_context(value, name):
    if isinstance(value, dict):
        return value.get("context") == name or any(
            _uses_context(v, name) for v in value.values()
        )
    if isinstance(value, (tuple, list)):
        return any(_uses_context(v, name) for v in value)
    return False


def _v2_expression_uses_context(expression, name):
    if "context" in expression:
        return expression["context"] == name
    if "base64" in expression:
        return _v2_expression_uses_context(expression["base64"], name)
    if "object" in expression:
        children = expression["object"].values()
    elif "array" in expression:
        children = expression["array"]
    elif "concat" in expression:
        children = expression["concat"]
    else:
        return False
    return any(_v2_expression_uses_context(child, name) for child in children)


def _v2_uses_context(spec, name):
    return any(
        _v2_expression_uses_context(item.expression, name)
        for item in _iter_expressions(spec)
    )


@dataclass(frozen=True)
class CustomHTTPSpec:
    kind: str = "custom_http"
    transport: TransportSpec | TransportSpecV2 | dict | None = None
    request_url: str | None = None
    request_method: str | None = None
    request_headers: tuple[tuple[str, str], ...] | dict | None = None
    api_key: str | None = None
    request_body_template: str | None = None
    response_jsonpath: str | None = None
    response_latency_jsonpath: str | None = None
    session_id_jsonpath: str | None = None
    run_id_jsonpath: str | None = None
    run_log_jsonpath: str | None = None
    timeout_s: float | None = None

    def __post_init__(self) -> None:
        if self.kind != "custom_http":
            raise ValueError(f"kind must be 'custom_http', got {self.kind!r}")
        if self.transport is not None:
            if any(
                getattr(self, field) is not None for field in LEGACY_TRANSPORT_FIELDS
            ):
                raise ValueError("transport and legacy transport fields conflict")
            transport = self.transport
            if isinstance(transport, dict):
                transport = parse_transport_spec(transport)
            if not isinstance(transport, (TransportSpec, TransportSpecV2)):
                raise ValueError("transport must be a transport specification")
            uses_browser_context = (
                _v2_uses_context(transport, "scenario_url")
                if isinstance(transport, TransportSpecV2)
                else _uses_context(transport.request.body, "scenario_url")
            )
            if uses_browser_context:
                raise ValueError("scenario_url context requires a browser target")
            object.__setattr__(self, "transport", transport)
            return
        for field in ("request_url", "request_body_template", "response_jsonpath"):
            if not getattr(self, field):
                raise ValueError(f"{field} is required")
        object.__setattr__(self, "request_method", self.request_method or "POST")
        object.__setattr__(
            self, "timeout_s", 120.0 if self.timeout_s is None else self.timeout_s
        )
        headers = self.request_headers or ()
        object.__setattr__(
            self,
            "request_headers",
            (
                tuple(headers.items())
                if isinstance(headers, dict)
                else tuple(tuple(header) for header in headers)
            ),
        )


class CustomHTTPTarget(Target):
    supports_history: ClassVar[bool] = True

    compatible_classes: ClassVar[frozenset[str]] = frozenset(
        {
            "llm_chat",
            "agent_with_tools",
            "agent_with_rag",
            "http-chat",
            "tool-using",
            "rag",
        }
    )

    def __init__(self, spec: CustomHTTPSpec) -> None:
        self.spec = spec
        self._conversation_id = None
        self._session_id = None
        self._v2_run = None
        self._last_run_log = None
        self._last_transport_evidence = {}
        self.supports_history = (
            spec.transport is None or spec.transport.session.mode != "none"
        )
        if spec.transport is None:
            warnings.warn(
                "custom_http legacy fields are deprecated; migrate to transport before the next major release",
                DeprecationWarning,
                stacklevel=2,
            )
            self._body_tpl = compile_template(
                spec.request_body_template, "request_body_template", _dry_run_ctx()
            )
            self._header_tpls = [
                (
                    key,
                    f"request_headers[{key}]",
                    compile_template(value, f"request_headers[{key}]", _dry_run_ctx()),
                )
                for key, value in spec.request_headers
            ]
            self._legacy_mapping = LegacyResponseSelector(
                text_path=spec.response_jsonpath,
                latency_path=spec.response_latency_jsonpath,
                metadata_paths={
                    name: path
                    for name, path in {
                        "session_id": spec.session_id_jsonpath,
                        "run_id": spec.run_id_jsonpath,
                        "run_log": spec.run_log_jsonpath,
                    }.items()
                    if path
                },
            )
            from jsonpath_ng import parse

            for path in (
                spec.response_jsonpath,
                spec.response_latency_jsonpath,
                spec.session_id_jsonpath,
                spec.run_id_jsonpath,
                spec.run_log_jsonpath,
            ):
                if path:
                    parse(path)

    async def send_prompt(
        self, prompt: str, history: tuple[Turn, ...] = ()
    ) -> tuple[str, float]:
        self._last_run_log = None
        self._last_transport_evidence = {}
        if not history or self._conversation_id is None:
            self._conversation_id = uuid.uuid4().hex
            self._session_id = None
        if self.spec.transport is None:
            return await self._send_legacy(prompt, history)
        spec = self.spec.transport
        context = TransportContext(
            prompt=prompt,
            history=tuple({"role": t.role, "content": t.content} for t in history),
            conversation_id=self._conversation_id,
            session_id=self._session_id,
        )
        if isinstance(spec, TransportSpecV2):
            if self._v2_run is None:
                self._v2_run = V2Run(spec, policy=execution_policy(spec))
            result = await self._v2_run.attempt(context)
        else:
            result = await TransportEngine(spec, policy=execution_policy(spec)).run(context)
        metadata = result.metadata
        if result.outcome == TransportOutcome.SUCCEEDED:
            if spec.session.mode == "server_returned":
                session_id = metadata.get("session_id")
                if not session_id:
                    raise TargetTransportError(
                        "mapping_error: missing server session ID"
                    )
                self._session_id = str(session_id)
            try:
                self._set_run_log(result.as_dict()["metadata"])
            except (ValueError, TypeError):
                self._last_transport_evidence = {
                    "transport": {
                        "outcome": "target_error",
                        "http_status": result.http_status,
                        "matched_rule_id": result.matched_rule_id,
                        "reason_code": "mapping_error",
                    }
                }
                raise TargetTransportError("target_error: mapping_error") from None
            return result.response_text, result.latency_ms
        transport = {
            "outcome": result.outcome.value,
            "http_status": result.http_status,
            "matched_rule_id": result.matched_rule_id,
            "reason_code": result.reason_code.value,
        }
        if result.outcome == TransportOutcome.BLOCKED and result.matched_rule_id:
            transport["origin"] = "mapped_body_rule"
        self._last_transport_evidence = {"transport": transport}
        if result.outcome == TransportOutcome.BLOCKED:
            raise TargetBlockedError(
                "target API refused the request", transport_metadata=transport
            )
        if result.outcome == TransportOutcome.TIMED_OUT:
            raise TimeoutError("timeout: target operation exceeded its budget")
        raise TargetTransportError(f"target_error: {result.reason_code.value}")

    async def _send_legacy(self, prompt, history):
        context = {
            "prompt": prompt,
            "api_key": self.spec.api_key or "",
            "history": [{"role": t.role, "content": t.content} for t in history],
            "conversation_id": self._conversation_id,
        }
        body = render(self._body_tpl, "request_body_template", context)
        headers = {
            key: render(template, field, context)
            for key, field, template in self._header_tpls
        }
        content_type = headers.get("Content-Type", "application/json")
        if content_type.startswith("application/json") or content_type == "":
            headers["Content-Type"] = "application/json"
        request = LegacyPreparedRequest(
            self.spec.request_method,
            self.spec.request_url,
            headers,
            body,
            self.spec.timeout_s,
        )
        result = await TransportEngine.run_legacy(
            request,
            self._legacy_mapping,
            secrets=(self.spec.api_key,) if self.spec.api_key else (),
        )
        self._set_run_log(result.metadata)
        return result.response_text, result.latency_ms

    def _set_run_log(self, metadata):
        self._last_run_log = run_log_from_metadata(metadata)

    async def begin_probe(self, probe) -> None:
        self._last_run_log = None
        self._conversation_id = None
        self._session_id = None
        self._last_transport_evidence = {}

    async def collect_evidence(self):
        return dict(self._last_transport_evidence)

    def last_run_log(self):
        return self._last_run_log


def run_log_from_metadata(metadata):
    if not any(name in metadata for name in ("session_id", "run_id", "run_log")):
        return
    from argus.scenarios.models import TargetRunLog

    fields = {
        name: metadata[name] for name in ("session_id", "run_id") if name in metadata
    }
    events = metadata.get("run_log", [])
    if isinstance(events, dict):
        fields["is_dry_run"] = bool(events.get("is_dry_run", False))
        fields["events"] = events.get("events", events.get("tools", []))
    else:
        fields["events"] = events
    return TargetRunLog.model_validate(fields)
