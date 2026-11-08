from __future__ import annotations

import asyncio
import copy
import json
import time
from dataclasses import dataclass, field, replace
from typing import Any
from urllib.parse import quote, urlsplit

import httpx
from jsonpath_ng import parse

from .models import (
    JSON_VALUE_TYPES,
    RequestSpec,
    PollSpec,
    SafeReasonCode,
    SyncSpec,
    TransportContext,
    TransportOutcome,
    TransportResult,
    TransportSpec,
)
from .security import ExecutionPolicy, Redactor, resolve_secret, redacted_transport_logs

_MISSING = object()
_OMIT = object()


def select(body, path, legacy=False):
    matches = parse(path).find(body)
    if not matches:
        return _MISSING
    if len(matches) != 1 and not legacy:
        raise ValueError("Ambiguous response path")
    return matches[0].value


def matches_predicate(body, predicate):
    if "all" in predicate:
        return all(matches_predicate(body, p) for p in predicate["all"])
    if "any" in predicate:
        return any(matches_predicate(body, p) for p in predicate["any"])
    if "not" in predicate:
        return not matches_predicate(body, predicate["not"])
    value = select(body, predicate["path"])
    if "exists" in predicate:
        return (value is not _MISSING) == predicate["exists"]
    if value is _MISSING:
        return False
    if "type" in predicate:
        return type(value) in JSON_VALUE_TYPES[predicate["type"]]
    if "equals" in predicate:
        return type(value) == type(predicate["equals"]) and value == predicate["equals"]
    return any(
        type(value) == type(item) and value == item for item in predicate["one_of"]
    )


def outcome_match(outcome, status, body):
    if (
        status in {401, 407, 404, 405, 408, 422, 429}
        or status >= 500
        or (not 200 <= status < 300 and status not in {400, 403})
    ):
        return TransportOutcome.TARGET_ERROR, None, SafeReasonCode.HTTP_ERROR, []
    rules = [
        r
        for r in outcome.rules
        if status in r.http_status and matches_predicate(body, r.when)
    ]
    if rules:
        rule = rules[0]
        if status in {400, 403} and rule.outcome != TransportOutcome.BLOCKED:
            return (
                TransportOutcome.TARGET_ERROR,
                None,
                SafeReasonCode.HTTP_ERROR,
                [r.id for r in rules],
            )
        reason = {
            TransportOutcome.SUCCEEDED: SafeReasonCode.OK,
            TransportOutcome.BLOCKED: SafeReasonCode.TARGET_REFUSAL,
            TransportOutcome.TARGET_ERROR: SafeReasonCode.TARGET_ERROR,
        }[rule.outcome]
        return rule.outcome, rule.id, reason, [r.id for r in rules]
    if status in {400, 403}:
        return TransportOutcome.TARGET_ERROR, None, SafeReasonCode.HTTP_ERROR, []
    if outcome.kind == "http_only":
        return TransportOutcome.SUCCEEDED, None, SafeReasonCode.OK, []
    return TransportOutcome.TARGET_ERROR, None, SafeReasonCode.UNKNOWN_STATUS, []


def evaluate_response(spec, status, body, *, latency_ms=0, redactor=None):
    redactor = redactor or Redactor()
    diagnostics = {
        "http_status": status,
        "response_paths": {},
        "top_keys": [],
        "outcome_matches": [],
    }
    if isinstance(body, dict):
        diagnostics["top_keys"] = [redactor.clean(str(k))[:64] for k in list(body)[:32]]
    try:
        outcome, rid, reason, ids = outcome_match(spec.outcome, status, body)
        diagnostics.update(outcome_matches=ids, outcome_selected=rid)
        if outcome != TransportOutcome.SUCCEEDED:
            if outcome == TransportOutcome.BLOCKED and rid:
                diagnostics["origin"] = "mapped_body_rule"
            return TransportResult(
                outcome,
                None,
                latency_ms,
                status,
                rid,
                reason,
                {},
                redactor.clean(diagnostics),
            )
        if spec.response.format == "text":
            answer = body
        else:
            answer = _MISSING
            for path in spec.response.text.paths:
                candidate = select(body, path)
                diagnostics["response_paths"][path] = (
                    "NOT_FOUND" if candidate is _MISSING else type(candidate).__name__
                )
                if candidate is not _MISSING:
                    answer = candidate
                    break
        if answer is _MISSING or answer is None or answer in ([], {}):
            raise ValueError("Missing or empty answer")
        if isinstance(answer, str):
            if not answer.strip():
                raise ValueError("Empty answer")
        elif spec.response.text.cast == "string_or_json":
            answer = json.dumps(answer, ensure_ascii=False, allow_nan=False)
        else:
            raise ValueError("Incorrect answer type")
        metadata = {}
        for name, selector in spec.response.metadata.items():
            value = select(body, selector.path)
            if value is _MISSING:
                if selector.required:
                    raise ValueError("Required metadata missing")
            else:
                metadata[name] = value
        if spec.session.mode == "server_returned":
            sid = select(body, spec.session.id_path)
            if not isinstance(sid, (str, int)) or isinstance(sid, bool) or not str(sid):
                raise ValueError("Session ID missing")
            metadata["session_id"] = str(sid)
        return TransportResult(
            outcome,
            redactor.clean(answer),
            latency_ms,
            status,
            rid,
            reason,
            redactor.clean(metadata),
            redactor.clean(diagnostics),
        )
    except (ValueError, TypeError, OverflowError, RecursionError):
        return TransportResult(
            TransportOutcome.TARGET_ERROR,
            None,
            latency_ms,
            status,
            None,
            SafeReasonCode.MAPPING_ERROR,
            {},
            redactor.clean(diagnostics),
        )


def bind(value, context):
    if "literal" in value:
        return copy.deepcopy(value["literal"])
    if "context" in value:
        item = getattr(context, value["context"])
        if item is None:
            if value.get("missing") == "omit":
                return _OMIT
            raise ValueError("Binding context missing")
        return list(item) if isinstance(item, tuple) else item
    if "object" in value:
        return {
            key: item
            for key, val in value["object"].items()
            if (item := bind(val, context)) is not _OMIT
        }
    return [item for val in value["array"] if (item := bind(val, context)) is not _OMIT]


def render_request(request, context):
    if "none" in request.body:
        return None
    if "json" in request.body:
        data = {
            key: item
            for key, val in request.body["json"].items()
            if (item := bind(val, context)) is not _OMIT
        }
        return json.dumps(data, ensure_ascii=False, allow_nan=False).encode("utf-8")
    data = bind(request.body["text"], context)
    if not isinstance(data, str):
        raise ValueError("Text body must be a string")
    return data.encode("utf-8")


@dataclass(frozen=True)
class LegacyPreparedRequest:
    method: str
    url: str
    headers: dict[str, str]
    content: str | bytes
    timeout_s: float = 120


@dataclass(frozen=True)
class LegacyResponseSelector:
    text_path: str | None = None
    latency_path: str | None = None
    metadata_paths: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class LegacyResult:
    response_text: str
    latency_ms: float
    metadata: dict = field(default_factory=dict)


class TransportEngine:
    def __init__(self, spec, *, policy=None, client=None, redactor=None):
        self.spec = spec
        self.policy = policy or ExecutionPolicy()
        self.client = client
        self.redactor = redactor or Redactor()

    async def run(self, context):
        with redacted_transport_logs(self.redactor):
            return await self._run(context)

    async def _run(self, context):
        start = time.monotonic()
        redactor = self.redactor
        if not isinstance(self.spec.delivery, (SyncSpec, PollSpec)):
            return self.failure(SafeReasonCode.UNSUPPORTED_DELIVERY, start)
        try:
            content = render_request(self.spec.request, context)
        except (ValueError, TypeError, AttributeError):
            return self.failure(SafeReasonCode.BINDING_ERROR, start)
        request_headers = {**self.spec.request.headers, "Accept-Encoding": "identity"}
        try:
            if self.spec.auth.kind == "bearer":
                secret = resolve_secret(self.spec.auth.secret, self.policy)
                redactor.add(secret)
                request_headers["Authorization"] = "Bearer " + secret
            for header in self.spec.auth.headers:
                secret = resolve_secret(header.secret, self.policy)
                redactor.add(secret)
                request_headers[header.name] = secret
        except (ValueError, OSError, UnicodeError):
            return self.failure(SafeReasonCode.SECRET_ERROR, start)
        if "json" in self.spec.request.body and not any(
            k.lower() == "content-type" for k in request_headers
        ):
            request_headers["Content-Type"] = "application/json"
        diagnostics = {
            "request_method": self.spec.request.method,
            "request_url": self.spec.request.url,
            "request_fields": list(self.spec.request.body.get("json", {})),
            "requests": {"submit": 0, "poll": 0, "retry": 0},
        }
        try:
            async with asyncio.timeout(self.spec.timeout.total_deadline_s):
                if self.client is None:
                    async with httpx.AsyncClient(
                        follow_redirects=False, trust_env=False
                    ) as client:
                        return await self._operate(
                            client,
                            request_headers,
                            content,
                            start,
                            redactor,
                            diagnostics,
                        )
                return await self._operate(
                    self.client, request_headers, content, start, redactor, diagnostics
                )
        except asyncio.CancelledError as exc:
            if isinstance(self.spec.delivery, PollSpec) and diagnostics.get("run_id"):
                diagnostics["job_detached"] = True
            exc.transport_diagnostics = redactor.clean(diagnostics)
            raise
        except (TimeoutError, httpx.TimeoutException):
            return self.failure(
                SafeReasonCode.TIMEOUT, start, diagnostics=redactor.clean(diagnostics)
            )
        except (ValueError, OSError):
            return self.failure(
                SafeReasonCode.ENDPOINT_ERROR,
                start,
                diagnostics=redactor.clean(diagnostics),
            )
        except httpx.HTTPError:
            return self.failure(
                SafeReasonCode.NETWORK_ERROR,
                start,
                diagnostics=redactor.clean(diagnostics),
            )

    async def _operate(self, client, headers, content, start, redactor, diagnostics):
        submitted = await self._exchange(
            client,
            self.spec.request,
            headers,
            content,
            start,
            redactor,
            diagnostics,
            phase="submit",
        )
        if isinstance(submitted, TransportResult):
            return submitted
        status, body = submitted
        if isinstance(self.spec.delivery, SyncSpec):
            return self._evaluate(status, body, start, redactor, diagnostics)
        delivery = self.spec.delivery
        try:
            _, _, reason, matched = outcome_match(delivery.submit_outcome, status, body)
            if matched or reason == SafeReasonCode.HTTP_ERROR:
                return self._evaluate(
                    status,
                    body,
                    start,
                    redactor,
                    diagnostics,
                    spec=replace(self.spec, outcome=delivery.submit_outcome),
                )
            if status not in delivery.submit_http_status:
                return self.failure(
                    SafeReasonCode.HTTP_ERROR,
                    start,
                    status=status,
                    diagnostics=redactor.clean(diagnostics),
                )
            if delivery.submit_outcome.unmatched != "accepted":
                return self.failure(
                    SafeReasonCode.UNKNOWN_STATUS,
                    start,
                    status=status,
                    diagnostics=redactor.clean(diagnostics),
                )
            job_id = select(body, delivery.run_id["path"])
            if type(job_id) not in {str, int} or not str(job_id):
                raise ValueError("Missing or invalid run ID")
            job_id = str(job_id)
            diagnostics["run_id"] = redactor.clean(job_id)
            encoded = quote(job_id, safe="")
            if encoded in {".", ".."}:
                encoded = encoded.replace(".", "%2E")
            poll_request = replace(
                delivery.request,
                url=delivery.request.url.replace("{run_id}", encoded),
            )
            auth_names = {header.name.lower() for header in self.spec.auth.headers}
            if self.spec.auth.kind == "bearer":
                auth_names.add("authorization")
            auth_headers = {
                key: value
                for key, value in headers.items()
                if key.lower() in auth_names
            }
            poll_headers = {
                **poll_request.headers,
                **auth_headers,
                "Accept-Encoding": "identity",
            }
            for index in range(delivery.max_polls):
                polled = await self._exchange(
                    client,
                    poll_request,
                    poll_headers,
                    None,
                    start,
                    redactor,
                    diagnostics,
                    phase="poll",
                )
                if isinstance(polled, TransportResult):
                    return polled
                status, body = polled
                _, _, reason, matched = outcome_match(self.spec.outcome, status, body)
                pending = (
                    not matched
                    and reason != SafeReasonCode.HTTP_ERROR
                    and matches_predicate(body, delivery.pending)
                )
                if not pending:
                    result = self._evaluate(status, body, start, redactor, diagnostics)
                    metadata = {"run_id": redactor.clean(job_id), **result.metadata}
                    if metadata.get("run_id") is None:
                        metadata["run_id"] = redactor.clean(job_id)
                    return replace(result, metadata=metadata)
                if index + 1 == delivery.max_polls:
                    return self.failure(
                        SafeReasonCode.POLL_LIMIT,
                        start,
                        status=status,
                        diagnostics=redactor.clean(diagnostics),
                    )
                await asyncio.sleep(delivery.interval_s)
        except (ValueError, TypeError, OverflowError, RecursionError):
            return self.failure(
                SafeReasonCode.MAPPING_ERROR,
                start,
                status=status,
                diagnostics=redactor.clean(diagnostics),
            )

    def _evaluate(self, status, body, start, redactor, diagnostics, *, spec=None):
        result = evaluate_response(
            spec or self.spec,
            status,
            body,
            latency_ms=(time.monotonic() - start) * 1000,
            redactor=redactor,
        )
        return replace(
            result,
            diagnostics=redactor.clean({**diagnostics, **result.diagnostics}),
        )

    async def _exchange(
        self,
        client,
        request,
        headers,
        content,
        start,
        redactor,
        diagnostics,
        *,
        phase,
    ):
        try:
            ip = await self.policy.endpoint_ip(request.url)
        except (ValueError, OSError):
            return self.failure(
                SafeReasonCode.ENDPOINT_ERROR,
                start,
                diagnostics=redactor.clean(diagnostics),
            )
        remaining = self.spec.timeout.total_deadline_s - (time.monotonic() - start)
        if remaining <= 0:
            raise TimeoutError
        budget = self.spec.timeout
        timeout = httpx.Timeout(
            connect=min(budget.connect_s, remaining),
            read=min(budget.read_s, remaining),
            write=min(budget.write_s, remaining),
            pool=min(budget.pool_s, remaining),
        )
        url = httpx.URL(request.url)
        parts = urlsplit(str(url))
        headers = {**headers, "Host": parts.netloc}
        url = url.copy_with(host=ip)
        diagnostics["requests"][phase] += 1
        async with client.stream(
            request.method,
            url,
            headers=headers,
            content=content,
            timeout=timeout,
            follow_redirects=False,
            extensions={"sni_hostname": parts.hostname},
        ) as response:
            status = response.status_code
            if not 200 <= status < 300 and status not in {400, 403}:
                return self.failure(
                    SafeReasonCode.HTTP_ERROR,
                    start,
                    status=status,
                    diagnostics=redactor.clean(diagnostics),
                )
            if response.headers.get(
                "Content-Encoding", "identity"
            ).strip().lower() not in {"", "identity"}:
                return self.failure(
                    SafeReasonCode.PARSE_ERROR,
                    start,
                    status=status,
                    diagnostics=redactor.clean(diagnostics),
                )
            body = bytearray()
            async for chunk in response.aiter_bytes():
                body.extend(chunk)
                if len(body) > self.spec.limits.response_bytes:
                    return self.failure(
                        SafeReasonCode.RESPONSE_LIMIT,
                        start,
                        status=status,
                        diagnostics=redactor.clean(diagnostics),
                    )
            try:
                raw = body.decode("utf-8")
                parsed = json.loads(raw) if self.spec.response.format == "json" else raw
            except (UnicodeError, ValueError, RecursionError):
                return self.failure(
                    SafeReasonCode.PARSE_ERROR,
                    start,
                    status=status,
                    diagnostics=redactor.clean(diagnostics),
                )
            return status, parsed

    @staticmethod
    def failure(reason, start, *, status=None, diagnostics=None):
        outcome = (
            TransportOutcome.TIMED_OUT
            if reason == SafeReasonCode.TIMEOUT
            else TransportOutcome.TARGET_ERROR
        )
        return TransportResult(
            outcome,
            None,
            (time.monotonic() - start) * 1000,
            status,
            None,
            reason,
            (
                {"run_id": diagnostics["run_id"]}
                if diagnostics and diagnostics.get("run_id")
                else {}
            ),
            diagnostics or {"requests": {"submit": 0, "poll": 0, "retry": 0}},
        )

    @staticmethod
    async def run_legacy(request, mapping, *, client=None, secrets=()):
        if client is None:
            async with httpx.AsyncClient(timeout=request.timeout_s) as owned:
                return await TransportEngine.run_legacy(
                    request, mapping, client=owned, secrets=secrets
                )
        start = time.monotonic()
        response = await client.request(
            method=request.method,
            url=request.url,
            headers=request.headers,
            content=request.content,
        )
        response.raise_for_status()
        ct = request.headers.get("Content-Type", "application/json")
        body = (
            response.json()
            if ct.startswith("application/json") or ct == ""
            else {"_raw": response.text}
        )
        if mapping.text_path:
            value = select(body, mapping.text_path, legacy=True)
            answer = (
                ""
                if value is _MISSING or value is None or value in ([], {})
                else (
                    value
                    if isinstance(value, str)
                    else json.dumps(value, ensure_ascii=False)
                )
            )
        elif isinstance(body, dict) and "_raw" in body:
            answer = body["_raw"]
        else:
            answer = json.dumps(body, ensure_ascii=False)
        latency = (time.monotonic() - start) * 1000
        if mapping.latency_path:
            value = select(body, mapping.latency_path, legacy=True)
            if value is not _MISSING and isinstance(value, (int, float)):
                latency = float(value)
        metadata = {}
        for name, path in mapping.metadata_paths.items():
            if path:
                value = select(body, path, legacy=True)
                if value is not _MISSING:
                    metadata[name] = value
        redactor = Redactor(secrets)
        return LegacyResult(redactor.clean(answer), latency, redactor.clean(metadata))
