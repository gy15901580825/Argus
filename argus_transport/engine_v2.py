from __future__ import annotations

import asyncio
import base64
import copy
import json
import re
import time
import uuid
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Mapping
from urllib.parse import quote, urlencode, urlsplit, urlunsplit

import httpx

from .engine import _OMIT, evaluate_response, matches_predicate, outcome_match, select
from .models import (
    SafeReasonCode,
    SyncSpec,
    TransportContext,
    TransportOutcome,
    TransportResult,
)
from .security import redacted_transport_logs, resolve_secret
from .spec_v2 import PollSpecV2, RequestSpecV2, TransportSpecV2

if TYPE_CHECKING:
    from .runtime_v2 import V2Run


def bind_v2(
    value: dict,
    context: TransportContext,
    scope: Mapping[str, str | int],
    env: Mapping[str, str],
) -> object:
    if "literal" in value:
        return copy.deepcopy(value["literal"])
    if "context" in value or "var" in value or "env" in value:
        if "context" in value:
            item = getattr(context, value["context"])
        elif "var" in value:
            item = scope.get(value["var"])
        else:
            item = env.get(value["env"])
        if item is None:
            if value.get("missing") == "omit":
                return _OMIT
            raise ValueError("Binding value missing")
        return list(item) if isinstance(item, tuple) else item
    if "generate" in value:
        kind = value["generate"]
        if kind == "uuid4":
            return str(uuid.uuid4())
        if kind == "now_iso8601":
            return (
                datetime.now(timezone.utc)
                .isoformat(timespec="milliseconds")
                .replace("+00:00", "Z")
            )
        return time.time_ns() // 1_000_000
    if "concat" in value:
        items = [bind_v2(part, context, scope, env) for part in value["concat"]]
        if any(type(item) not in {str, int} for item in items):
            raise ValueError("Concat requires strings or integers")
        result = "".join(str(item) for item in items)
        if len(result.encode("utf-8")) > 8192:
            raise ValueError("Concat exceeds byte limit")
        return result
    if "base64" in value:
        item = bind_v2(value["base64"], context, scope, env)
        if not isinstance(item, str):
            raise ValueError("Base64 requires a string")
        return base64.b64encode(item.encode("utf-8")).decode("ascii")
    if "object" in value:
        return {
            name: item
            for name, expr in value["object"].items()
            if (item := bind_v2(expr, context, scope, env)) is not _OMIT
        }
    return [
        item
        for expr in value["array"]
        if (item := bind_v2(expr, context, scope, env)) is not _OMIT
    ]


def render_url(
    request: RequestSpecV2,
    context: TransportContext,
    scope: Mapping[str, str | int],
    env: Mapping[str, str],
) -> str:
    parts = urlsplit(request.url)

    def segment(value):
        def substitute(match):
            item = scope.get(match.group(1))
            if type(item) not in {str, int}:
                raise ValueError("Path variable requires a string or integer")
            return quote(str(item), safe="")

        result = re.sub(r"\{([^{}]+)\}", substitute, value)
        return result.replace(".", "%2E") if result in {".", ".."} else result

    path = "/".join(segment(value) for value in parts.path.split("/"))
    query = []
    for name, expr in request.query.items():
        item = bind_v2(expr, context, scope, env)
        if item is _OMIT:
            continue
        if type(item) not in {str, int}:
            raise ValueError("Query requires strings or integers")
        query.append((name, item))
    return urlunsplit(
        (
            parts.scheme,
            parts.netloc,
            path,
            urlencode(query) if request.query else parts.query,
            parts.fragment,
        )
    )


def render_body_v2(
    request: RequestSpecV2,
    context: TransportContext,
    scope: Mapping[str, str | int],
    env: Mapping[str, str],
) -> bytes | None:
    if "none" in request.body:
        return None
    if "json" in request.body:
        data = {
            name: item
            for name, expr in request.body["json"].items()
            if (item := bind_v2(expr, context, scope, env)) is not _OMIT
        }
        return json.dumps(data, ensure_ascii=False, allow_nan=False).encode("utf-8")
    data = bind_v2(request.body["text"], context, scope, env)
    if not isinstance(data, str):
        raise ValueError("Text body must be a string")
    return data.encode("utf-8")


@dataclass(frozen=True)
class ExchangeResponse:
    status: int
    body: object
    headers: Mapping[str, str]


class TransportEngineV2:
    def __init__(
        self,
        spec: TransportSpecV2,
        *,
        run: V2Run,
        client: httpx.AsyncClient | None = None,
    ):
        self.spec = spec
        self.runtime = run
        self.policy = run.policy
        self.client = client
        self.redactor = run.redactor

    async def run(self, context: TransportContext) -> TransportResult:
        with redacted_transport_logs(self.redactor):
            return await self._run(context)

    async def _run(self, context):
        start = time.monotonic()
        redactor = self.redactor
        if not isinstance(self.spec.delivery, (SyncSpec, PollSpecV2)):
            return self.failure(SafeReasonCode.UNSUPPORTED_DELIVERY, start)
        try:
            scope = dict(self.runtime.run_vars)
            for name, expression in self.spec.let.attempt.items():
                item = bind_v2(expression, context, scope, self.runtime.env)
                if item is not _OMIT:
                    if type(item) not in {str, int}:
                        raise ValueError("Variable requires a string or integer")
                    scope[name] = item
            request = replace(
                self.spec.request,
                url=render_url(self.spec.request, context, scope, self.runtime.env),
            )
            content = render_body_v2(request, context, scope, self.runtime.env)
        except (ValueError, TypeError, AttributeError, OverflowError, RecursionError):
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
            "request_url": request.url,
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
                            request,
                            context,
                            scope,
                        )
                return await self._operate(
                    self.client,
                    request_headers,
                    content,
                    start,
                    redactor,
                    diagnostics,
                    request,
                    context,
                    scope,
                )
        except asyncio.CancelledError as exc:
            if isinstance(self.spec.delivery, PollSpecV2) and diagnostics.get("run_id"):
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

    async def _operate(
        self,
        client,
        headers,
        content,
        start,
        redactor,
        diagnostics,
        request,
        context,
        scope,
    ):
        submitted = await self._exchange(
            client,
            request,
            headers,
            content,
            start,
            redactor,
            diagnostics,
            phase="submit",
        )
        if isinstance(submitted, TransportResult):
            return submitted
        status, body = submitted.status, submitted.body
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
            job_id = select(body, delivery.ids["run_id"]["path"])
            if type(job_id) not in {str, int} or not str(job_id):
                raise ValueError("Missing or invalid run ID")
            job_id = str(job_id)
            diagnostics["run_id"] = redactor.clean(job_id)
            try:
                poll_request = replace(
                    delivery.request,
                    url=render_url(
                        delivery.request,
                        context,
                        {**scope, "run_id": job_id},
                        self.runtime.env,
                    ),
                )
            except (ValueError, TypeError, AttributeError):
                return self.failure(
                    SafeReasonCode.BINDING_ERROR,
                    start,
                    status=status,
                    diagnostics=redactor.clean(diagnostics),
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
                status, body = polled.status, polled.body
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
            return ExchangeResponse(status, parsed, {})

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
