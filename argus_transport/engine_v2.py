from __future__ import annotations

import asyncio
import base64
import copy
import json
import math
import re
import time
import uuid
from dataclasses import dataclass, replace
from contextlib import asynccontextmanager
from collections.abc import Callable
from types import MappingProxyType
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import TYPE_CHECKING, Mapping
from urllib.parse import quote, urlencode, urljoin, urlsplit, urlunsplit

import httpx

from .engine import _MISSING, _OMIT, evaluate_response, matches_predicate, outcome_match, select
from .models import (
    SafeReasonCode,
    SyncSpec,
    TransportContext,
    TransportOutcome,
    TransportResult,
)
from .security import redacted_transport_logs, resolve_secret
from .spec_v2 import CaptureSpec, PollSpecV2, RequestSpecV2, TransportSpecV2

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
        if any(item is _OMIT for item in items):
            return _OMIT
        if any(type(item) not in {str, int} for item in items):
            raise ValueError("Concat requires strings or integers")
        result = "".join(str(item) for item in items)
        if len(result.encode("utf-8")) > 8192:
            raise ValueError("Concat exceeds byte limit")
        return result
    if "base64" in value:
        item = bind_v2(value["base64"], context, scope, env)
        if item is _OMIT:
            return _OMIT
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
    *, boundary: str | None = None,
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
    if "multipart" in request.body:
        if request.method not in {"POST", "PUT"}:
            raise ValueError("Multipart method must be POST or PUT")
        boundary = boundary or uuid.uuid4().hex
        parts = []
        for name, part in request.body["multipart"].items():
            if re.fullmatch(r"[a-z][a-z0-9_]{0,31}", name) is None:
                raise ValueError("Invalid multipart part name")
            if part["content_type"] not in {"text/plain", "text/markdown", "application/json", "text/csv"}:
                raise ValueError("Invalid multipart media type")
            filename = bind_v2(part["filename"], context, scope, env)
            content = bind_v2(part["content"], context, scope, env)
            if filename is _OMIT or content is _OMIT:
                continue
            if not isinstance(filename, str) or not filename or any(char in filename for char in '\r\n\0"'):
                raise ValueError("Invalid multipart filename")
            if not isinstance(content, str):
                raise ValueError("Multipart content must be a string")
            encoded = content.encode("utf-8")
            if len(encoded) > 1048576:
                raise ValueError("Multipart content exceeds byte limit")
            disposition = f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"; filename="{filename}"\r\n'
            parts.append(disposition.encode("utf-8") +
                         f'Content-Type: {part["content_type"]}\r\n\r\n'.encode("ascii") + encoded + b"\r\n")
        return b"".join(parts) + f"--{boundary}--\r\n".encode("ascii")
    data = bind_v2(request.body["text"], context, scope, env)
    if not isinstance(data, str):
        raise ValueError("Text body must be a string")
    return data.encode("utf-8")


@dataclass(frozen=True)
class ExchangeResponse:
    status: int
    body: object
    headers: Mapping[str, str]


class _CapturePrefixError(ValueError):
    pass


class _CaptureNotFound(ValueError):
    pass


class _CaptureAmbiguous(ValueError):
    def __init__(self, count):
        super().__init__('Ambiguous captured item')
        self.count = count


class _SecretBindingError(ValueError):
    pass


def _resolved_where(value, context, scope, env):
    result = json.loads(json.dumps(value))
    for operator in ('all', 'any', 'not'):
        if operator in value:
            children = [value[operator]] if operator == 'not' else value[operator]
            resolved = [_resolved_where(child, context, scope, env) for child in children]
            if any(child is _OMIT for child in resolved):
                return _OMIT
            result[operator] = resolved[0] if operator == 'not' else resolved
            return result
    operator = 'equals' if 'equals' in value else 'one_of' if 'one_of' in value else None
    if operator is not None:
        values = [result[operator]] if operator == 'equals' else result[operator]
        resolved = []
        for item in values:
            if isinstance(item, dict) and set(item) in ({'env'}, {'env', 'missing'}, {'var'}):
                expression = {**item, 'missing': 'omit'} if 'var' in item else item
                item = bind_v2(expression, context, scope, env)
            if item is _OMIT:
                return _OMIT
            resolved.append(item)
        result[operator] = resolved[0] if operator == 'equals' else resolved
    return result


def capture_value(selector, body, context, scope, env, *, given=False):
    if given:
        raw = body
    elif selector.items is not None:
        items = select(body, selector.items)
        if not isinstance(items, list):
            raise ValueError('Capture items must be an array')
        where = _resolved_where(selector.where, context, scope, env)
        matched = [] if where is _OMIT else [item for item in items if matches_predicate(item, where)]
        if not matched:
            raise _CaptureNotFound('No captured item')
        if len(matched) != 1:
            raise _CaptureAmbiguous(len(matched))
        raw = select(matched[0], selector.take)
    else:
        raw = select(body, selector.path)
    if raw is _MISSING:
        raise _CaptureNotFound('No captured item')
    if selector.last_segment or selector.expect_prefix is not None:
        if not isinstance(raw, str) or not raw:
            raise _CapturePrefixError('Invalid captured identifier')
        if selector.expect_prefix is not None and not (given and selector.last_segment):
            try:
                prefix = bind_v2(selector.expect_prefix, context, scope, env)
            except (ValueError, TypeError, AttributeError, OverflowError, RecursionError):
                raise _CapturePrefixError('Invalid capture prefix') from None
            if not isinstance(prefix, str) or not prefix or not raw.startswith(prefix):
                raise _CapturePrefixError('Invalid capture prefix')
        if selector.last_segment:
            value = raw if given else raw.rsplit('/', 1)[-1]
            if re.fullmatch(r'[A-Za-z0-9._~-]{1,256}', value) is None:
                raise _CapturePrefixError('Invalid captured identifier')
            return value
        return raw
    if type(raw) not in {str, int} or not str(raw):
        raise ValueError('Missing captured identifier')
    return raw


def _request_needs(request):
    needs = set(request.placeholders)
    def collect(expression):
        if 'var' in expression:
            needs.add(expression['var'])
        elif 'base64' in expression:
            collect(expression['base64'])
        elif 'object' in expression:
            for child in expression['object'].values():
                collect(child)
        elif 'array' in expression or 'concat' in expression:
            for child in expression.get('array', expression.get('concat', ())):
                collect(child)
    for expression in request.query.values():
        collect(expression)
    for expression in request.body.get('json', {}).values():
        collect(expression)
    if 'text' in request.body:
        collect(request.body['text'])
    return frozenset(needs)


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

    @asynccontextmanager
    async def _client(self):
        if self.client is not None:
            yield self.client
        else:
            async with httpx.AsyncClient(follow_redirects=False, trust_env=False) as client:
                yield client

    def _headers(self, request):
        headers = {**request.headers, 'Accept-Encoding': 'identity'}
        try:
            if self.spec.auth.kind == 'bearer':
                secret = resolve_secret(self.spec.auth.secret, self.policy)
                self.redactor.add(secret)
                headers['Authorization'] = 'Bearer ' + secret
            for header in self.spec.auth.headers:
                secret = resolve_secret(header.secret, self.policy)
                self.redactor.add(secret)
                headers[header.name] = secret
        except (ValueError, OSError, UnicodeError):
            raise _SecretBindingError('Secret resolution failed') from None
        if 'json' in request.body and not any(k.lower() == 'content-type' for k in headers):
            headers['Content-Type'] = 'application/json'
        return headers

    def _bind_request(self, request, context, scope):
        boundary = None
        if "multipart" in request.body:
            if any(name.lower() == "content-type" for name in request.headers):
                raise ValueError("Content-Type conflicts with multipart body")
            boundary = uuid.uuid4().hex
            request = replace(request, headers={**request.headers,
                              "Content-Type": "multipart/form-data; boundary=" + boundary})
        bound = replace(request, url=render_url(request, context, scope, self.runtime.env))
        return bound, render_body_v2(bound, context, scope, self.runtime.env, boundary=boundary)

    def _bind_undo(self, intent, context, scope):
        intent._bindings = MappingProxyType(dict(scope))
        intent._context = context
        try:
            request, content = self._bind_request(intent.spec.request, context, scope)
            headers = self._headers(request)
        except (ValueError, TypeError, AttributeError, OverflowError, RecursionError):
            intent.status = 'unbound'
            return
        intent._request = request
        intent._content = content
        intent._headers = headers
        intent.url = self.redactor.clean(request.url)
        intent.status = 'pending'

    async def startup(self, context):
        start = time.monotonic()
        scope = dict(self.runtime.run_vars)
        diagnostics = {'requests': {'provision': 0, 'setup': 0, 'cleanup': 0}}
        with redacted_transport_logs(self.redactor):
            async with asyncio.timeout(self.spec.timeout.total_deadline_s):
                async with self._client() as client:
                    if self.spec.lifecycle.provision is not None:
                        from .provision_v2 import run_provision
                        async def exchange(request, bindings):
                            request, content = self._bind_request(request, context, bindings)
                            return await self._exchange(client, request, self._headers(request), content,
                                                        start, self.redactor, diagnostics, phase='provision')
                        scope.update(await run_provision(self.runtime, exchange))
                    await self._steps(self.spec.lifecycle.run, 'run', self.runtime.run_undos,
                                      client, context, scope, start, diagnostics)
        self.runtime.run_vars = MappingProxyType(scope)

    async def _steps(self, steps, scope_name, stack, client, context, scope, start, diagnostics):
        from .runtime_v2 import TargetRunStopped, UndoIntent, _ResourceRecord
        for step in steps:
            if step.if_present is not None:
                guard = scope.get(step.if_present, getattr(context, step.if_present, None))
                if guard is None or guard is _OMIT:
                    continue
            reason = SafeReasonCode.SETUP_FAILED
            try:
                request, content = self._bind_request(step.request, context, scope)
                headers = self._headers(request)
                self.runtime.ledger._check_request()
                intent = None
                if step.undo is not None:
                    needs = _request_needs(step.undo.request)
                    if step.undo.confirm is not None:
                        needs |= _request_needs(step.undo.confirm.request)
                    intent = UndoIntent(scope_name, step.id, step.undo, needs, frozenset(step.capture))
                    self._bind_undo(intent, context, scope)
                    stack.register(intent)
                self.runtime.ledger.charge('setup')
                records = []
                def record_accepted():
                    record = _ResourceRecord(
                        self.redactor.clean(f"step '{step.id}' {request.method} {request.url}"),
                        scope_name, step.id, intent,
                        len(self.runtime.attempt_undos) - 1 if scope_name == 'attempt' else None,
                    )
                    records.append(record)
                    self.runtime._resources.append(record)
                    stack._resources.append(record)
                response = await self._exchange(client, request, headers, content, start,
                                                self.redactor, diagnostics, phase='setup', admitted=True,
                                                on_accepted=record_accepted if request.method in {"POST", "PUT", "PATCH", "DELETE"} else None)
                if records and isinstance(response, ExchangeResponse):
                    names = []
                    for selector in step.capture.values():
                        if selector.expect_prefix is not None:
                            try:
                                name = capture_value(replace(selector, last_segment=False), response.body,
                                                     context, scope, self.runtime.env)
                            except (ValueError, TypeError, AttributeError, OverflowError, RecursionError):
                                continue
                            if name not in names:
                                names.append(name)
                    if names:
                        record = records[0]
                        self.runtime._resources.remove(record)
                        stack._resources.remove(record)
                        identified = [replace(record, name=name) for name in names]
                        self.runtime._resources.extend(identified)
                        stack._resources.extend(identified)
                if isinstance(response, TransportResult):
                    reason = response.reason_code
                elif response.status in step.expect.http_status and (
                    step.expect.when is None or matches_predicate(response.body, step.expect.when)
                ):
                    selected = {name: capture_value(selector, response.body, context, scope,
                                                    self.runtime.env)
                                for name, selector in step.capture.items()}
                    scope.update(selected)
                    if intent is not None:
                        self._bind_undo(intent, context, scope)
                    continue
            except _CapturePrefixError:
                reason = SafeReasonCode.ID_PREFIX_MISMATCH
            except (ValueError, TypeError, AttributeError, OverflowError, RecursionError):
                reason = SafeReasonCode.SETUP_FAILED
            except httpx.TimeoutException:
                reason = SafeReasonCode.TIMEOUT
            except httpx.HTTPError:
                reason = SafeReasonCode.NETWORK_ERROR
            if scope_name == 'run':
                stop_reason = 'id_prefix_mismatch' if reason == SafeReasonCode.ID_PREFIX_MISMATCH else 'setup_failed_run'
                raise TargetRunStopped(stop_reason, f"step '{step.id}'")
            return self.failure(reason, start, diagnostics=self.redactor.clean(diagnostics))
        return None

    async def cleanup(self, stack, diagnostics=None):
        start = time.monotonic()
        diagnostics = diagnostics if diagnostics is not None else {'requests': {'cleanup': 0}}
        async def send(intent):
            if intent.spec.request.method not in {'GET', 'DELETE'} or 'multipart' in intent.spec.request.body:
                intent.status = 'failed'
                return
            if intent._request is None:
                intent.status = 'unbound'
                return
            try:
                response = await self._exchange(client, intent._request, intent._headers,
                                                intent._content, start, self.redactor,
                                                diagnostics, phase='cleanup')
                if isinstance(response, TransportResult):
                    intent.http_status = response.http_status
                    intent.status = 'failed'
                    return
                intent.http_status = response.status
                if response.status in intent.spec.expect.http_status:
                    intent.status = 'done' if intent.spec.expect.when is None or matches_predicate(
                        response.body, intent.spec.expect.when) else 'failed'
                    return
                intent.status = 'failed'
                confirm = intent.spec.confirm
                if confirm is None:
                    return
                self.runtime.ledger._check_stopped()
                if confirm.request.method != 'GET' or 'multipart' in confirm.request.body:
                    return
                try:
                    request, content = self._bind_request(confirm.request, intent._context, intent._bindings)
                    headers = self._headers(request)
                except (ValueError, TypeError, AttributeError, OverflowError, RecursionError):
                    intent.status = 'unconfirmed'
                    return
                if not self.runtime.ledger.reserve_optional_cleanup():
                    intent.status = 'unconfirmed'
                    return
                confirmed = await self._exchange(client, request, headers, content, start, self.redactor,
                                                 diagnostics, phase='cleanup')
                if isinstance(confirmed, TransportResult):
                    intent.status = 'failed'
                else:
                    intent.status = 'done' if confirmed.status in confirm.gone_status else 'unconfirmed'
            except (TimeoutError, httpx.HTTPError, ValueError, OSError):
                intent.status = 'failed'
        with redacted_transport_logs(self.redactor):
            async with self._client() as client:
                try:
                    await stack.unwind(send, timeout_s=self.spec.timeout.cleanup_s)
                except TimeoutError:
                    pass

    async def _run(self, context):
        from .runtime_v2 import UndoStack
        start = time.monotonic()
        if not isinstance(self.spec.delivery, (SyncSpec, PollSpecV2)):
            return self.failure(SafeReasonCode.UNSUPPORTED_DELIVERY, start)
        stack = UndoStack(self.runtime.ledger, self.redactor)
        self.runtime.attempt_undos.append(stack)
        diagnostics = {
            'request_method': self.spec.request.method,
            'request_url': self.spec.request.url,
            'request_fields': list(self.spec.request.body.get('json', {})),
            'requests': {'submit': 0, 'poll': 0, 'retry': 0},
        }
        if self.spec.lifecycle.attempt:
            diagnostics['requests'].update(setup=0, cleanup=0)
        result = None
        interrupted = None
        try:
            async with asyncio.timeout(self.spec.timeout.total_deadline_s):
                scope = dict(self.runtime.run_vars)
                for name, expression in self.spec.let.attempt.items():
                    item = bind_v2(expression, context, scope, self.runtime.env)
                    if item is not _OMIT:
                        if type(item) not in {str, int}:
                            raise ValueError('Variable requires a string or integer')
                        scope[name] = item
                async with self._client() as client:
                    result = await self._steps(self.spec.lifecycle.attempt, 'attempt', stack,
                                               client, context, scope, start, diagnostics)
                    if result is None:
                        request, content = self._bind_request(self.spec.request, context, scope)
                        headers = self._headers(request)
                        diagnostics['request_url'] = request.url
                        result = await self._operate(client, headers, content, start, self.redactor,
                                                     diagnostics, request, context, scope)
        except asyncio.CancelledError as exc:
            interrupted = exc
            if isinstance(self.spec.delivery, PollSpecV2) and diagnostics.get('run_id'):
                diagnostics['job_detached'] = True
            raise
        except (TimeoutError, httpx.TimeoutException):
            result = self.failure(SafeReasonCode.TIMEOUT, start, diagnostics=diagnostics)
        except _SecretBindingError:
            result = self.failure(SafeReasonCode.SECRET_ERROR, start, diagnostics=diagnostics)
        except (ValueError, TypeError, AttributeError, OverflowError, RecursionError):
            result = self.failure(SafeReasonCode.BINDING_ERROR, start, diagnostics=diagnostics)
        except OSError:
            result = self.failure(SafeReasonCode.ENDPOINT_ERROR, start, diagnostics=diagnostics)
        except httpx.HTTPError:
            result = self.failure(SafeReasonCode.NETWORK_ERROR, start, diagnostics=diagnostics)
        finally:
            try:
                if stack.intents:
                    await self.cleanup(stack, diagnostics)
            except asyncio.CancelledError as exc:
                interrupted = exc
                raise
            finally:
                if stack._resources or any(step.undo for step in self.spec.lifecycle.attempt):
                    diagnostics['cleanup'] = stack.report()
                if interrupted is not None:
                    interrupted.transport_diagnostics = self.redactor.clean(diagnostics)
        return replace(result, diagnostics=self.redactor.clean({**result.diagnostics, **diagnostics}))

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
            terminal_submit = matched or reason == SafeReasonCode.HTTP_ERROR
            verify_submit = status == 202 and delivery.location == 'verify'
            if terminal_submit and not verify_submit:
                return self._evaluate(
                    status,
                    body,
                    start,
                    redactor,
                    diagnostics,
                    spec=replace(self.spec, outcome=delivery.submit_outcome),
                )
            if not terminal_submit and status not in delivery.submit_http_status:
                return self.failure(
                    SafeReasonCode.HTTP_ERROR,
                    start,
                    status=status,
                    diagnostics=redactor.clean(diagnostics),
                )
            if not terminal_submit and delivery.submit_outcome.unmatched != "accepted":
                return self.failure(
                    SafeReasonCode.UNKNOWN_STATUS,
                    start,
                    status=status,
                    diagnostics=redactor.clean(diagnostics),
                )
            raw_ids = {name: select(body, selector['path']) for name, selector in delivery.ids.items()}
            try:
                ids = {name: capture_value(CaptureSpec(selector['path'], selector.get('last_segment', False),
                                                      selector.get('expect_prefix')), body, context, scope,
                                           self.runtime.env)
                       for name, selector in delivery.ids.items()}
            except _CapturePrefixError:
                return self.failure(SafeReasonCode.ID_PREFIX_MISMATCH, start, status=status,
                                    diagnostics=redactor.clean(diagnostics))
            except ValueError:
                return self.failure(SafeReasonCode.MISSING_ID, start, status=status,
                                    diagnostics=redactor.clean(diagnostics))
            if 'run_id' in ids:
                diagnostics['run_id'] = redactor.clean(str(ids['run_id']))
            try:
                poll_request = replace(
                    delivery.request,
                    url=render_url(delivery.request, context, {**scope, **ids}, self.runtime.env),
                )
            except (ValueError, TypeError, AttributeError):
                return self.failure(SafeReasonCode.BINDING_ERROR, start, status=status,
                                    diagnostics=redactor.clean(diagnostics))
            location_error = self._verify_location(submitted, request.url, poll_request.url, start, diagnostics)
            if location_error is not None:
                return location_error
            if terminal_submit:
                result = self._evaluate(status, body, start, redactor, diagnostics,
                                        spec=replace(self.spec, outcome=delivery.submit_outcome))
                metadata = dict(result.metadata)
                if 'run_id' in ids:
                    metadata['run_id'] = redactor.clean(str(ids['run_id']))
                else:
                    metadata.pop('run_id', None)
                return replace(result, metadata=metadata)
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
            response = submitted
            for index in range(delivery.max_polls):
                if delivery.wait is not None:
                    delay = self._poll_wait(response.headers)
                    if delay > delivery.wait.max_s:
                        return self.failure(SafeReasonCode.POLL_WAIT_LIMIT, start, status=response.status,
                                            diagnostics=redactor.clean(diagnostics))
                else:
                    delay = delivery.interval_s if index else 0
                if delay >= self.spec.timeout.total_deadline_s - (time.monotonic() - start):
                    raise TimeoutError
                if delay > 0:
                    await asyncio.sleep(delay)
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
                for name, selector in delivery.ids.items():
                    poll_selector = delivery.poll_selectors.get(name)
                    if poll_selector is not None:
                        raw = select(body, poll_selector.path)
                        valid = type(raw) is type(ids[name]) and raw == ids[name]
                        if poll_selector.expect_prefix is not None:
                            try:
                                prefix = bind_v2(poll_selector.expect_prefix, context, scope, self.runtime.env)
                                valid_prefix = isinstance(prefix, str) and bool(prefix)
                                if poll_selector.last_segment:
                                    valid = valid_prefix and type(raw) is str and raw == prefix + str(ids[name])
                                else:
                                    valid = valid and valid_prefix and type(raw) is str and raw.startswith(prefix)
                            except (ValueError, TypeError, AttributeError, OverflowError, RecursionError):
                                valid = False
                        if not valid:
                            return self.failure(SafeReasonCode.POLL_IDENTITY_CHANGED, start, status=status,
                                                diagnostics=redactor.clean(diagnostics))
                        continue
                    raw = select(body, selector['path'])
                    if raw is _MISSING:
                        continue
                    try:
                        capture_value(CaptureSpec(selector['path'], selector.get('last_segment', False),
                                                  selector.get('expect_prefix')), body, context, scope,
                                      self.runtime.env)
                    except _CapturePrefixError:
                        return self.failure(SafeReasonCode.ID_PREFIX_MISMATCH, start, status=status,
                                            diagnostics=redactor.clean(diagnostics))
                    except ValueError:
                        return self.failure(SafeReasonCode.POLL_IDENTITY_CHANGED, start, status=status,
                                            diagnostics=redactor.clean(diagnostics))
                    if type(raw) is not type(raw_ids[name]) or raw != raw_ids[name]:
                        return self.failure(SafeReasonCode.POLL_IDENTITY_CHANGED, start, status=status,
                                            diagnostics=redactor.clean(diagnostics))
                _, _, reason, matched = outcome_match(self.spec.outcome, status, body)
                pending = (
                    not matched
                    and reason != SafeReasonCode.HTTP_ERROR
                    and matches_predicate(body, delivery.pending)
                )
                if not pending:
                    result = self._evaluate(status, body, start, redactor, diagnostics)
                    metadata = dict(result.metadata)
                    if 'run_id' in ids:
                        metadata['run_id'] = redactor.clean(str(ids['run_id']))
                    else:
                        metadata.pop('run_id', None)
                    return replace(result, metadata=metadata)
                if index + 1 == delivery.max_polls:
                    return self.failure(
                        SafeReasonCode.POLL_LIMIT,
                        start,
                        status=status,
                        diagnostics=redactor.clean(diagnostics),
                    )
                response = polled
        except (ValueError, TypeError, OverflowError, RecursionError):
            return self.failure(
                SafeReasonCode.MAPPING_ERROR,
                start,
                status=status,
                diagnostics=redactor.clean(diagnostics),
            )

    def _poll_wait(self, headers):
        wait = self.spec.delivery.wait
        value = headers.get('retry-after')
        if value is None:
            return wait.default_s
        try:
            delay = float(value)
        except ValueError:
            try:
                date = parsedate_to_datetime(value)
                if date.tzinfo is None:
                    date = date.replace(tzinfo=timezone.utc)
                delay = max(0, date.timestamp() - time.time())
            except (ValueError, TypeError, OverflowError):
                return wait.default_s
        return delay if math.isfinite(delay) and delay >= 0 else wait.default_s

    def _verify_location(self, response, request_url, poll_url, start, diagnostics):
        from .runtime_v2 import TargetRunStopped
        if self.spec.delivery.location != 'verify' or response.status != 202:
            return None
        location = response.headers.get('location')
        if location is None:
            return self.failure(SafeReasonCode.LOCATION_MISSING, start, status=response.status,
                                diagnostics=self.redactor.clean(diagnostics))
        try:
            actual = urlsplit(urljoin(request_url, location))
            expected = urlsplit(poll_url or self.spec.delivery.request.url)
            safe = (actual.scheme, actual.netloc) == (expected.scheme, expected.netloc)
            safe = safe and (poll_url is None or actual.path == expected.path)
            safe = safe and not (actual.query or actual.fragment or '@' in actual.netloc
                                     or '?' in location or '#' in location)
        except ValueError:
            safe = False
        if not safe:
            self.runtime.ledger.trip('unsafe_location')
            raise TargetRunStopped('unsafe_location')
        return None

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
        admitted=False,
        on_accepted: Callable[[], None] | None = None,
    ):
        from .runtime_v2 import TargetRunStopped
        self.runtime.ledger._check_stopped()
        if phase == "cleanup" and (request.method not in {"GET", "DELETE"} or "multipart" in request.body):
            return self.failure(SafeReasonCode.SETUP_FAILED, start, diagnostics=redactor.clean(diagnostics))
        try:
            ip = await self.policy.endpoint_ip(request.url)
        except (ValueError, OSError):
            return self.failure(
                SafeReasonCode.ENDPOINT_ERROR,
                start,
                diagnostics=redactor.clean(diagnostics),
            )
        deadline = self.spec.timeout.cleanup_s if phase == "cleanup" else self.spec.timeout.total_deadline_s
        remaining = deadline - (time.monotonic() - start)
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
        self.runtime.ledger._check_stopped()
        if phase == "cleanup":
            self.runtime.ledger.spend_cleanup()
        elif not admitted:
            self.runtime.ledger.charge(phase)
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
            if on_accepted is not None and 200 <= status < 300:
                on_accepted()
            stop = self.spec.budget.stop_on
            retained = {'location', 'retry-after', *(name.lower() for name in stop.alert_names)}
            response_headers = {name: response.headers[name] for name in retained
                                if name in response.headers}
            reason = ('stop_on_status' if status in stop.http_status else
                      'alert' if any(name.lower() in response_headers for name in stop.alert_names) else None)
            if reason is not None:
                self.runtime.ledger.trip(reason)
                raise TargetRunStopped(self.runtime.ledger.stopped)
            exchange = ExchangeResponse(status, None, response_headers)
            if phase in {'submit', 'poll'} and isinstance(self.spec.delivery, PollSpecV2):
                location_error = self._verify_location(
                    exchange, request.url, request.url if phase == 'poll' else None, start, diagnostics,
                )
                if location_error is not None:
                    return location_error
            http_error = phase not in {'provision', 'setup', 'cleanup'} and not 200 <= status < 300 and status not in {400, 403}
            if http_error and not (stop.credential_echo and redactor.values):
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
                    SafeReasonCode.HTTP_ERROR if http_error else SafeReasonCode.PARSE_ERROR,
                    start,
                    status=status,
                    diagnostics=redactor.clean(diagnostics),
                )
            body = bytearray()
            echo_values = tuple(value.encode('utf-8') for value in redactor.values) if stop.credential_echo else ()
            async for chunk in response.aiter_bytes():
                previous_len = len(body)
                remaining = self.spec.limits.response_bytes - previous_len
                body.extend(chunk[:remaining])
                if any(len(value) <= len(body) and
                       body.find(value, max(0, previous_len - len(value) + 1)) >= 0
                       for value in echo_values):
                    self.runtime.ledger.trip('credential_echo')
                    raise TargetRunStopped(self.runtime.ledger.stopped)
                if len(chunk) > remaining:
                    return self.failure(
                        SafeReasonCode.HTTP_ERROR if http_error else SafeReasonCode.RESPONSE_LIMIT,
                        start,
                        status=status,
                        diagnostics=redactor.clean(diagnostics),
                    )
            try:
                raw = body.decode("utf-8")
            except UnicodeError:
                return self.failure(SafeReasonCode.HTTP_ERROR if http_error else SafeReasonCode.PARSE_ERROR,
                                    start, status=status, diagnostics=redactor.clean(diagnostics))
            if http_error:
                return self.failure(SafeReasonCode.HTTP_ERROR, start, status=status,
                                    diagnostics=redactor.clean(diagnostics))
            try:
                parsed = (None if not raw and phase in {"provision", "setup", "cleanup"} else json.loads(raw)) if self.spec.response.format == "json" else raw
            except (ValueError, RecursionError):
                if phase == "cleanup":
                    return exchange
                return self.failure(SafeReasonCode.PARSE_ERROR, start, status=status,
                                    diagnostics=redactor.clean(diagnostics))
            return replace(exchange, body=parsed)

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
