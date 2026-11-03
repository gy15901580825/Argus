from __future__ import annotations

import copy
import json
import re
from dataclasses import dataclass
from typing import Iterator
from urllib.parse import urlsplit, urlunsplit

from .models import (
    AuthSpec,
    FrozenModel,
    OutcomeSpec,
    PollSpec,
    RequestSpec,
    ResourceLimits,
    ResponseSpec,
    SessionSpec,
    SseSpec,
    SubmissionOutcomeSpec,
    SyncSpec,
    TimeoutBudget,
    TransportSpec,
    _CONTEXT_KEYS,
    choice,
    endpoint,
    headers,
    object_fields,
    origin,
    path,
    positive,
    predicate,
    text,
    value_expr,
)

NAME_RE = re.compile(r"[a-z][a-z0-9_]{0,31}\Z")
ENV_NAME_RE = re.compile(r"[A-Z_][A-Z0-9_]{0,63}\Z")
SECRET_WORDS = ("key", "token", "secret", "password", "auth", "header", "cookie")
CONTEXT_KEYS_V2 = frozenset(_CONTEXT_KEYS)
V2_FIELD_NAMES = frozenset(
    {"let", "run", "attempt", "var", "concat", "generate", "base64", "env", "query"}
)
_QUERY_RESERVED = {"key", "auth", "authorization"}
_QUERY_FRAGMENTS = ("token", "api_key", "apikey", "password", "secret", "credential")
_EXPR_KINDS = {
    "literal",
    "context",
    "object",
    "array",
    "var",
    "concat",
    "generate",
    "base64",
    "env",
}


def _name(value):
    if (
        not isinstance(value, str)
        or not NAME_RE.fullmatch(value)
        or value in CONTEXT_KEYS_V2
        or any(word in value.lower() for word in SECRET_WORDS)
    ):
        raise ValueError("Invalid transport variable name")
    return value


def value_expr_v2(value: dict, depth: int = 0, *, visible: frozenset[str]) -> dict:
    if depth > 16:
        raise ValueError("Binding nesting exceeds maximum")
    object_fields(value, _EXPR_KINDS | {"missing"})
    kinds = set(value) & _EXPR_KINDS
    if len(kinds) != 1:
        raise ValueError("Binding requires one variant")
    kind = next(iter(kinds))
    if "missing" in value:
        if kind not in {"context", "var", "env"}:
            raise ValueError("Binding requires one variant")
        choice(value["missing"], {"error", "omit"})
    item = value[kind]
    if kind in {"literal", "context"}:
        value_expr(value, depth)
    elif kind == "var":
        _name(item)
        if not isinstance(item, str) or item not in visible:
            raise ValueError("Transport variable is not visible")
    elif kind == "env":
        if not isinstance(item, str) or not ENV_NAME_RE.fullmatch(item):
            raise ValueError("Invalid environment variable name")
    elif kind == "generate":
        choice(item, {"uuid4", "now_iso8601", "now_unix_ms"})
    elif kind == "base64":
        value_expr_v2(item, depth + 1, visible=visible)
    elif kind == "concat":
        if not isinstance(item, list) or not 2 <= len(item) <= 16:
            raise ValueError("Invalid concat binding")
        static_bytes = 0
        for part in item:
            value_expr_v2(part, depth + 1, visible=visible)
            if "literal" in part:
                if type(part["literal"]) not in {str, int}:
                    raise ValueError("Concat requires strings or integers")
                static_bytes += len(str(part["literal"]).encode("utf-8"))
            elif "object" in part or "array" in part:
                raise ValueError("Concat requires strings or integers")
        if static_bytes > 8192:
            raise ValueError("Concat exceeds byte limit")
    elif kind == "object":
        if not isinstance(item, dict) or len(item) > 128:
            raise ValueError("Invalid object binding")
        for name, expr in item.items():
            text(name)
            value_expr_v2(expr, depth + 1, visible=visible)
    else:
        if not isinstance(item, list) or len(item) > 128:
            raise ValueError("Invalid array binding")
        for expr in item:
            value_expr_v2(expr, depth + 1, visible=visible)
    return copy.deepcopy(value)


def _endpoint_v2(url, visible):
    text(url)
    try:
        parts = urlsplit(url)
    except ValueError as exc:
        raise ValueError("Invalid transport endpoint") from exc
    if any(char in parts.netloc + parts.query for char in "{}"):
        raise ValueError("Endpoint variables must be in the path")
    found = []
    for segment in parts.path.split("/"):
        matches = re.findall(r"\{([^{}]*)\}", segment)
        remaining = re.sub(r"\{[^{}]*\}", "", segment)
        if len(matches) > 1 or "{" in remaining or "}" in remaining:
            raise ValueError("Endpoint requires one variable per path segment")
        for name in matches:
            if (
                not NAME_RE.fullmatch(name)
                or name not in visible
                or name in CONTEXT_KEYS_V2 - {"run_id"}
            ):
                raise ValueError("Endpoint variable is not visible")
            found.append(name)
    endpoint(re.sub(r"\{[^{}]*\}", "v", url))
    return url, tuple(found)


@dataclass(frozen=True)
class RequestSpecV2(FrozenModel):
    method: str
    url: str
    headers: dict[str, str]
    body: dict
    query: dict[str, dict]
    placeholders: tuple[str, ...]

    @classmethod
    def from_dict(cls, data, *, visible: frozenset[str]):
        object_fields(data, {"method", "url", "headers", "body", "query"}, {"url"})
        method = choice(
            data.get("method", "POST"),
            {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"},
        )
        body = data.get(
            "body", {"none": True} if method in {"GET", "HEAD", "DELETE"} else None
        )
        object_fields(body, {"json", "text", "none"})
        if len(body) != 1:
            raise ValueError("Body requires one variant")
        if "none" in body:
            if body["none"] is not True:
                raise ValueError("Invalid empty body")
        elif "json" in body:
            if not isinstance(body["json"], dict) or len(body["json"]) > 128:
                raise ValueError("Invalid JSON body")
            for name, expr in body["json"].items():
                text(name)
                value_expr_v2(expr, visible=visible)
        else:
            value_expr_v2(body["text"], visible=visible)
        if method in {"GET", "HEAD"} and body != {"none": True}:
            raise ValueError("GET and HEAD cannot have a body")
        public = headers(data.get("headers", {}))
        content_type = next(
            (v for k, v in public.items() if k.lower() == "content-type"), None
        )
        if (
            content_type
            and "json" in body
            and content_type.split(";")[0].strip().lower() != "application/json"
        ):
            raise ValueError("Content-Type conflicts with body")
        url, placeholders = _endpoint_v2(data["url"], visible)
        query = data.get("query", {})
        if not isinstance(query, dict) or len(query) > 128:
            raise ValueError("Invalid query bindings")
        if "query" in data and "?" in url:
            raise ValueError("Query bindings conflict with endpoint query")
        for name, expr in query.items():
            normalized = text(name).lower().replace("-", "_")
            if normalized in _QUERY_RESERVED or any(
                word in normalized for word in _QUERY_FRAGMENTS
            ):
                raise ValueError("Credential-like query parameter")
            value_expr_v2(expr, visible=visible)
        return cls(
            method, url, public, copy.deepcopy(body), copy.deepcopy(query), placeholders
        )


@dataclass(frozen=True)
class LetSpec(FrozenModel):
    run: dict[str, dict]
    attempt: dict[str, dict]


@dataclass(frozen=True)
class PollSpecV2(FrozenModel):
    kind: str
    ids: dict[str, dict]
    request: RequestSpecV2
    pending: dict
    interval_s: float
    max_polls: int
    submit_http_status: tuple[int, ...]
    submit_outcome: SubmissionOutcomeSpec


@dataclass(frozen=True)
class TransportSpecV2(FrozenModel):
    version: int
    request: RequestSpecV2
    auth: AuthSpec
    response: ResponseSpec
    outcome: OutcomeSpec
    delivery: SyncSpec | PollSpecV2 | SseSpec
    timeout: TimeoutBudget
    session: SessionSpec
    limits: ResourceLimits
    let: LetSpec

    @classmethod
    def from_dict(cls, data):
        required = set(TransportSpec.__dataclass_fields__)
        object_fields(data, required | {"let"}, required)
        if type(data["version"]) is not int or data["version"] != 2:
            raise ValueError("Unsupported transport version")
        declarations = data.get("let", {})
        object_fields(declarations, {"run", "attempt"})
        visible = set()
        scopes = {}
        for scope in ("run", "attempt"):
            values = declarations.get(scope, {})
            if not isinstance(values, dict) or len(values) > 128:
                raise ValueError("Invalid variable declarations")
            parsed = {}
            for name, expr in values.items():
                _name(name)
                if name in visible:
                    raise ValueError("Duplicate transport variable")
                parsed[name] = value_expr_v2(expr, visible=frozenset(visible))
                visible.add(name)
            scopes[scope] = parsed
        request = RequestSpecV2.from_dict(data["request"], visible=frozenset(visible))
        auth = AuthSpec.from_dict(data["auth"])
        auth_names = {h.name.lower() for h in auth.headers} | (
            {"authorization"} if auth.kind == "bearer" else set()
        )
        if auth_names & {k.lower() for k in request.headers}:
            raise ValueError("Auth and public headers conflict")
        delivery_data = data["delivery"]
        object_fields(
            delivery_data,
            {
                "kind",
                "run_id",
                "request",
                "pending",
                "interval_s",
                "max_polls",
                "submit_http_status",
                "submit_outcome",
                "event_names",
                "data_format",
                "terminal",
                "accumulation",
                "idle_timeout_s",
                "reconnect",
                "delta_selector",
            },
            {"kind"},
        )
        kind = choice(delivery_data["kind"], {"sync", "poll", "sse"})
        if kind == "sync":
            object_fields(delivery_data, {"kind"}, {"kind"})
            delivery = SyncSpec()
        elif kind == "sse":
            envelope = copy.deepcopy(data)
            envelope.pop("let", None)
            envelope["version"] = 1
            envelope["request"] = {
                "url": request.url.replace("{", "").replace("}", ""),
                "body": {"none": True},
            }
            delivery = TransportSpec.from_dict(envelope).delivery
        else:
            fields = {
                "kind",
                "run_id",
                "request",
                "pending",
                "interval_s",
                "max_polls",
                "submit_http_status",
                "submit_outcome",
            }
            object_fields(delivery_data, fields, fields)
            object_fields(delivery_data["run_id"], {"path"}, {"path"})
            path(delivery_data["run_id"]["path"])
            poll_request = RequestSpecV2.from_dict(
                delivery_data["request"], visible=frozenset(visible | {"run_id"})
            )
            if poll_request.method != "GET" or origin(poll_request.url) != origin(
                request.url
            ):
                raise ValueError("Poll origin or method mismatch")
            if poll_request.placeholders.count("run_id") != 1:
                raise ValueError("Poll URL requires one run ID")
            if auth_names & {k.lower() for k in poll_request.headers}:
                raise ValueError("Poll auth and public headers conflict")
            max_polls = delivery_data["max_polls"]
            if type(max_polls) is not int:
                raise ValueError("Invalid poll limit")
            positive(max_polls, 100)
            statuses = delivery_data["submit_http_status"]
            if (
                not isinstance(statuses, list)
                or not statuses
                or any(type(v) is not int or not 200 <= v < 300 for v in statuses)
            ):
                raise ValueError("Invalid submit HTTP status")
            delivery = PollSpecV2(
                kind,
                {"run_id": copy.deepcopy(delivery_data["run_id"])},
                poll_request,
                predicate(delivery_data["pending"]),
                positive(delivery_data["interval_s"]),
                max_polls,
                tuple(statuses),
                SubmissionOutcomeSpec.from_dict(delivery_data["submit_outcome"]),
            )
        limits = ResourceLimits.from_dict(data["limits"])
        outcome = OutcomeSpec.from_dict(data["outcome"])
        if len(outcome.rules) > limits.max_rules:
            raise ValueError("Outcome rules exceed limit")
        return cls(
            2,
            request,
            auth,
            ResponseSpec.from_dict(data["response"]),
            outcome,
            delivery,
            TimeoutBudget.from_dict(data["timeout"]),
            SessionSpec.from_dict(data["session"]),
            limits,
            LetSpec(**scopes),
        )

    def to_dict(self) -> dict:
        delivery = self.delivery
        if isinstance(delivery, PollSpecV2):
            delivery = PollSpec(
                delivery.kind,
                delivery.ids["run_id"],
                _v1_request(delivery.request),
                delivery.pending,
                delivery.interval_s,
                delivery.max_polls,
                delivery.submit_http_status,
                delivery.submit_outcome,
            )
        envelope = TransportSpec(
            1,
            _v1_request(self.request),
            self.auth,
            self.response,
            self.outcome,
            delivery,
            self.timeout,
            self.session,
            self.limits,
        )
        result = envelope.to_dict()
        result["version"] = 2
        result["request"] = _request_dict(self.request)
        if isinstance(self.delivery, PollSpecV2):
            result["delivery"]["request"] = _request_dict(self.delivery.request)
        if self.let.run or self.let.attempt:
            result["let"] = json.loads(
                json.dumps({"run": self.let.run, "attempt": self.let.attempt})
            )
        return result


def _v1_request(request):
    return RequestSpec(request.method, request.url, request.headers, request.body)


def _request_dict(request):
    result = json.loads(
        json.dumps(
            {
                "method": request.method,
                "url": request.url,
                "headers": request.headers,
                "body": request.body,
            }
        )
    )
    if request.query:
        result["query"] = json.loads(json.dumps(request.query))
    return result


def parse_transport_spec(data: dict) -> TransportSpec | TransportSpecV2:
    if not isinstance(data, dict) or type(data.get("version")) is not int:
        raise ValueError("Unsupported transport version")
    if data["version"] == 1:
        return TransportSpec.from_dict(data)
    if data["version"] == 2:
        return TransportSpecV2.from_dict(data)
    raise ValueError("Unsupported transport version")


def iter_requests(spec: TransportSpecV2) -> Iterator[tuple[str, RequestSpecV2]]:
    yield "submit", spec.request
    if isinstance(spec.delivery, PollSpecV2):
        yield "poll", spec.delivery.request


def with_origin(data: dict, override: str) -> dict:
    message = (
        "version 2 endpoint override takes an origin such as http://127.0.0.1:8080"
    )
    try:
        endpoint(override)
        replacement = urlsplit(override)
        if (
            replacement.path not in {"", "/"}
            or replacement.query
            or replacement.fragment
            or "?" in override
            or "#" in override
            or "@" in replacement.netloc
        ):
            raise ValueError(message)
    except (ValueError, TypeError):
        raise ValueError(message) from None
    spec = TransportSpecV2.from_dict(data)
    result = copy.deepcopy(data)
    for owner, request in iter_requests(spec):
        parts = urlsplit(request.url)
        url = urlunsplit(
            (
                replacement.scheme,
                replacement.netloc,
                parts.path,
                parts.query,
                parts.fragment,
            )
        )
        target = (
            result["request"] if owner == "submit" else result["delivery"]["request"]
        )
        target["url"] = url
    TransportSpecV2.from_dict(result)
    return result
