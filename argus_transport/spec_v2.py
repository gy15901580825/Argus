from __future__ import annotations

import copy
import json
import re
from dataclasses import asdict, dataclass, field
from typing import Iterator, Literal
from urllib.parse import urlsplit, urlunsplit

from .models import (
    AuthSpec,
    FrozenModel,
    OutcomeSpec,
    RequestSpec,
    ResourceLimits,
    ResponseSpec,
    SessionSpec,
    SseSpec,
    SubmissionOutcomeSpec,
    SyncSpec,
    TimeoutBudget,
    TransportSpec,
    TransportContext,
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
    _rule_dict,
)

NAME_RE = re.compile(r"[a-z][a-z0-9_]{0,31}\Z")
ENV_NAME_RE = re.compile(r"[A-Z_][A-Z0-9_]{0,63}\Z")
SECRET_WORDS = ("key", "token", "secret", "password", "auth", "header", "cookie")
CONTEXT_KEYS_V2 = frozenset(_CONTEXT_KEYS) | {"material"}
V2_FIELD_NAMES = frozenset(
    {"let", "run", "attempt", "var", "concat", "generate", "base64", "env", "query",
     "lifecycle", "id", "if_present", "expect", "http_status", "when", "capture",
     "undo", "budget", "max_requests", "cleanup_reserve", "cleanup_s",
     "last_segment", "expect_prefix", "ids", "wait", "from", "default_s", "max_s", "location",
     "stop_on", "alert_names", "credential_echo"}
    | {"provision", "find", "create", "manual", "title", "steps", "items", "where",
       "take", "given", "hint", "multipart", "filename", "content_type", "content",
       "confirm", "gone_status"}
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


@dataclass(frozen=True)
class TransportContextV2(TransportContext):
    material: str | None = None


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
    if kind == "context":
        choice(item, CONTEXT_KEYS_V2)
    elif kind == "literal":
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
        object_fields(body, {"json", "text", "none", "multipart"})
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
        elif "multipart" in body:
            parts = body["multipart"]
            if method not in {"POST", "PUT"}:
                raise ValueError("Multipart method must be POST or PUT")
            if not isinstance(parts, dict) or not 1 <= len(parts) <= 4:
                raise ValueError("Multipart requires one to four parts")
            for name, part in parts.items():
                if not isinstance(name, str) or not NAME_RE.fullmatch(name):
                    raise ValueError("Invalid multipart part name")
                object_fields(part, {"filename", "content_type", "content"},
                              {"filename", "content_type", "content"})
                choice(part["content_type"], {"text/plain", "text/markdown", "application/json", "text/csv"})
                value_expr_v2(part["filename"], visible=visible)
                value_expr_v2(part["content"], visible=visible)
        else:
            value_expr_v2(body["text"], visible=visible)
        if method in {"GET", "HEAD"} and body != {"none": True}:
            raise ValueError("GET and HEAD cannot have a body")
        public = headers(data.get("headers", {}))
        content_type = next(
            (v for k, v in public.items() if k.lower() == "content-type"), None
        )
        if content_type is not None and "multipart" in body:
            raise ValueError("Content-Type conflicts with multipart body")
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
class ExpectSpec(FrozenModel):
    http_status: tuple[int, ...]
    when: dict | None = None

    @classmethod
    def from_dict(cls, data):
        object_fields(data, {"http_status", "when"}, {"http_status"})
        statuses = data["http_status"]
        if (
            not isinstance(statuses, list)
            or not statuses
            or any(type(code) is not int or not 100 <= code <= 599 for code in statuses)
        ):
            raise ValueError("Invalid expected HTTP status")
        return cls(tuple(statuses), predicate(data["when"]) if "when" in data else None)


@dataclass(frozen=True)
class CaptureSpec(FrozenModel):
    path: str | None = None
    last_segment: bool = False
    expect_prefix: dict | None = None
    items: str | None = None
    where: dict | None = None
    take: str | None = None

    @classmethod
    def from_dict(cls, data, *, visible):
        object_fields(data, {"path", "items", "where", "take", "last_segment", "expect_prefix"})
        if "path" in data:
            if set(data) & {"items", "where", "take"}:
                raise ValueError("Capture requires one selector variant")
            path(data["path"])
            where = None
        else:
            if not {"items", "where", "take"} <= set(data):
                raise ValueError("Capture requires items, where and take")
            path(data["items"])
            path(data["take"])
            where = _where_predicate(data["where"], visible=visible)
        last_segment = data.get("last_segment", False)
        if type(last_segment) is not bool:
            raise ValueError("Capture last_segment must be boolean")
        prefix = (
            value_expr_v2(data["expect_prefix"], visible=visible)
            if "expect_prefix" in data else None
        )
        return cls(data.get("path"), last_segment, prefix, data.get("items"), where, data.get("take"))


def _where_references(value, location=()):
    for operator in ("all", "any"):
        if operator in value:
            for index, child in enumerate(value[operator]):
                yield from _where_references(child, location + (operator, index))
            return
    if "not" in value:
        yield from _where_references(value["not"], location + ('not',))
        return
    values = [value["equals"]] if "equals" in value else value.get("one_of", [])
    for index, item in enumerate(values):
        if isinstance(item, dict) and (
            set(item) in ({"env"}, {"env", "missing"}, {"var"})
        ):
            yield location + (('equals',) if 'equals' in value else ('one_of', index)), item


def _where_predicate(value, *, visible):
    result = predicate(value)
    for _, reference in _where_references(result):
        value_expr_v2(reference, visible=visible)
    return result


@dataclass(frozen=True)
class ConfirmationSpec(FrozenModel):
    request: RequestSpecV2
    gone_status: tuple[int, ...]

    @classmethod
    def from_dict(cls, data, *, visible):
        object_fields(data, {"request", "gone_status"}, {"request", "gone_status"})
        object_fields(data["request"], {"method", "url", "headers", "body", "query"}, {"url"})
        if data["request"].get("method", "POST") != "GET":
            raise ValueError("Confirmation method must be GET")
        statuses = ExpectSpec.from_dict({"http_status": data["gone_status"]}).http_status
        return cls(RequestSpecV2.from_dict(data["request"], visible=visible), statuses)


@dataclass(frozen=True)
class UndoSpec(FrozenModel):
    request: RequestSpecV2
    expect: ExpectSpec
    confirm: ConfirmationSpec | None = None

    @classmethod
    def from_dict(cls, data, *, visible):
        object_fields(data, {"request", "expect", "confirm"}, {"request", "expect"})
        object_fields(data["request"], {"method", "url", "headers", "body", "query"}, {"url"})
        method = data["request"].get("method", "POST")
        if not isinstance(method, str) or method not in {"DELETE", "GET"}:
            raise ValueError("Undo method must be DELETE or GET")
        return cls(
            RequestSpecV2.from_dict(data["request"], visible=visible),
            ExpectSpec.from_dict(data["expect"]),
            ConfirmationSpec.from_dict(data["confirm"], visible=visible) if "confirm" in data else None,
        )


@dataclass(frozen=True)
class StepSpec(FrozenModel):
    id: str
    if_present: str | None
    request: RequestSpecV2
    expect: ExpectSpec
    capture: dict[str, CaptureSpec]
    undo: UndoSpec | None


@dataclass(frozen=True)
class FindStepSpec(FrozenModel):
    id: str
    request: RequestSpecV2
    expect: ExpectSpec
    capture: dict[str, CaptureSpec]
    given: dict[str, dict] = field(default_factory=dict)
    hint: str | None = None


@dataclass(frozen=True)
class ManualSpec(FrozenModel):
    title: str
    steps: tuple[str, ...]


@dataclass(frozen=True)
class ProvisionSpec(FrozenModel):
    find: tuple[FindStepSpec, ...]
    create: tuple[StepSpec, ...] = ()
    manual: ManualSpec | None = None


@dataclass(frozen=True)
class LifecycleSpec(FrozenModel):
    run: tuple[StepSpec, ...] = ()
    attempt: tuple[StepSpec, ...] = ()
    provision: ProvisionSpec | None = None


@dataclass(frozen=True)
class StopOnSpec(FrozenModel):
    http_status: tuple[int, ...] = (429,)
    alert_names: tuple[str, ...] = ()
    credential_echo: bool = True

    @classmethod
    def from_dict(cls, data):
        object_fields(data, {"http_status", "alert_names", "credential_echo"})
        statuses = data.get('http_status', [429])
        if not isinstance(statuses, list) or any(type(value) is not int or not 100 <= value <= 599
                                                for value in statuses):
            raise ValueError('Invalid stop HTTP status')
        names = data.get('alert_names', [])
        if not isinstance(names, list):
            raise ValueError('Invalid alert names')
        for name in names:
            if not isinstance(name, str) or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name):
                raise ValueError('Invalid alert name')
        echo = data.get('credential_echo', True)
        if type(echo) is not bool:
            raise ValueError('Invalid credential echo switch')
        return cls(tuple(statuses), tuple(names), echo)


@dataclass(frozen=True)
class BudgetSpec(FrozenModel):
    max_requests: int | None = None
    cleanup_reserve: int = 100
    stop_on: StopOnSpec = StopOnSpec()

    @classmethod
    def from_dict(cls, data):
        object_fields(data, {"max_requests", "cleanup_reserve", "stop_on"})
        for name, value in data.items():
            if name == 'stop_on':
                continue
            if type(value) is not int or value < (1 if name == "max_requests" else 0):
                raise ValueError("Invalid request budget")
        return cls(**{name: value for name, value in data.items() if name != 'stop_on'},
                   stop_on=StopOnSpec.from_dict(data.get('stop_on', {})))


@dataclass(frozen=True)
class TimeoutBudgetV2(TimeoutBudget):
    cleanup_s: float = 60

    @classmethod
    def from_dict(cls, data):
        object_fields(data, set(cls.__dataclass_fields__))
        parsed = {
            name: positive(value, 300 if name == "cleanup_s" else 86400)
            for name, value in data.items()
        }
        return cls(**parsed)


def _declare(name, declared):
    _name(name)
    if name in declared:
        raise ValueError("Duplicate transport variable")
    declared.add(name)


def _parse_steps(values, visible, declared):
    if not isinstance(values, list):
        raise ValueError("Invalid lifecycle steps")
    parsed = []
    for data in values:
        object_fields(
            data,
            {"id", "if_present", "request", "expect", "capture", "undo"},
            {"id", "request", "expect"},
        )
        _declare(data["id"], declared)
        guard = data.get("if_present")
        if "if_present" in data and (
            not isinstance(guard, str) or guard not in visible | CONTEXT_KEYS_V2
        ):
            raise ValueError("Step guard is not visible")
        before = frozenset(visible)
        request = RequestSpecV2.from_dict(data["request"], visible=before)
        if request.method not in {"POST", "PUT", "PATCH", "GET", "DELETE"}:
            raise ValueError("Invalid lifecycle step method")
        captures = data.get("capture", {})
        if not isinstance(captures, dict) or len(captures) > 128:
            raise ValueError("Invalid lifecycle captures")
        capture = {}
        for name, selector in captures.items():
            _declare(name, declared)
            capture[name] = CaptureSpec.from_dict(selector, visible=before)
        visible.update(capture)
        undo = (
            UndoSpec.from_dict(data["undo"], visible=frozenset(visible))
            if "undo" in data else None
        )
        parsed.append(
            StepSpec(data["id"], guard, request, ExpectSpec.from_dict(data["expect"]),
                     capture, undo)
        )
    return tuple(parsed)


def _parse_provision(data, visible, declared):
    object_fields(data, {"find", "create", "manual"}, {"find"})
    values = data["find"]
    if not isinstance(values, list) or not values:
        raise ValueError("Provision requires at least one find step")
    found = []
    for step in values:
        if isinstance(step, dict) and "mcp" in step:
            raise ValueError("MCP provision steps are not supported yet")
        object_fields(step, {"id", "request", "expect", "capture", "given", "hint"},
                      {"id", "request", "expect", "capture"})
        _declare(step["id"], declared)
        before = frozenset(visible)
        request = RequestSpecV2.from_dict(step["request"], visible=before)
        if request.method != "GET":
            raise ValueError("Find method must be GET")
        captures = step["capture"]
        if not isinstance(captures, dict) or not 1 <= len(captures) <= 128:
            raise ValueError("Find requires captures")
        capture = {}
        for name, selector in captures.items():
            _declare(name, declared)
            capture[name] = CaptureSpec.from_dict(selector, visible=before)
        given = step.get("given", {})
        if not isinstance(given, dict) or ("given" in step and set(given) != set(capture)):
            raise ValueError("Given names must equal capture names")
        parsed_given = {name: value_expr_v2(expr, visible=before) for name, expr in given.items()}
        hint = text(step["hint"]) if "hint" in step else None
        found.append(FindStepSpec(step["id"], request, ExpectSpec.from_dict(step["expect"]),
                                  capture, parsed_given, hint))
        visible.update(capture)
    creates = data.get("create", [])
    if not isinstance(creates, list):
        raise ValueError("Invalid provision create steps")
    for step in creates:
        if isinstance(step, dict) and "mcp" in step:
            raise ValueError("MCP provision steps are not supported yet")
        if isinstance(step, dict) and ("undo" in step or "if_present" in step):
            raise ValueError("Provision create cannot have undo or a guard")
    created = _parse_steps(creates, visible, declared)
    if any(step.request.method not in {"POST", "PUT"} for step in created):
        raise ValueError("Provision create method must be POST or PUT")
    manual = None
    if "manual" in data:
        item = data["manual"]
        object_fields(item, {"title", "steps"}, {"title", "steps"})
        if not isinstance(item["steps"], list):
            raise ValueError("Invalid manual steps")
        manual = ManualSpec(text(item["title"]), tuple(text(value) for value in item["steps"]))
    return ProvisionSpec(tuple(found), created, manual)


@dataclass(frozen=True)
class WaitSpec(FrozenModel):
    header: str
    default_s: float
    max_s: float

    @classmethod
    def from_dict(cls, data):
        object_fields(data, {'from', 'default_s', 'max_s'}, {'from', 'default_s', 'max_s'})
        header = choice(data['from'], {'Retry-After'})
        default = positive(data['default_s'])
        maximum = positive(data['max_s'])
        return cls(header, default, maximum)


@dataclass(frozen=True)
class PollSpecV2(FrozenModel):
    kind: str
    ids: dict[str, dict]
    request: RequestSpecV2
    pending: dict
    interval_s: float | None
    max_polls: int
    submit_http_status: tuple[int, ...]
    submit_outcome: SubmissionOutcomeSpec
    wait: WaitSpec | None = None
    location: Literal['ignore', 'verify'] = 'ignore'
    _run_id_sugar: bool = field(default=False, compare=False, repr=False)


@dataclass(frozen=True)
class TransportSpecV2(FrozenModel):
    version: int
    request: RequestSpecV2
    auth: AuthSpec
    response: ResponseSpec
    outcome: OutcomeSpec
    delivery: SyncSpec | PollSpecV2 | SseSpec
    timeout: TimeoutBudgetV2
    session: SessionSpec
    limits: ResourceLimits
    let: LetSpec
    lifecycle: LifecycleSpec
    budget: BudgetSpec

    @classmethod
    def from_dict(cls, data):
        required = set(TransportSpec.__dataclass_fields__)
        object_fields(data, required | {"let", "lifecycle", "budget"}, required)
        if type(data["version"]) is not int or data["version"] != 2:
            raise ValueError("Unsupported transport version")
        declarations = data.get("let", {})
        object_fields(declarations, {"run", "attempt"})
        visible = set()
        declared = set()
        scopes = {}
        lifecycle_data = data.get("lifecycle", {})
        object_fields(lifecycle_data, {"run", "attempt", "provision"})
        steps = {}
        provision = None
        for scope in ("run", "attempt"):
            values = declarations.get(scope, {})
            if not isinstance(values, dict) or len(values) > 128:
                raise ValueError("Invalid variable declarations")
            parsed = {}
            for name, expr in values.items():
                _declare(name, declared)
                parsed[name] = value_expr_v2(expr, visible=frozenset(visible))
                visible.add(name)
            scopes[scope] = parsed
            if scope == "run" and "provision" in lifecycle_data:
                provision = _parse_provision(lifecycle_data["provision"], visible, declared)
            steps[scope] = _parse_steps(lifecycle_data.get(scope, []), visible, declared)
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
                "ids",
                "wait",
                "location",
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
        timeout = TimeoutBudgetV2.from_dict(data["timeout"])
        kind = choice(delivery_data["kind"], {"sync", "poll", "sse"})
        if kind == "sync":
            object_fields(delivery_data, {"kind"}, {"kind"})
            delivery = SyncSpec()
        elif kind == "sse":
            envelope = copy.deepcopy(data)
            envelope.pop("let", None)
            envelope.pop("lifecycle", None)
            envelope.pop("budget", None)
            envelope["timeout"].pop("cleanup_s", None)
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
                "ids",
                "wait",
                "location",
                "request",
                "pending",
                "interval_s",
                "max_polls",
                "submit_http_status",
                "submit_outcome",
            }
            object_fields(delivery_data, fields, fields - {'run_id', 'ids', 'interval_s', 'wait', 'location'})
            if ('ids' in delivery_data) == ('run_id' in delivery_data):
                raise ValueError('Poll requires either ids or run_id')
            if ('wait' in delivery_data) == ('interval_s' in delivery_data):
                raise ValueError('Poll requires either wait or interval_s')
            location = choice(delivery_data.get('location', 'ignore'), {'ignore', 'verify', 'follow'})
            if location == 'follow':
                raise ValueError('location follow is not supported yet')
            sugar = 'run_id' in delivery_data
            ids = {'run_id': delivery_data['run_id']} if sugar else delivery_data['ids']
            if not isinstance(ids, dict) or not 1 <= len(ids) <= 4:
                raise ValueError('Poll requires one to four IDs')
            parsed_ids = {}
            for name, selector in ids.items():
                if name != 'run_id':
                    _name(name)
                if name in declared:
                    raise ValueError('Duplicate transport variable')
                if sugar:
                    object_fields(selector, {'path'}, {'path'})
                CaptureSpec.from_dict(selector, visible=frozenset(visible))
                if 'path' not in selector:
                    raise ValueError('Delivery IDs require path selectors')
                parsed_ids[name] = copy.deepcopy(selector)
            poll_request = RequestSpecV2.from_dict(
                delivery_data['request'], visible=frozenset(visible | set(ids))
            )
            if poll_request.method != "GET" or origin(poll_request.url) != origin(
                request.url
            ):
                raise ValueError("Poll origin or method mismatch")
            if any(poll_request.placeholders.count(name) != 1 for name in ids):
                raise ValueError('Poll URL requires each ID exactly once')
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
                parsed_ids,
                poll_request,
                predicate(delivery_data["pending"]),
                positive(delivery_data['interval_s']) if 'interval_s' in delivery_data else None,
                max_polls,
                tuple(statuses),
                SubmissionOutcomeSpec.from_dict(delivery_data['submit_outcome']),
                WaitSpec.from_dict(delivery_data['wait']) if 'wait' in delivery_data else None,
                location,
                sugar,
            )
        limits = ResourceLimits.from_dict(data["limits"])
        outcome = OutcomeSpec.from_dict(data["outcome"])
        if len(outcome.rules) > limits.max_rules:
            raise ValueError("Outcome rules exceed limit")
        result = cls(
            2,
            request,
            auth,
            ResponseSpec.from_dict(data["response"]),
            outcome,
            delivery,
            timeout,
            SessionSpec.from_dict(data["session"]),
            limits,
            LetSpec(**scopes),
            LifecycleSpec(**steps, provision=provision),
            BudgetSpec.from_dict(data.get("budget", {})),
        )
        for _, item in iter_requests(result):
            if origin(item.url) != origin(request.url):
                raise ValueError("Lifecycle origin mismatch")
            if auth_names & {name.lower() for name in item.headers}:
                raise ValueError("Auth and public headers conflict")
        return result

    def to_dict(self) -> dict:
        delivery = self.delivery
        if isinstance(delivery, PollSpecV2):
            delivery = SyncSpec()
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
        if self.timeout.cleanup_s == 60:
            result["timeout"].pop("cleanup_s", None)
        if self.lifecycle.run or self.lifecycle.attempt or self.lifecycle.provision:
            result["lifecycle"] = {
                scope: [_step_dict(step) for step in getattr(self.lifecycle, scope)]
                for scope in ("run", "attempt") if getattr(self.lifecycle, scope)
            }
            if self.lifecycle.provision is not None:
                provision = self.lifecycle.provision
                value = {"find": [_find_dict(step) for step in provision.find]}
                if provision.create:
                    value["create"] = [_step_dict(step) for step in provision.create]
                if provision.manual is not None:
                    value["manual"] = {"title": provision.manual.title, "steps": list(provision.manual.steps)}
                result["lifecycle"]["provision"] = value
        if self.budget != BudgetSpec():
            result["budget"] = {
                name: value for name, value in asdict(self.budget).items() if name != 'stop_on'
                if value != getattr(BudgetSpec(), name)
            }
            if self.budget.stop_on != StopOnSpec():
                stop = self.budget.stop_on
                result['budget']['stop_on'] = {'http_status': list(stop.http_status),
                                             'alert_names': list(stop.alert_names),
                                             'credential_echo': stop.credential_echo}
        if isinstance(self.delivery, PollSpecV2):
            poll = self.delivery
            result['delivery'] = {
                'kind': poll.kind,
                'request': _request_dict(poll.request),
                'pending': json.loads(json.dumps(poll.pending)),
                'max_polls': poll.max_polls,
                'submit_http_status': list(poll.submit_http_status),
                'submit_outcome': {
                    'kind': poll.submit_outcome.kind,
                    'unmatched': poll.submit_outcome.unmatched,
                    'rules': [_rule_dict(rule) for rule in poll.submit_outcome.rules],
                },
            }
            if poll._run_id_sugar:
                result['delivery']['run_id'] = json.loads(json.dumps(poll.ids['run_id']))
            else:
                result['delivery']['ids'] = json.loads(json.dumps(poll.ids))
            if poll.wait is not None:
                result['delivery']['wait'] = {'from': poll.wait.header,
                                            'default_s': poll.wait.default_s, 'max_s': poll.wait.max_s}
            else:
                result['delivery']['interval_s'] = poll.interval_s
            if poll.location != 'ignore':
                result['delivery']['location'] = poll.location
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


@dataclass(frozen=True)
class _RequestOwner(FrozenModel):
    owner: str
    path: tuple[str | int, ...]
    request: RequestSpecV2
    guard: str | None = None


@dataclass(frozen=True)
class _ExpressionOwner(FrozenModel):
    owner: str
    path: tuple[str | int, ...]
    expression: dict
    guard: str | None = None


def _iter_owners(spec):
    yield _RequestOwner("submit", ("request",), spec.request)
    if isinstance(spec.delivery, PollSpecV2):
        yield _RequestOwner('poll', ('delivery', 'request'), spec.delivery.request)
        for name, selector in spec.delivery.ids.items():
            if 'expect_prefix' in selector:
                yield _ExpressionOwner('delivery_id', ('delivery', 'ids', name, 'expect_prefix'),
                                       selector['expect_prefix'])
    for scope in ("run", "attempt"):
        for name, expression in getattr(spec.let, scope).items():
            yield _ExpressionOwner("let", ("let", scope, name), expression)
        if scope == 'run' and spec.lifecycle.provision is not None:
            for group in ('find', 'create'):
                for index, step in enumerate(getattr(spec.lifecycle.provision, group)):
                    location = ('lifecycle', 'provision', group, index)
                    yield _RequestOwner('provision', location + ('request',), step.request)
                    yield from _capture_owners(step.capture, location, 'provision')
                    if isinstance(step, FindStepSpec):
                        for name, expression in step.given.items():
                            yield _ExpressionOwner('provision', location + ('given', name), expression)
        for index, step in enumerate(getattr(spec.lifecycle, scope)):
            location = ("lifecycle", scope, index)
            yield _RequestOwner("setup", location + ("request",), step.request, step.if_present)
            yield from _capture_owners(step.capture, location, 'capture', step.if_present)
            if step.undo:
                yield _RequestOwner("cleanup", location + ("undo", "request"),
                                    step.undo.request, step.if_present)
                if step.undo.confirm is not None:
                    yield _RequestOwner('cleanup', location + ('undo', 'confirm', 'request'),
                                        step.undo.confirm.request, step.if_present)


def _capture_owners(captures, location, owner, guard=None):
    for name, capture in captures.items():
        if capture.expect_prefix is not None:
            yield _ExpressionOwner(owner, location + ('capture', name, 'expect_prefix'),
                                   capture.expect_prefix, guard)
        if capture.where is not None:
            for expression_path, expression in _where_references(capture.where):
                yield _ExpressionOwner(owner, location + ('capture', name, 'where') + expression_path,
                                       expression, guard)


def iter_requests(spec: TransportSpecV2) -> Iterator[tuple[str, RequestSpecV2]]:
    for item in _iter_owners(spec):
        if isinstance(item, _RequestOwner):
            yield item.owner, item.request


def _iter_expressions(spec):
    for item in _iter_owners(spec):
        if isinstance(item, _ExpressionOwner):
            yield item
            continue
        for name, expression in item.request.query.items():
            yield _ExpressionOwner(item.owner, item.path + ("query", name), expression, item.guard)
        body = item.request.body
        if "json" in body:
            for name, expression in body["json"].items():
                yield _ExpressionOwner(item.owner, item.path + ("body", "json", name), expression, item.guard)
        elif "text" in body:
            yield _ExpressionOwner(item.owner, item.path + ("body", "text"), body["text"], item.guard)
        elif "multipart" in body:
            for name, part in body['multipart'].items():
                for field_name in ('filename', 'content'):
                    yield _ExpressionOwner(item.owner, item.path + ('body', 'multipart', name, field_name),
                                           part[field_name], item.guard)


def _expect_dict(expect):
    result = {"http_status": list(expect.http_status)}
    if expect.when is not None:
        result["when"] = json.loads(json.dumps(expect.when))
    return result


def _step_dict(step):
    result = {"id": step.id, "request": _request_dict(step.request),
              "expect": _expect_dict(step.expect)}
    if step.if_present is not None:
        result["if_present"] = step.if_present
    if step.capture:
        captures = {}
        for name, capture in step.capture.items():
            selector = ({"path": capture.path} if capture.path is not None else
                        {"items": capture.items, "where": json.loads(json.dumps(capture.where)), "take": capture.take})
            if capture.last_segment:
                selector["last_segment"] = True
            if capture.expect_prefix is not None:
                selector["expect_prefix"] = json.loads(json.dumps(capture.expect_prefix))
            captures[name] = selector
        result["capture"] = captures
    if step.undo:
        result["undo"] = {"request": _request_dict(step.undo.request),
                          "expect": _expect_dict(step.undo.expect)}
        if step.undo.confirm is not None:
            result['undo']['confirm'] = {'request': _request_dict(step.undo.confirm.request),
                                         'gone_status': list(step.undo.confirm.gone_status)}
    return result


def _find_dict(step):
    result = _step_dict(StepSpec(step.id, None, step.request, step.expect, step.capture, None))
    if step.given:
        result['given'] = json.loads(json.dumps(step.given))
    if step.hint is not None:
        result['hint'] = step.hint
    return result


def provision_checklist(spec: TransportSpecV2, *, step_id: str | None, hint: str | None) -> list[str]:
    result = []
    if step_id is not None:
        result.append(f"NOT PROVISIONED: find step '{step_id}' matched no item (0 business requests sent)")
        if hint is not None:
            result.append(f'Hint: {hint}')
    provision = spec.lifecycle.provision
    if provision is None:
        return result
    if provision.manual is not None:
        result.append(provision.manual.title)
        result.extend(f'[ ] {step}' for step in provision.manual.steps)
    result.append('Derived from the config:')

    for step in provision.find:
        env_names = [expr['env'] for expr in step.given.values() if 'env' in expr]
        suffix = f" (skipped when ${env_names[0]} is set)" if env_names else ''
        for capture in step.capture.values():
            if capture.where is None:
                continue
            if set(capture.where) == {'path', 'equals'}:
                item_path, literal = capture.where['path'], capture.where['equals']
                if isinstance(literal, dict) and set(literal) in ({'env'}, {'env', 'missing'}, {'var'}):
                    display = '$' + literal.get('env', literal.get('var'))
                else:
                    display = literal if isinstance(literal, str) else json.dumps(literal)
                result.append(f'[ ] Exactly one item in {capture.items} has {item_path} = {display}{suffix}')
            else:
                result.append(f'[ ] Exactly one item in {capture.items} matches the complete configured filter.{suffix}')
    bindings = {}

    def collect(expr, location):
        if expr.get('context') in {'prompt', 'material'}:
            bindings.setdefault(expr['context'], '.'.join(location))
        for name, child in expr.get('object', {}).items():
            collect(child, (*location, name))
        for child in expr.get('array', expr.get('concat', [])):
            collect(child, location)
        if 'base64' in expr:
            collect(expr['base64'], location)

    for name, expr in spec.request.body.get('json', {}).items():
        collect(expr, (name,))
    if 'prompt' in bindings:
        line = f"[ ] Argus sends the prompt to {bindings['prompt']}"
        if 'material' in bindings:
            line += f" and the material to {bindings['material']}"
        result.append(line + '.')
    return result


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
    for item in _iter_owners(spec):
        if not isinstance(item, _RequestOwner):
            continue
        request = item.request
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
        target = result
        for component in item.path:
            target = target[component]
        target["url"] = url
    TransportSpecV2.from_dict(result)
    return result


def material_binding(spec: TransportSpecV2) -> Literal["none", "optional", "required"]:
    def references(expression):
        if expression.get("context") == "material":
            yield expression.get("missing") != "omit"
        elif "base64" in expression:
            yield from references(expression["base64"])
        elif "object" in expression:
            for child in expression["object"].values():
                yield from references(child)
        elif "array" in expression or "concat" in expression:
            for child in expression.get("array", expression.get("concat", ())):
                yield from references(child)

    binding: Literal["none", "optional", "required"] = "none"
    for item in _iter_expressions(spec):
        for required in references(item.expression):
            if required and item.guard != "material":
                return "required"
            binding = "optional"
    return binding
