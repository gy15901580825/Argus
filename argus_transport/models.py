from __future__ import annotations

import copy
import json
import math
import re
from dataclasses import asdict, dataclass, field, fields
from enum import Enum
from typing import Any, Literal, NotRequired, TypeAlias, TypedDict
from urllib.parse import urlsplit

ContextKey: TypeAlias = Literal[
    "prompt", "scenario_url", "history", "conversation_id", "session_id", "run_id"
]
MetadataKey: TypeAlias = Literal["session_id", "run_id", "run_log", "latency_ms"]
JsonValue: TypeAlias = (
    str | int | float | bool | None | list["JsonValue"] | dict[str, "JsonValue"]
)


class LiteralValue(TypedDict):
    literal: JsonValue


class ContextValue(TypedDict):
    context: ContextKey
    missing: NotRequired[Literal["error", "omit"]]


class ObjectValue(TypedDict):
    object: dict[str, "ValueExpr"]


class ArrayValue(TypedDict):
    array: list["ValueExpr"]


ValueExpr: TypeAlias = LiteralValue | ContextValue | ObjectValue | ArrayValue


class JsonBody(TypedDict):
    json: dict[str, ValueExpr]


class TextBody(TypedDict):
    text: ValueExpr


class NoBody(TypedDict):
    none: Literal[True]


class ResponseMetadata(TypedDict, total=False):
    session_id: str
    run_id: str | int
    run_log: JsonValue
    latency_ms: float


_CONTEXT_KEYS = {
    "prompt",
    "scenario_url",
    "history",
    "conversation_id",
    "session_id",
    "run_id",
}
_CONTROL_HEADERS = {
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "upgrade",
    "proxy-authorization",
    "accept-encoding",
}
_PATH = re.compile(r"\$(?:\.[A-Za-z_][\w-]*|\[\d+\]|\['[^'\r\n]+'\])*\Z")


class FrozenDict(dict):
    def _immutable(self, *args, **kwargs):
        raise TypeError("Transport data is immutable")

    __setitem__ = __delitem__ = clear = pop = popitem = setdefault = update = (
        __ior__
    ) = _immutable

    def __deepcopy__(self, memo):
        return self


def freeze(value):
    if isinstance(value, dict):
        return FrozenDict((key, freeze(item)) for key, item in value.items())
    if isinstance(value, (tuple, list)):
        return tuple(freeze(item) for item in value)
    return value


class FrozenModel:
    def __post_init__(self):
        for item in fields(self):
            object.__setattr__(self, item.name, freeze(getattr(self, item.name)))


def object_fields(value, allowed, required=()):
    if (
        not isinstance(value, dict)
        or set(value) - set(allowed)
        or set(required) - set(value)
    ):
        raise ValueError("Invalid transport fields")
    return value


def text(value):
    if not isinstance(value, str) or not value:
        raise ValueError("Expected nonempty string")
    return value


def choice(value, options):
    if not isinstance(value, str) or value not in options:
        raise ValueError("Invalid transport variant")
    return value


def positive(value, maximum=None):
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value <= 0
    ):
        raise ValueError("Expected positive finite number")
    if maximum is not None and value > maximum:
        raise ValueError("Transport resource limit exceeds maximum")
    return value


def path(value, legacy=False):
    text(value)
    if not legacy and not _PATH.fullmatch(value):
        raise ValueError("Unsupported transport JSONPath")
    from jsonpath_ng import parse

    try:
        parse(value)
    except Exception as exc:
        raise ValueError("Invalid transport JSONPath") from exc
    return value


def headers(value):
    if not isinstance(value, dict):
        raise ValueError("Invalid headers")
    names = set()
    for name, val in value.items():
        header_name(name)
        if (
            name.lower() in names
            or name.lower() in _CONTROL_HEADERS
            or not isinstance(val, str)
            or "\r" in val
            or "\n" in val
        ):
            raise ValueError("Invalid or reserved header")
        names.add(name.lower())
    return dict(value)


def header_name(name):
    if not isinstance(name, str) or not re.fullmatch(
        r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name
    ):
        raise ValueError("Invalid header name")
    if name.lower() in _CONTROL_HEADERS:
        raise ValueError("Reserved header")
    return name


def endpoint(value, poll=False):
    text(value)
    try:
        p = urlsplit(value)
        port = p.port
    except ValueError as exc:
        raise ValueError("Invalid transport endpoint") from exc
    if (
        p.scheme not in {"http", "https"}
        or not p.hostname
        or p.username
        or p.password
        or p.fragment
    ):
        raise ValueError("Invalid transport endpoint")
    if "\r" in value or "\n" in value or "\\" in value:
        raise ValueError("Invalid transport endpoint")
    if "{" in value or "}" in value:
        if (
            not poll
            or p.path.count("{run_id}") != 1
            or "{" in value.replace("{run_id}", "")
            or "}" in value.replace("{run_id}", "")
        ):
            raise ValueError("Endpoint variables must be a run ID path segment")
        if "{run_id}" not in p.path.split("/"):
            raise ValueError("Run ID must occupy one path segment")
    return value


def value_expr(value, depth=0):
    if depth > 16:
        raise ValueError("Binding nesting exceeds maximum")
    object_fields(value, {"literal", "context", "missing", "object", "array"})
    kinds = set(value) & {"literal", "context", "object", "array"}
    if len(kinds) != 1 or ("missing" in value and "context" not in kinds):
        raise ValueError("Binding requires one variant")
    kind = next(iter(kinds))
    if kind == "context":
        choice(value[kind], _CONTEXT_KEYS)
        choice(value.get("missing", "error"), {"error", "omit"})
    elif kind == "object":
        if not isinstance(value[kind], dict) or len(value[kind]) > 128:
            raise ValueError("Invalid object binding")
        for key, item in value[kind].items():
            text(key)
            value_expr(item, depth + 1)
    elif kind == "array":
        if not isinstance(value[kind], list) or len(value[kind]) > 128:
            raise ValueError("Invalid array binding")
        for item in value[kind]:
            value_expr(item, depth + 1)
    else:
        import json

        try:
            json.dumps(value[kind], allow_nan=False)
        except (TypeError, ValueError) as exc:
            raise ValueError("Invalid literal JSON") from exc
    return copy.deepcopy(value)


def predicate(value, depth=0):
    if depth > 16:
        raise ValueError("Predicate nesting exceeds maximum")
    object_fields(value, {"path", "equals", "one_of", "exists", "all", "any", "not"})
    logical = set(value) & {"all", "any", "not"}
    if logical:
        if len(value) != 1:
            raise ValueError("Predicate requires one variant")
        kind = next(iter(logical))
        items = [value[kind]] if kind == "not" else value[kind]
        if not isinstance(items, list) or not items or len(items) > 32:
            raise ValueError("Invalid predicate list")
        for item in items:
            predicate(item, depth + 1)
    else:
        if "path" not in value or len(value) != 2:
            raise ValueError("Predicate requires path and operator")
        path(value["path"])
        operator = next(k for k in value if k != "path")
        if operator not in {"equals", "one_of", "exists"}:
            raise ValueError("Invalid predicate operator")
        if operator == "exists" and not isinstance(value[operator], bool):
            raise ValueError("Invalid exists predicate")
        if operator == "one_of" and (
            not isinstance(value[operator], list)
            or not value[operator]
            or len(value[operator]) > 128
        ):
            raise ValueError("Invalid one_of predicate")
    return copy.deepcopy(value)


class TransportOutcome(str, Enum):
    SUCCEEDED = "succeeded"
    BLOCKED = "blocked"
    TARGET_ERROR = "target_error"
    TIMED_OUT = "timed_out"


class SafeReasonCode(str, Enum):
    OK = "ok"
    TARGET_REFUSAL = "target_refusal"
    TARGET_ERROR = "target_error"
    TIMEOUT = "timeout"
    HTTP_ERROR = "http_error"
    UNKNOWN_STATUS = "unknown_status"
    MAPPING_ERROR = "mapping_error"
    PARSE_ERROR = "parse_error"
    SECRET_ERROR = "secret_error"
    ENDPOINT_ERROR = "endpoint_error"
    BINDING_ERROR = "binding_error"
    RESPONSE_LIMIT = "response_limit"
    UNSUPPORTED_DELIVERY = "unsupported_delivery"
    NETWORK_ERROR = "network_error"
    POLL_LIMIT = "poll_limit"
    SETUP_FAILED = "setup_failed"
    ID_PREFIX_MISMATCH = "id_prefix_mismatch"
    MISSING_ID = "missing_id"
    POLL_WAIT_LIMIT = "poll_wait_limit"
    POLL_IDENTITY_CHANGED = "poll_identity_changed"
    LOCATION_MISSING = "location_missing"


@dataclass(frozen=True)
class RequestSpec(FrozenModel):
    method: str
    url: str
    headers: dict[str, str]
    body: JsonBody | TextBody | NoBody

    @classmethod
    def from_dict(cls, data, poll=False):
        object_fields(data, {"method", "url", "headers", "body"}, {"url"})
        method = choice(
            data.get("method", "POST"),
            {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"},
        )
        body = data.get("body", {"none": True} if method in {"GET", "HEAD"} else None)
        object_fields(body, {"json", "text", "none"})
        if len(body) != 1:
            raise ValueError("Body requires one variant")
        if "none" in body:
            if body["none"] is not True:
                raise ValueError("Invalid empty body")
        elif "json" in body:
            if not isinstance(body["json"], dict) or len(body["json"]) > 128:
                raise ValueError("Invalid JSON body")
            for key, item in body["json"].items():
                text(key)
                value_expr(item)
        else:
            value_expr(body["text"])
        if method in {"GET", "HEAD"} and body != {"none": True}:
            raise ValueError("GET and HEAD cannot have a body")
        hs = headers(data.get("headers", {}))
        content_type = next(
            (v for k, v in hs.items() if k.lower() == "content-type"), None
        )
        if (
            content_type
            and "json" in body
            and content_type.split(";")[0].strip().lower() != "application/json"
        ):
            raise ValueError("Content-Type conflicts with body")
        return cls(method, endpoint(data["url"], poll), hs, copy.deepcopy(body))


@dataclass(frozen=True)
class SecretRef(FrozenModel):
    source: str
    name: str | None = None
    path: str | None = None
    strip_final_newline: bool = False

    @classmethod
    def from_dict(cls, data):
        object_fields(
            data, {"source", "name", "path", "strip_final_newline"}, {"source"}
        )
        source = choice(data["source"], {"env", "file"})
        required = "name" if source == "env" else "path"
        if required not in data or ("path" if source == "env" else "name") in data:
            raise ValueError("Invalid secret reference")
        text(data[required])
        if not isinstance(data.get("strip_final_newline", False), bool):
            raise ValueError("Invalid newline option")
        return cls(
            source,
            data.get("name"),
            data.get("path"),
            data.get("strip_final_newline", False),
        )


@dataclass(frozen=True)
class AuthHeader(FrozenModel):
    name: str
    secret: SecretRef


@dataclass(frozen=True)
class AuthSpec(FrozenModel):
    kind: str
    headers: tuple[AuthHeader, ...] = ()
    secret: SecretRef | None = None

    @classmethod
    def from_dict(cls, data):
        object_fields(data, {"kind", "headers", "secret"}, {"kind"})
        kind = choice(data["kind"], {"none", "headers", "bearer"})
        if kind == "none":
            if len(data) != 1:
                raise ValueError("none auth cannot carry credentials")
            return cls(kind)
        if kind == "bearer":
            if set(data) != {"kind", "secret"}:
                raise ValueError("Invalid bearer auth")
            return cls(kind, secret=SecretRef.from_dict(data["secret"]))
        if (
            set(data) != {"kind", "headers"}
            or not isinstance(data["headers"], list)
            or not data["headers"]
            or len(data["headers"]) > 32
        ):
            raise ValueError("Invalid auth headers")
        auth = []
        names = set()
        for item in data["headers"]:
            object_fields(item, {"name", "secret"}, {"name", "secret"})
            name = header_name(item["name"])
            if name.lower() in names:
                raise ValueError("Duplicate auth header")
            names.add(name.lower())
            auth.append(AuthHeader(name, SecretRef.from_dict(item["secret"])))
        return cls(kind, tuple(auth))


@dataclass(frozen=True)
class TextSelector(FrozenModel):
    paths: tuple[str, ...]
    cast: str
    empty: str = "error"


@dataclass(frozen=True)
class MetadataSelector(FrozenModel):
    path: str
    required: bool = False


@dataclass(frozen=True)
class ResponseSpec(FrozenModel):
    format: str
    text: TextSelector
    metadata: dict[MetadataKey, MetadataSelector] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data):
        object_fields(data, {"format", "text", "metadata"}, {"format", "text"})
        fmt = choice(data["format"], {"json", "text"})
        ts = data["text"]
        object_fields(ts, {"paths", "cast", "empty"})
        cast = choice(ts.get("cast", "string"), {"string", "string_or_json"})
        choice(ts.get("empty", "error"), {"error"})
        paths = ts.get("paths", [])
        if not isinstance(paths, list) or len(paths) > 32:
            raise ValueError("Invalid text paths")
        if fmt == "json" and not paths:
            raise ValueError("JSON response requires paths")
        if fmt == "text" and (
            "paths" in ts or cast != "string" or data.get("metadata")
        ):
            raise ValueError("Invalid text response mapping")
        for p in paths:
            path(p)
        metadata = data.get("metadata", {})
        object_fields(metadata, {"session_id", "run_id", "run_log", "latency_ms"})
        parsed = {}
        for key, item in metadata.items():
            object_fields(item, {"path", "required"}, {"path"})
            if not isinstance(item.get("required", False), bool):
                raise ValueError("Invalid metadata requirement")
            parsed[key] = MetadataSelector(
                path(item["path"]), item.get("required", False)
            )
        return cls(fmt, TextSelector(tuple(paths), cast), parsed)


@dataclass(frozen=True)
class OutcomeRule(FrozenModel):
    id: str
    priority: int
    http_status: tuple[int, ...]
    when: dict
    outcome: TransportOutcome


@dataclass(frozen=True)
class OutcomeSpec(FrozenModel):
    kind: str
    rules: tuple[OutcomeRule, ...] = ()
    unmatched: str = "target_error"

    @classmethod
    def from_dict(cls, data):
        return cls._parse_dict(data, submission=False)

    @classmethod
    def _parse_dict(cls, data, *, submission):
        object_fields(data, {"kind", "rules", "unmatched"}, {"kind"})
        kind = choice(data["kind"], {"rules"} if submission else {"rules", "http_only"})
        if kind == "http_only":
            if len(data) != 1:
                raise ValueError("http_only cannot carry rules")
            return cls(kind)
        object_fields(
            data, {"kind", "rules", "unmatched"}, {"kind", "rules", "unmatched"}
        )
        choice(
            data.get("unmatched", "target_error"),
            {"accepted", "target_error"} if submission else {"target_error"},
        )
        items = data.get("rules", [])
        if not isinstance(items, list) or len(items) > 32:
            raise ValueError("Invalid outcome rules")
        ids = set()
        priorities = set()
        rules = []
        for item in items:
            object_fields(
                item,
                {"id", "priority", "http_status", "when", "outcome"},
                {"id", "priority", "http_status", "when", "outcome"},
            )
            rid = text(item["id"])
            pri = item["priority"]
            statuses = item["http_status"]
            if (
                rid in ids
                or not isinstance(pri, int)
                or isinstance(pri, bool)
                or pri in priorities
            ):
                raise ValueError("Duplicate or invalid outcome priority")
            if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", rid):
                raise ValueError("Invalid rule ID")
            if (
                not isinstance(statuses, list)
                or not statuses
                or any(
                    isinstance(x, bool) or not isinstance(x, int) or not 100 <= x <= 599
                    for x in statuses
                )
            ):
                raise ValueError("Invalid HTTP status list")
            outcome = TransportOutcome(item["outcome"])
            if outcome == TransportOutcome.TIMED_OUT:
                raise ValueError("Body rules cannot claim a timeout")
            ids.add(rid)
            priorities.add(pri)
            rules.append(
                OutcomeRule(rid, pri, tuple(statuses), predicate(item["when"]), outcome)
            )
        return cls(
            kind,
            tuple(sorted(rules, key=lambda r: -r.priority)),
            data.get("unmatched", "target_error"),
        )


class SubmissionProgress(str, Enum):
    ACCEPTED = "accepted"


@dataclass(frozen=True)
class SubmissionOutcomeSpec(OutcomeSpec):
    unmatched: Literal["accepted", "target_error"] = "accepted"

    @classmethod
    def from_dict(cls, data):
        return cls._parse_dict(data, submission=True)


@dataclass(frozen=True)
class TimeoutBudget(FrozenModel):
    total_deadline_s: float = 300
    connect_s: float = 10
    read_s: float = 300
    write_s: float = 30
    pool_s: float = 10
    cleanup_grace_s: float = 2

    @classmethod
    def from_dict(cls, data):
        keys = set(cls.__dataclass_fields__)
        object_fields(data, keys)
        parsed = {key: positive(value, 86400) for key, value in data.items()}
        return cls(**parsed)


@dataclass(frozen=True)
class ResourceLimits(FrozenModel):
    response_bytes: int = 8388608
    event_bytes: int = 1048576
    max_events: int = 1024
    max_rules: int = 32

    @classmethod
    def from_dict(cls, data):
        object_fields(data, set(cls.__dataclass_fields__))
        for key, value in data.items():
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError("Resource limits must be integers")
            positive(value, getattr(cls(), key))
        return cls(**data)


@dataclass(frozen=True)
class SessionSpec(FrozenModel):
    mode: str = "none"
    id_path: str | None = None

    @classmethod
    def from_dict(cls, data):
        object_fields(data, {"mode", "id_path"}, {"mode"})
        mode = choice(data["mode"], {"none", "client_generated", "server_returned"})
        if mode == "server_returned":
            if "id_path" not in data:
                raise ValueError("Server session requires an ID path")
            path(data["id_path"])
        elif "id_path" in data:
            raise ValueError("Unexpected session path")
        return cls(mode, data.get("id_path"))


@dataclass(frozen=True)
class SyncSpec(FrozenModel):
    kind: str = "sync"


@dataclass(frozen=True)
class PollSpec(FrozenModel):
    kind: str
    run_id: dict
    request: RequestSpec
    pending: dict
    interval_s: float
    max_polls: int
    submit_http_status: tuple[int, ...]
    submit_outcome: SubmissionOutcomeSpec


@dataclass(frozen=True)
class SseSpec(FrozenModel):
    kind: str
    config: dict


@dataclass(frozen=True)
class TransportSpec(FrozenModel):
    version: int
    request: RequestSpec
    auth: AuthSpec
    response: ResponseSpec
    outcome: OutcomeSpec
    delivery: SyncSpec | PollSpec | SseSpec
    timeout: TimeoutBudget
    session: SessionSpec
    limits: ResourceLimits

    @classmethod
    def from_dict(cls, data):
        object_fields(
            data,
            set(cls.__dataclass_fields__),
            {
                "version",
                "request",
                "auth",
                "response",
                "outcome",
                "delivery",
                "timeout",
                "session",
                "limits",
            },
        )
        if type(data["version"]) is not int or data["version"] != 1:
            raise ValueError("Unsupported transport version")
        request = RequestSpec.from_dict(data["request"])
        auth = AuthSpec.from_dict(data["auth"])
        auth_names = {h.name.lower() for h in auth.headers} | (
            {"authorization"} if auth.kind == "bearer" else set()
        )
        if auth_names & {k.lower() for k in request.headers}:
            raise ValueError("Auth and public headers conflict")
        delivery = data["delivery"]
        object_fields(
            delivery,
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
        kind = choice(delivery["kind"], {"sync", "poll", "sse"})
        if kind == "sync":
            if len(delivery) != 1:
                raise ValueError("Unexpected sync fields")
            delivery = SyncSpec()
        elif kind == "poll":
            object_fields(
                delivery,
                {
                    "kind",
                    "run_id",
                    "request",
                    "pending",
                    "interval_s",
                    "max_polls",
                    "submit_http_status",
                    "submit_outcome",
                },
                {
                    "kind",
                    "run_id",
                    "request",
                    "pending",
                    "interval_s",
                    "max_polls",
                    "submit_http_status",
                    "submit_outcome",
                },
            )
            object_fields(delivery["run_id"], {"path"}, {"path"})
            path(delivery["run_id"]["path"])
            poll_request = RequestSpec.from_dict(delivery["request"], poll=True)
            if poll_request.method != "GET" or origin(poll_request.url) != origin(
                request.url
            ):
                raise ValueError("Poll origin or method mismatch")
            if auth_names & {k.lower() for k in poll_request.headers}:
                raise ValueError("Poll auth and public headers conflict")
            max_polls = delivery["max_polls"]
            if isinstance(max_polls, bool) or not isinstance(max_polls, int):
                raise ValueError("Invalid poll limit")
            positive(max_polls, 100)
            statuses = delivery["submit_http_status"]
            if (
                not isinstance(statuses, list)
                or not statuses
                or any(type(v) is not int or not 200 <= v < 300 for v in statuses)
            ):
                raise ValueError("Invalid submit HTTP status")
            delivery = PollSpec(
                kind,
                copy.deepcopy(delivery["run_id"]),
                poll_request,
                predicate(delivery["pending"]),
                positive(delivery["interval_s"]),
                max_polls,
                tuple(statuses),
                SubmissionOutcomeSpec.from_dict(delivery["submit_outcome"]),
            )
        else:
            object_fields(
                delivery,
                {
                    "kind",
                    "event_names",
                    "data_format",
                    "terminal",
                    "accumulation",
                    "idle_timeout_s",
                    "reconnect",
                    "delta_selector",
                },
                {
                    "kind",
                    "event_names",
                    "data_format",
                    "terminal",
                    "accumulation",
                    "idle_timeout_s",
                    "reconnect",
                },
            )
            if not isinstance(delivery["event_names"], list) or any(
                not isinstance(v, str) for v in delivery["event_names"]
            ):
                raise ValueError("Invalid SSE event names")
            choice(delivery["data_format"], {"json", "text"})
            choice(delivery["accumulation"], {"final_value", "text_delta"})
            predicate(delivery["terminal"])
            positive(delivery["idle_timeout_s"])
            if delivery["reconnect"] is not False:
                raise ValueError("SSE reconnect unsupported")
            if "delta_selector" in delivery:
                path(delivery["delta_selector"])
            delivery = SseSpec(kind, copy.deepcopy(delivery))
        limits = ResourceLimits.from_dict(data["limits"])
        outcome = OutcomeSpec.from_dict(data["outcome"])
        if len(outcome.rules) > limits.max_rules:
            raise ValueError("Outcome rules exceed limit")
        return cls(
            1,
            request,
            auth,
            ResponseSpec.from_dict(data["response"]),
            outcome,
            delivery,
            TimeoutBudget.from_dict(data["timeout"]),
            SessionSpec.from_dict(data["session"]),
            limits,
        )

    def to_dict(self):
        import json

        result = json.loads(json.dumps(asdict(self)))
        result["auth"] = {"kind": self.auth.kind}
        if self.auth.kind == "headers":
            result["auth"]["headers"] = [
                {"name": h.name, "secret": _secret_dict(h.secret)}
                for h in self.auth.headers
            ]
        if self.auth.kind == "bearer":
            result["auth"]["secret"] = _secret_dict(self.auth.secret)
        result["response"]["text"]["paths"] = list(self.response.text.paths)
        if self.response.format == "text":
            result["response"]["text"].pop("paths")
        if self.session.id_path is None:
            result["session"].pop("id_path")
        if self.outcome.kind == "http_only":
            result["outcome"] = {"kind": "http_only"}
        else:
            result["outcome"]["rules"] = [_rule_dict(r) for r in self.outcome.rules]
        if isinstance(self.delivery, PollSpec):
            result["delivery"]["submit_http_status"] = list(
                self.delivery.submit_http_status
            )
            result["delivery"]["submit_outcome"]["rules"] = [
                _rule_dict(r) for r in self.delivery.submit_outcome.rules
            ]
        if isinstance(self.delivery, SseSpec):
            result["delivery"] = json.loads(json.dumps(self.delivery.config))
        return result


def _secret_dict(ref):
    result = {"source": ref.source, "strip_final_newline": ref.strip_final_newline}
    result["name" if ref.source == "env" else "path"] = (
        ref.name if ref.source == "env" else ref.path
    )
    return result


def _rule_dict(rule):
    return {
        "id": rule.id,
        "priority": rule.priority,
        "http_status": list(rule.http_status),
        "when": json.loads(json.dumps(rule.when)),
        "outcome": rule.outcome.value,
    }


def origin(url):
    p = urlsplit(url)
    return f'{p.scheme.lower()}://{p.hostname.lower()}:{p.port or (443 if p.scheme=="https" else 80)}'


@dataclass(frozen=True)
class TransportContext(FrozenModel):
    prompt: str
    scenario_url: str | None = None
    history: tuple = ()
    conversation_id: str = ""
    session_id: str | None = None
    run_id: str | None = None


@dataclass(frozen=True)
class ConversationState(FrozenModel):
    conversation_id: str
    session_id: str | None = None
    run_id: str | None = None


@dataclass(frozen=True)
class TransportResult(FrozenModel):
    outcome: TransportOutcome
    response_text: str | None
    latency_ms: float
    http_status: int | None
    matched_rule_id: str | None
    reason_code: SafeReasonCode
    metadata: ResponseMetadata = field(default_factory=dict)
    diagnostics: dict = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data):
        object_fields(
            data, set(cls.__dataclass_fields__), set(cls.__dataclass_fields__)
        )
        outcome = TransportOutcome(data["outcome"])
        reason = SafeReasonCode(data["reason_code"])
        latency = data["latency_ms"]
        if (
            isinstance(latency, bool)
            or not isinstance(latency, (int, float))
            or not math.isfinite(latency)
            or latency < 0
        ):
            raise ValueError("Invalid transport latency")
        status = data["http_status"]
        if status is not None and (type(status) is not int or not 100 <= status <= 599):
            raise ValueError("Invalid transport HTTP status")
        rule = data["matched_rule_id"]
        if rule is not None and (not isinstance(rule, str) or not rule):
            raise ValueError("Invalid transport rule identifier")
        answer = data["response_text"]
        if outcome == TransportOutcome.SUCCEEDED:
            if (
                not isinstance(answer, str)
                or not answer.strip()
                or reason != SafeReasonCode.OK
            ):
                raise ValueError("Invalid successful transport reply")
        elif answer is not None:
            raise ValueError("Non-success transport reply contains an answer")
        if not isinstance(data["metadata"], dict) or not isinstance(
            data["diagnostics"], dict
        ):
            raise ValueError("Invalid transport metadata")
        if set(data["metadata"]) - {"session_id", "run_id", "run_log", "latency_ms"}:
            raise ValueError("Unknown transport metadata")
        if (
            outcome == TransportOutcome.BLOCKED
            and reason != SafeReasonCode.TARGET_REFUSAL
        ):
            raise ValueError("Invalid blocked transport reason")
        if outcome == TransportOutcome.TIMED_OUT and reason != SafeReasonCode.TIMEOUT:
            raise ValueError("Invalid timeout transport reason")
        return cls(
            outcome,
            answer,
            latency,
            status,
            rule,
            reason,
            data["metadata"],
            data["diagnostics"],
        )

    def as_dict(self):
        import json

        return json.loads(
            json.dumps(
                {
                    **asdict(self),
                    "outcome": self.outcome.value,
                    "reason_code": self.reason_code.value,
                }
            )
        )
