"""The `--bindings` file: reviewed facts a document cannot supply, parsed once at the command boundary."""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from argus_transport.spec_v2 import CONTEXT_KEYS_V2, NAME_RE, SECRET_WORDS, value_expr_v2

from .openapi import Source, pointer_child

MAX_BYTES = 64 * 1024
MAX_SEGMENTS = 16
# The suffix becomes the run variable input_<suffix>, which a transport name caps at 32 characters.
ENV_NAME = re.compile(r"TARGET_INPUT_[A-Z0-9_]{1,26}")
CREDENTIAL_NAME = re.compile(r"key|token|password|secret|auth|credential", re.I)
MAX_STEPS = 8
STEP_KEYS = {"id", "operation", "scope", "values", "parameters", "capture", "undo", "multipart"}
# Each kind yields one string or number the document can type-check; nested objects are written as nested paths.
STEP_KINDS = {"literal", "env", "var", "generate", "concat", "context"}


@dataclass(frozen=True)
class UserField:
    """One file entry: a body path, its transport value (None for the prompt and reply), and where the file says it."""
    path: tuple[str, ...]
    source: Source
    origin: str | None = None
    value: dict | None = None


@dataclass(frozen=True)
class UserCapture:
    name: str
    path: tuple[str, ...]
    source: Source


@dataclass(frozen=True)
class UserUndo:
    operation: str
    parameters: tuple[UserField, ...]  # path is the one parameter name
    source: Source


@dataclass(frozen=True)
class MultipartIssue:
    source: Source
    why: str


@dataclass(frozen=True)
class UserPart:
    name: str
    content: dict
    filename: str
    content_type: str
    source: Source
    defaults: tuple[str, ...]


@dataclass(frozen=True)
class UserMultipart:
    parts: tuple[UserPart, ...]
    issues: tuple[MultipartIssue, ...]


@dataclass(frozen=True)
class UserStep:
    """A prerequisite call before the ask; the file names it because no document says the ask needs it."""
    id: str
    operation: str
    scope: str  # "run" once per run, "attempt" before every ask
    values: tuple[UserField, ...]  # request body paths
    parameters: tuple[UserField, ...]  # path and query parameters by name
    capture: tuple[UserCapture, ...] | None  # None lets the draft propose one with the undo
    undo: UserUndo | None  # None lets the draft propose one
    source: Source
    origin: str | None = None
    multipart: UserMultipart | None = None


@dataclass(frozen=True)
class UserCarry:
    parameter: str
    submit_parameter: str
    source: Source


@dataclass(frozen=True)
class UserPoll:
    operation: str
    parameters: tuple[UserCarry, ...]
    source: Source


@dataclass(frozen=True)
class UserId:
    field: str
    last_segment: bool
    source: Source
    origin: str | None = None


@dataclass(frozen=True)
class UserCompletion:
    path: tuple[str, ...]
    style: Literal["enum", "presence"]
    succeeded: str
    pending: tuple[str, ...]
    failed: tuple[str, ...]
    source: Source
    origin: str | None = None


@dataclass(frozen=True)
class DraftInputs:
    source: dict  # {"file", "sha256"} of the raw bytes, appended to provenance inputs
    prompt: UserField | None
    reply: UserField | None
    values: tuple[UserField, ...]
    steps: tuple[UserStep, ...] = ()
    poll: UserPoll | None = None
    ids: tuple[UserId, ...] = ()
    completion: UserCompletion | None = None


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate key {json.dumps(key)}")
        result[key] = value
    return result


def _constant(name):
    raise ValueError(f"{name} is not a JSON number")


def _path(pointer, where):
    if not isinstance(pointer, str) or not pointer.startswith("/") or re.search(r"~(?![01])", pointer):
        raise ValueError(f"{where} must be a JSON pointer such as /inputs/question")
    path = tuple(part.replace("~1", "/").replace("~0", "~") for part in pointer.split("/")[1:])
    if not all(path) or len(path) > MAX_SEGMENTS:
        raise ValueError(f"{where} needs 1 to {MAX_SEGMENTS} non-empty segments")
    return path


def _entry(data, where, keys):
    if not isinstance(data, dict) or not set(data) <= keys | {"origin"}:
        raise ValueError(f"{where} must be an object with only " + ", ".join(sorted(keys | {"origin"})))
    if not isinstance(data.get("origin", ""), str):
        raise ValueError(f"{where}/origin must be a string")
    return data.get("origin")


def _field(data, file, where):
    origin = _entry(data, where, {"path"})
    return UserField(_path(data.get("path"), where + "/path"), Source(file, where), origin)


def _value(pointer, data, file):
    where = pointer_child("/values", pointer)
    origin = _entry(data, where, {"literal", "env"})
    path = _path(pointer, where)
    expression = {key: item for key, item in data.items() if key != "origin"}
    if set(expression) not in ({"literal"}, {"env"}):
        raise ValueError(f"{where} needs exactly one of literal or env")
    if any(CREDENTIAL_NAME.search(part) for part in path):
        raise ValueError(f"{where} names a credential; credentials never enter a bindings file, use TARGET_API_KEY")
    if "literal" in expression and type(expression["literal"]) not in {str, int, float, bool}:
        raise ValueError(f"{where}/literal must be a string, number or boolean")
    if "env" in expression and (not isinstance(expression["env"], str) or not ENV_NAME.fullmatch(expression["env"])
                                or any(word in expression["env"].lower() for word in SECRET_WORDS)):
        raise ValueError(f"{where}/env must name a non-secret TARGET_INPUT_<NAME> variable")
    value_expr_v2(expression, visible=frozenset())
    return UserField(path, Source(file, where), origin, expression)


def _object(data, where, keys, required=frozenset()):
    if not isinstance(data, dict) or not set(data) <= keys or not required <= set(data):
        raise ValueError(f"{where} must be an object with " + ", ".join(sorted(keys)) + (" (" + ", ".join(sorted(required)) + " required)" if required else ""))
    return data


def _step_expression(data, where, visible, top=True):
    """A step value: literal JSON, a TARGET_INPUT env name, an earlier capture, a generated value, a concat of those, or the material."""
    if not isinstance(data, dict) or len(data) != 1 or not set(data) <= (STEP_KINDS if top else {"literal", "var", "generate"}):
        raise ValueError(f"{where} must be one of " + (", ".join(sorted(STEP_KINDS)) if top else "literal, var or generate inside concat"))
    kind, item = next(iter(data.items()))
    if kind == "env" and (not isinstance(item, str) or not ENV_NAME.fullmatch(item) or any(word in item.lower() for word in SECRET_WORDS)):
        raise ValueError(f"{where}/env must name a non-secret TARGET_INPUT_<NAME> variable")
    if kind == "context" and item != "material":
        raise ValueError(f"{where}/context can only be material; the prompt goes to the ask")
    if kind == "literal" and item is None:
        raise ValueError(f"{where}/literal cannot be null")
    if kind == "concat" and isinstance(item, list):
        for index, part in enumerate(item):
            _step_expression(part, f"{where}/concat/{index}", visible, top=False)
    try:
        value_expr_v2(data, visible=frozenset(visible))
    except ValueError as exc:
        raise ValueError(f"{where}: {exc}; a var names a capture of an earlier step") from None
    return data


def _variable(value, where, taken):
    """A step ID or capture name; both become transport variable names."""
    if (not isinstance(value, str) or not NAME_RE.fullmatch(value) or value in CONTEXT_KEYS_V2
            or any(word in value for word in SECRET_WORDS)):
        raise ValueError(f"{where} must be a lowercase transport name without a secret word")
    if value.startswith("input_") or value in taken:
        raise ValueError(f"{where} must be unique and not start with input_")
    taken.add(value)
    return value


def _named(data, where, file, visible):
    if not isinstance(data, dict):
        raise ValueError(f"{where} must map parameter names to values")
    for name in data:
        if not name or CREDENTIAL_NAME.search(name):
            raise ValueError(f"{where} names a credential or an empty parameter")
    return tuple(UserField((name,), Source(file, pointer_child(where, name)), None,
                           _step_expression(item, pointer_child(where, name), visible)) for name, item in data.items())


def _secret_literal(value):
    if isinstance(value, str):
        return any(word in value.lower() for word in SECRET_WORDS)
    if isinstance(value, dict):
        return any(_secret_literal(key) or _secret_literal(item) for key, item in value.items())
    if isinstance(value, list):
        return any(_secret_literal(item) for item in value)
    return False


def _part_secret(expression):
    if "literal" in expression:
        return _secret_literal(expression["literal"])
    return any(_part_secret(part) for part in expression.get("concat", ()))


def _multipart(data, where, file, visible, has_values):
    parts, issues = [], []

    def reject(pointer, why):
        issues.append(MultipartIssue(Source(file, pointer), why))

    if has_values:
        reject(where, "A step cannot send both JSON values and multipart parts.")
    if not isinstance(data, dict) or not 1 <= len(data) <= 4:
        reject(where, "A multipart body must map one to four part names to parts.")
        return UserMultipart((), tuple(issues))
    for name, raw in data.items():
        at = pointer_child(where, name)
        if not NAME_RE.fullmatch(name) or any(word in name.lower() for word in SECRET_WORDS):
            reject(at, "A multipart part needs a lowercase transport name without a secret word.")
            continue
        if not isinstance(raw, dict) or not set(raw) <= {"content", "filename", "content_type"} or "content" not in raw:
            reject(at, "A multipart part needs content and only optional filename and content_type literals.")
            continue
        try:
            content = _step_expression(raw["content"], at + "/content", visible)
        except ValueError:
            reject(at + "/content", "The multipart content is not a supported step expression.")
            continue
        filename, content_type = raw.get("filename", "material.txt"), raw.get("content_type", "text/plain")
        if not isinstance(filename, str) or not filename or any(char in filename for char in '\r\n\x00"'):
            reject(at + "/filename", "The multipart filename must be a nonempty literal without a quote, line break or NUL.")
            continue
        if content_type not in ("text/plain", "text/markdown", "application/json", "text/csv"):
            reject(at + "/content_type", "The multipart content_type must be a supported literal media type.")
            continue
        if _part_secret(content) or _secret_literal(filename) or _secret_literal(content_type):
            reject(at, "A multipart part cannot contain a secret-like literal.")
            continue
        if "literal" in content and not isinstance(content["literal"], str):
            reject(at + "/content", "Multipart content must produce a string.")
            continue
        parts.append(UserPart(name, content, filename, content_type, Source(file, at),
                              tuple(key for key in ("filename", "content_type") if key not in raw)))
    return UserMultipart(tuple(parts), tuple(issues))


def _step(data, index, file, visible, taken):
    where = f"/steps/{index}"
    _object(data, where, STEP_KEYS | {"origin"}, {"id", "operation", "scope"})
    origin = _entry(data, where, STEP_KEYS)
    step_id = _variable(data["id"], where + "/id", taken)
    if not isinstance(data["operation"], str) or not data["operation"]:
        raise ValueError(f"{where}/operation must name an operation ID")
    if data["scope"] not in ("run", "attempt"):
        raise ValueError(f"{where}/scope must be run or attempt")
    values = data.get("values", {})
    if not isinstance(values, dict):
        raise ValueError(f"{where}/values must map JSON pointers to values")
    fields = []
    for pointer, item in values.items():
        at = pointer_child(where + "/values", pointer)
        path = _path(pointer, at)
        if any(CREDENTIAL_NAME.search(part) for part in path):
            raise ValueError(f"{at} names a credential; credentials never enter a bindings file, use TARGET_API_KEY")
        if any(other.path[:len(path)] == path or path[:len(other.path)] == other.path for other in fields):
            raise ValueError(f"{at} overlaps another value path")
        fields.append(UserField(path, Source(file, at), None, _step_expression(item, at, visible)))
    multipart = _multipart(data["multipart"], where + "/multipart", file, visible, "values" in data) if "multipart" in data else None
    parameters = _named(data.get("parameters", {}), where + "/parameters", file, visible)
    captures = None
    if "capture" in data:
        if not isinstance(data["capture"], dict):
            raise ValueError(f"{where}/capture must map variable names to response JSON pointers")
        captures = tuple(UserCapture(_variable(name, pointer_child(where + "/capture", name), taken),
                                     _path(pointer, pointer_child(where + "/capture", name)),
                                     Source(file, pointer_child(where + "/capture", name)))
                         for name, pointer in data["capture"].items())
    own = visible | {capture.name for capture in captures or ()}
    undo = None
    if "undo" in data:
        _object(data["undo"], where + "/undo", {"operation", "parameters"}, {"operation"})
        if not isinstance(data["undo"]["operation"], str) or not data["undo"]["operation"]:
            raise ValueError(f"{where}/undo/operation must name an operation ID")
        undo = UserUndo(data["undo"]["operation"], _named(data["undo"].get("parameters", {}), where + "/undo/parameters", file, own),
                        Source(file, where + "/undo"))
    visible.update(own - visible)
    return UserStep(step_id, data["operation"], data["scope"], tuple(fields), parameters, captures, undo, Source(file, where), origin, multipart)


def _steps(data, file):
    if not isinstance(data, list) or len(data) > MAX_STEPS:
        raise ValueError(f"steps must be a list of at most {MAX_STEPS} steps")
    visible, taken, steps = set(), set(), []
    for index, item in enumerate(data):
        step = _step(item, index, file, visible, taken)
        if step.scope == "run" and steps and steps[-1].scope == "attempt":
            raise ValueError(f"/steps/{index}: run steps come before attempt steps, as they run")
        steps.append(step)
    return tuple(steps)


def _poll_input(data, file):
    where = "/poll"
    if isinstance(data, str):
        operation, parameters = data, {}
    else:
        _object(data, where, {"operation", "parameters"}, {"operation"})
        operation, parameters = data["operation"], data.get("parameters", {})
    if not isinstance(operation, str) or not operation.strip():
        raise ValueError("/poll/operation must name an operation")
    if not isinstance(parameters, dict):
        raise ValueError("/poll/parameters must map poll names to submit path names")
    carried = []
    for name, source in parameters.items():
        at = pointer_child(where + "/parameters", name)
        if (not isinstance(source, str) or not name or not source
                or CREDENTIAL_NAME.search(name) or CREDENTIAL_NAME.search(source)):
            raise ValueError(f"{at} must name non-secret poll and submit path parameters")
        carried.append(UserCarry(name, source, Source(file, at)))
    return UserPoll(operation, tuple(carried), Source(file, where))


def _id_inputs(data, file):
    if not isinstance(data, dict):
        raise ValueError("/ids must map submit response fields to extraction entries")
    result = []
    for name, entry in data.items():
        at = pointer_child("/ids", name)
        if not name or CREDENTIAL_NAME.search(name):
            raise ValueError(f"{at} must name a non-secret submit response field")
        origin = _entry(entry, at, {"last_segment"})
        if type(entry.get("last_segment")) is not bool:
            raise ValueError(f"{at}/last_segment must be a boolean")
        result.append(UserId(name, entry["last_segment"], Source(file, at), origin))
    return tuple(result)


def _completion_input(data, file):
    where = "/completion"
    keys = {"path", "style", "succeeded", "pending", "failed"}
    _object(data, where, keys | {"origin"}, keys)
    if not isinstance(data.get("origin", ""), str):
        raise ValueError("/completion/origin must be a string")
    origin = data.get("origin")
    if data["style"] not in ("enum", "presence"):
        raise ValueError("/completion/style must be enum or presence")
    limit = 32 if data["style"] == "presence" else 128
    for key in ("pending", "failed"):
        values = data[key]
        if not isinstance(values, list) or len(values) > limit or any(not isinstance(v, str) or not v for v in values):
            raise ValueError(f"/completion/{key} must be a list of at most {limit} non-empty names")
    if not isinstance(data["succeeded"], str) or not data["succeeded"] or not data["pending"]:
        raise ValueError("/completion needs one success name and at least one pending name")
    names = [data["succeeded"], *data["pending"], *data["failed"]]
    if len(set(names)) != len(names):
        raise ValueError("/completion classes must be disjoint and contain no duplicates")
    return UserCompletion(_path(data["path"], where + "/path"), data["style"], data["succeeded"],
                          tuple(data["pending"]), tuple(data["failed"]), Source(file, where), origin)


def read_bindings(path: Path) -> DraftInputs:
    """Parse a version 1 bindings file; any structural problem raises ValueError before the document is read."""
    path = Path(path)
    raw = path.read_bytes()
    if len(raw) > MAX_BYTES:
        raise ValueError(f"file exceeds {MAX_BYTES} bytes")
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique, parse_constant=_constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise ValueError("file must be UTF-8 JSON") from None
    if not isinstance(data, dict) or not set(data) <= {"version", "prompt", "reply", "values", "steps", "poll", "ids", "completion"}:
        raise ValueError("file must be an object with only version, prompt, reply, values, steps, poll, ids and completion")
    if type(data.get("version")) is not int or data["version"] != 1:
        raise ValueError("version must be 1")
    values = data.get("values", {})
    if not isinstance(values, dict):
        raise ValueError("values must map JSON pointers to value entries")
    file = path.name
    return DraftInputs(
        {"file": file, "sha256": hashlib.sha256(raw).hexdigest()},
        _field(data["prompt"], file, "/prompt") if "prompt" in data else None,
        _field(data["reply"], file, "/reply") if "reply" in data else None,
        tuple(_value(pointer, entry, file) for pointer, entry in values.items()),
        _steps(data.get("steps", []), file),
        _poll_input(data["poll"], file) if "poll" in data else None,
        _id_inputs(data.get("ids", {}), file),
        _completion_input(data["completion"], file) if "completion" in data else None)
