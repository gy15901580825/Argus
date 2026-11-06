"""The `--bindings` file: reviewed facts a document cannot supply, parsed once at the command boundary."""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path

from argus_transport.spec_v2 import CONTEXT_KEYS_V2, NAME_RE, SECRET_WORDS, value_expr_v2

from .openapi import Source, pointer_child

MAX_BYTES = 64 * 1024
MAX_SEGMENTS = 16
# The suffix becomes the run variable input_<suffix>, which a transport name caps at 32 characters.
ENV_NAME = re.compile(r"TARGET_INPUT_[A-Z0-9_]{1,26}")
CREDENTIAL_NAME = re.compile(r"key|token|password|secret|auth|credential", re.I)
MAX_STEPS = 8
STEP_KEYS = {"id", "operation", "scope", "values", "parameters", "capture", "undo"}
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


@dataclass(frozen=True)
class DraftInputs:
    source: dict  # {"file", "sha256"} of the raw bytes, appended to provenance inputs
    prompt: UserField | None
    reply: UserField | None
    values: tuple[UserField, ...]
    steps: tuple[UserStep, ...] = ()


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
    return UserStep(step_id, data["operation"], data["scope"], tuple(fields), parameters, captures, undo, Source(file, where), origin)


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
    if not isinstance(data, dict) or not set(data) <= {"version", "prompt", "reply", "values", "steps"}:
        raise ValueError("file must be an object with only version, prompt, reply, values and steps")
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
        _steps(data.get("steps", []), file))
