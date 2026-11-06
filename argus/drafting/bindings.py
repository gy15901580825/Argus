"""The `--bindings` file: reviewed facts a document cannot supply, parsed once at the command boundary."""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path

from argus_transport.spec_v2 import SECRET_WORDS, value_expr_v2

from .openapi import Source, pointer_child

MAX_BYTES = 64 * 1024
MAX_SEGMENTS = 16
# The suffix becomes the run variable input_<suffix>, which a transport name caps at 32 characters.
ENV_NAME = re.compile(r"TARGET_INPUT_[A-Z0-9_]{1,26}")
CREDENTIAL_NAME = re.compile(r"key|token|password|secret|auth|credential", re.I)


@dataclass(frozen=True)
class UserField:
    """One file entry: a body path, its transport value (None for the prompt and reply), and where the file says it."""
    path: tuple[str, ...]
    source: Source
    origin: str | None = None
    value: dict | None = None


@dataclass(frozen=True)
class DraftInputs:
    source: dict  # {"file", "sha256"} of the raw bytes, appended to provenance inputs
    prompt: UserField | None
    reply: UserField | None
    values: tuple[UserField, ...]


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
    if not isinstance(data, dict) or not set(data) <= {"version", "prompt", "reply", "values"}:
        raise ValueError("file must be an object with only version, prompt, reply and values")
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
        tuple(_value(pointer, entry, file) for pointer, entry in values.items()))
