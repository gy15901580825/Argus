"""Loader + minimal client-side validator for target specs.

The engine is the source of truth for target specs; the CLI only checks
that `kind` is registered and that the file is valid JSON with
the per-kind required fields. This catches most operator mistakes before
round-tripping to the server.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any


class TargetLoadError(ValueError):
    pass


# Each $VAR / ${VAR} (and %VAR% on Windows) reference, expanded on its own, gives the value
# os.path.expandvars substitutes for it in context.
_POSIX_VAR_RE = re.compile(r"\$(?:\w+|\{[^}]*\})", re.ASCII)
_NT_VAR_RE = re.compile(r"%[^%]+%|\$(?:\w+|\{[^}]*\})", re.ASCII)


def _expand_env(value, substituted: list[str], *, skip_transport: bool = True):
    """Expand ${VAR} references in strings; recurse through dicts and lists.

    Appends every non-empty value it substitutes to `substituted`."""
    if isinstance(value, str):
        pattern = _NT_VAR_RE if os.name == "nt" else _POSIX_VAR_RE
        for m in pattern.finditer(value):
            expanded = os.path.expandvars(m.group(0))
            if expanded and expanded != m.group(0):
                substituted.append(expanded)
        return os.path.expandvars(value)
    if isinstance(value, dict):
        return {
            k: v if skip_transport and k == "transport"
            else _expand_env(v, substituted, skip_transport=skip_transport)
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [_expand_env(v, substituted, skip_transport=skip_transport) for v in value]
    return value


def load_target_spec(target_arg: str) -> dict[str, Any]:
    """target_arg is either a path to JSON file or an inline JSON string."""
    return load_target_spec_with_secrets(target_arg)[0]


def load_target_spec_with_secrets(target_arg: str) -> tuple[dict[str, Any], list[str]]:
    """Like load_target_spec, plus every non-empty value substituted for a $VAR reference."""
    text: str
    base_dir = None
    if target_arg.lstrip().startswith("{"):
        text = target_arg
    else:
        path = Path(target_arg)
        if not path.is_file():
            raise TargetLoadError(
                f"target arg is neither a JSON object nor a readable file: {target_arg!r}"
            )
        text = path.read_text()
        base_dir = path.resolve().parent

    try:
        spec = json.loads(text)
    except json.JSONDecodeError as e:
        raise TargetLoadError(f"target JSON malformed: {e}") from e
    return check_target_spec(spec, base_dir=base_dir)


def check_target_spec(
    spec: Any, *, base_dir: Path | None = None
) -> tuple[dict[str, Any], list[str]]:
    """Validate a parsed spec and expand its $VAR references, as load_target_spec_with_secrets does.

    base_dir is the spec file's directory: a python target's relative file entry is resolved against it."""
    if not isinstance(spec, dict):
        raise TargetLoadError("target must be a JSON object")
    if "kind" not in spec:
        raise TargetLoadError("target.kind is required")
    from argus.targets import (
        _BUILTIN_KINDS, _BuiltinValidation, _check_required, _check_sandbox, kinds,
    )

    info = _BUILTIN_KINDS.get(spec["kind"]) if isinstance(spec["kind"], str) else None
    if info is None:
        registered = kinds()
        if not isinstance(spec["kind"], str) or spec["kind"] not in registered:
            raise TargetLoadError(
                f"unknown target.kind {spec['kind']!r}; must be one of {sorted(registered)}"
            )
        info = registered[spec["kind"]]
    try:
        if not isinstance(info.validate, _BuiltinValidation):
            _check_required(spec, info.required)
            _check_sandbox(spec, info.sandbox_reason)
        if info.validate is not None:
            info.validate(spec)
    except ValueError as exc:
        raise TargetLoadError(str(exc)) from exc
    except (Exception, SystemExit) as exc:
        raise TargetLoadError(
            f"target.kind={spec['kind']!r} validation failed: {type(exc).__name__}: {exc}"
        ) from exc
    substituted: list[str] = []
    spec = _expand_env(spec, substituted, skip_transport=spec["kind"] in _BUILTIN_KINDS)
    if isinstance(info.validate, _BuiltinValidation):
        spec = info.validate.anchor(spec, base_dir)
    return spec, list(dict.fromkeys(substituted))
