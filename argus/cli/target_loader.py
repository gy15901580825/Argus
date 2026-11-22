"""Loader + minimal client-side validator for target specs.

The CLI checks syntax, registered kinds, required fields, and constructor
field names before passing the spec to the engine. This catches operator
mistakes before round-tripping to the server.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

import yaml


class TargetLoadError(ValueError):
    pass


# Match references once so escaped dollars and substituted values are not expanded again.
_POSIX_VAR_RE = re.compile(r"\$\$|\$(?:\w+|\{[^}]*\})", re.ASCII)
_NT_VAR_RE = re.compile(r"%%|\$\$|%[^%]+%|\$(?:\w+|\{[^}]*\})", re.ASCII)


def _expand_env(
    value, substituted: list[str], *, skip_transport: bool = True, field: str = "target"
):
    """Expand environment references in strings; recurse through dicts and lists.

    Appends every non-empty value it substitutes to `substituted`."""
    if isinstance(value, str):
        pattern = _NT_VAR_RE if os.name == "nt" else _POSIX_VAR_RE

        def expand(match):
            reference = match.group(0)
            if reference == "$$":
                return "$"
            if reference == "%%":
                return "%"
            if reference.startswith("${"):
                name = reference[2:-1]
            elif reference.startswith("%"):
                name = reference[1:-1]
            else:
                name = reference[1:]
            if name not in os.environ:
                command = f"set {name}=VALUE" if os.name == "nt" else f"export {name}"
                escape = "%% for a literal percent sign" if reference.startswith("%") else "$$ for a literal dollar sign"
                raise TargetLoadError(
                    f"{field} references environment variable {name!r}, which is not set; "
                    f"{command} before loading the target, or use {escape}"
                )
            expanded = os.environ[name]
            if expanded:
                substituted.append(expanded)
            return expanded

        return pattern.sub(expand, value)
    if isinstance(value, dict):
        return {
            k: v if skip_transport and k == "transport"
            else _expand_env(v, substituted, skip_transport=skip_transport, field=f"{field}.{k}")
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [
            _expand_env(v, substituted, skip_transport=skip_transport, field=f"{field}[{i}]")
            for i, v in enumerate(value)
        ]
    return value


def load_target_spec(target_arg: str) -> dict[str, Any]:
    """Load a JSON/YAML file or an inline JSON object. YAML requires .yaml/.yml."""
    return load_target_spec_with_secrets(target_arg)[0]


def load_target_spec_with_secrets(target_arg: str) -> tuple[dict[str, Any], list[str]]:
    """Like load_target_spec, plus every non-empty value substituted for a $VAR reference."""
    text: str
    base_dir = None
    is_yaml = False
    if target_arg.lstrip().startswith("{"):
        text = target_arg
    else:
        path = Path(target_arg)
        if not path.is_file():
            raise TargetLoadError(
                f"target arg is neither a JSON object nor a readable file: {target_arg!r}"
            )
        try:
            text = path.read_text()
        except (OSError, UnicodeDecodeError) as exc:
            raise TargetLoadError(f"cannot read the target file: {exc}") from exc
        base_dir = path.resolve().parent
        is_yaml = path.suffix.lower() in {".yaml", ".yml"}

    try:
        spec = yaml.safe_load(text) if is_yaml else json.loads(text)
    except json.JSONDecodeError as e:
        raise TargetLoadError(f"target JSON malformed: {e}") from e
    except yaml.YAMLError as exc:
        raise TargetLoadError(f"target YAML malformed: {exc}") from exc
    return check_target_spec(spec, base_dir=base_dir)


def check_target_spec(
    spec: Any, *, base_dir: Path | None = None
) -> tuple[dict[str, Any], list[str]]:
    """Validate a parsed spec and expand its $VAR references, as load_target_spec_with_secrets does.

    base_dir is the spec file's directory: a python target's relative file entry is resolved against it."""
    if not isinstance(spec, dict):
        raise TargetLoadError("target must be a JSON object")
    if "kind" not in spec:
        raise TargetLoadError("target.kind is required; add the 'kind' field, for example 'openai_compat'")
    from argus.targets import (
        _BUILTIN_KINDS, _BuiltinValidation, _check_fields, _check_required, _check_sandbox, kinds,
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
        from argus.input_budget import InputLimits

        InputLimits.from_spec(spec)
        if not isinstance(info.validate, _BuiltinValidation):
            _check_required(spec, info.required)
            _check_sandbox(spec, info.sandbox_reason)
        if info.validate is not None:
            info.validate(spec)
        _check_fields(spec)
    except ValueError as exc:
        raise TargetLoadError(str(exc)) from exc
    except (Exception, SystemExit) as exc:
        raise TargetLoadError(
            f"target.kind={spec['kind']!r} validation failed: {type(exc).__name__}: {exc}"
        ) from exc
    substituted: list[str] = []
    spec = _expand_env(spec, substituted, skip_transport=spec["kind"] in _BUILTIN_KINDS)
    if spec["kind"] == "mcp_gateway":
        from argus.targets.mcp_gateway import MCPGatewaySpec

        try:
            MCPGatewaySpec(**{k: v for k, v in spec.items() if k not in {"input_limits", "domain"}})
        except ValueError as exc:
            raise TargetLoadError(str(exc)) from exc
    if isinstance(info.validate, _BuiltinValidation):
        spec = info.validate.anchor(spec, base_dir)
    return spec, list(dict.fromkeys(substituted))
