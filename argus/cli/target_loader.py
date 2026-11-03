"""Loader + minimal client-side validator for target specs.

The engine is the source of truth for target specs; the CLI only checks
that `kind` is one of the known kinds (`_KNOWN_KINDS`) and that the file is valid JSON with
the per-kind required fields. This catches most operator mistakes before
round-tripping to the server.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

_KNOWN_KINDS = frozenset(
    {
        "openai_compat",
        "anthropic_native",
        "custom_http",
        "grpc",
        "browser_use",
        "payment_agent",
        "mcp_agent",
        "a2a_agent",
        "testbed_agent",
        "http_upload",
        "mcp_server",
        "vllm_server",
        "web_chat",
        "a2a_server",
        "python",
    }
)

_REQUIRED_FIELDS = {
    "openai_compat": {"endpoint_url", "model"},
    "anthropic_native": {"model", "api_key"},
    "custom_http": {"request_url", "request_body_template", "response_jsonpath"},
    "grpc": {"endpoint", "service_method"},
    "browser_use": {"agent_url", "scenario_kind"},
    "payment_agent": {"testbed_url", "inner", "sandbox"},
    "a2a_agent": {"testbed_url", "inner", "sandbox"},
    "mcp_agent": {"testbed_url", "inner", "sandbox"},
    "testbed_agent": {"environment", "testbed_url", "inner", "sandbox"},
    "http_upload": {"upload_url"},
    "mcp_server": {"url"},
    "a2a_server": {"url"},
    "vllm_server": {"url"},
    "web_chat": {"url", "input_selector", "response_selector"},
    "python": {"entry"},
}

# Adapters that act on the world rather than only exchanging text. For these
# `sandbox` must be present AND true — the orchestrator enforces the same rule,
# but that must not be the only place it is checked. The value is the reason
# shown to the operator, so each family says what it would actually reach.
_SANDBOX_REQUIRED_KINDS = {
    "payment_agent": "drives an agent that spends money",
    "a2a_agent": "drives an agent that sends messages to A2A peers and requests actions",
    "mcp_agent": "drives an agent against a live MCP server",
    "testbed_agent": "drives an agent inside a simulated environment",
}


class TargetLoadError(ValueError):
    pass


# Each $VAR / ${VAR} (and %VAR% on Windows) reference, expanded on its own, gives the value
# os.path.expandvars substitutes for it in context.
_POSIX_VAR_RE = re.compile(r"\$(?:\w+|\{[^}]*\})", re.ASCII)
_NT_VAR_RE = re.compile(r"%[^%]+%|\$(?:\w+|\{[^}]*\})", re.ASCII)


def _expand_env(value, substituted: list[str]):
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
        return {k: v if k == "transport" else _expand_env(v, substituted) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand_env(v, substituted) for v in value]
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
    if not isinstance(spec["kind"], str) or spec["kind"] not in _KNOWN_KINDS:
        raise TargetLoadError(
            f"unknown target.kind {spec['kind']!r}; must be one of {sorted(_KNOWN_KINDS)}"
        )
    required = _REQUIRED_FIELDS[spec["kind"]]
    if "transport" in spec:
        if spec["kind"] not in {"custom_http", "browser_use"}:
            raise TargetLoadError("transport is supported only by custom_http and browser_use")
        from argus.targets.custom_http import LEGACY_TRANSPORT_FIELDS
        legacy_fields = LEGACY_TRANSPORT_FIELDS if spec["kind"] == "custom_http" else {"agent_url", "timeout_s"}
        if set(spec) & legacy_fields:
            raise TargetLoadError("transport and legacy transport fields conflict")
        required = set() if spec["kind"] == "custom_http" else {"scenario_kind"}
    missing = required - set(spec.keys())
    if missing:
        raise TargetLoadError(
            f"target.kind={spec['kind']!r} missing required fields: {sorted(missing)}"
        )
    sandbox_reason = _SANDBOX_REQUIRED_KINDS.get(spec["kind"])
    if sandbox_reason is not None and spec["sandbox"] is not True:
        raise TargetLoadError(
            f"target.kind={spec['kind']!r} requires sandbox: true — this adapter "
            f"{sandbox_reason} and may only be pointed at a "
            "simulated testbed"
        )
    substituted: list[str] = []
    spec = _expand_env(spec, substituted)
    if spec["kind"] == "python" and base_dir is not None:
        spec = _anchor_python_entry(spec, base_dir)
    return spec, list(dict.fromkeys(substituted))


def _anchor_python_entry(spec: dict[str, Any], base_dir: Path) -> dict[str, Any]:
    from argus.targets.python_target import is_path_entry, split_entry

    try:
        target, func = split_entry(spec["entry"])
    except (ValueError, AttributeError):
        return spec  # the target builder reports a malformed entry
    if not is_path_entry(target) or Path(target).is_absolute():
        return spec
    return {**spec, "entry": f"{base_dir / target}:{func}"}
