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

_KNOWN_KINDS = frozenset({
    "openai_compat", "anthropic_native", "custom_http", "grpc", "browser_use",
    "payment_agent", "mcp_agent", "testbed_agent", "http_upload", "mcp_server",
    "vllm_server", "web_chat",
})

_REQUIRED_FIELDS = {
    "openai_compat": {"endpoint_url", "model"},
    "anthropic_native": {"model", "api_key"},
    "custom_http": {"request_url", "request_body_template", "response_jsonpath"},
    "grpc": {"endpoint", "service_method"},
    "browser_use": {"agent_url", "scenario_kind"},
    "payment_agent": {"testbed_url", "inner", "sandbox"},
    "mcp_agent": {"testbed_url", "inner", "sandbox"},
    "testbed_agent": {"environment", "testbed_url", "inner", "sandbox"},
    "http_upload": {"upload_url"},
    "mcp_server": {"url"},
    "vllm_server": {"url"},
    "web_chat": {"url", "input_selector", "response_selector"},
}

# Adapters that act on the world rather than only exchanging text. For these
# `sandbox` must be present AND true — the orchestrator enforces the same rule,
# but that must not be the only place it is checked. The value is the reason
# shown to the operator, so each family says what it would actually reach.
_SANDBOX_REQUIRED_KINDS = {
    "payment_agent": "drives an agent that spends money",
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
        return {k: _expand_env(v, substituted) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand_env(v, substituted) for v in value]
    return value


def load_target_spec(target_arg: str) -> dict[str, Any]:
    """target_arg is either a path to JSON file or an inline JSON string."""
    return load_target_spec_with_secrets(target_arg)[0]


def load_target_spec_with_secrets(target_arg: str) -> tuple[dict[str, Any], list[str]]:
    """Like load_target_spec, plus every non-empty value substituted for a $VAR reference."""
    text: str
    if target_arg.lstrip().startswith("{"):
        text = target_arg
    else:
        path = Path(target_arg)
        if not path.is_file():
            raise TargetLoadError(
                f"target arg is neither a JSON object nor a readable file: {target_arg!r}"
            )
        text = path.read_text()

    try:
        spec = json.loads(text)
    except json.JSONDecodeError as e:
        raise TargetLoadError(f"target JSON malformed: {e}") from e
    return check_target_spec(spec)


def check_target_spec(spec: Any) -> tuple[dict[str, Any], list[str]]:
    """Validate a parsed spec and expand its $VAR references, as load_target_spec_with_secrets does."""
    if not isinstance(spec, dict):
        raise TargetLoadError("target must be a JSON object")
    if "kind" not in spec:
        raise TargetLoadError("target.kind is required")
    if spec["kind"] not in _KNOWN_KINDS:
        raise TargetLoadError(
            f"unknown target.kind {spec['kind']!r}; must be one of {sorted(_KNOWN_KINDS)}"
        )
    missing = _REQUIRED_FIELDS[spec["kind"]] - set(spec.keys())
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
    return spec, list(dict.fromkeys(substituted))
