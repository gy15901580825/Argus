"""Loader + minimal client-side validator for target specs.

Server is the source of truth (Pydantic union in api_service); CLI only checks
that `kind` is one of the 8 known values and that the file is valid JSON with
the per-kind required fields. This catches most operator mistakes before
round-tripping to the server.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

_KNOWN_KINDS = frozenset({
    "openai_compat", "anthropic_native", "custom_http", "grpc", "browser_use",
    "payment_agent", "mcp_agent", "http_upload",
})

_REQUIRED_FIELDS = {
    "openai_compat": {"endpoint_url", "model"},
    "anthropic_native": {"model", "api_key"},
    "custom_http": {"request_url", "request_body_template", "response_jsonpath"},
    "grpc": {"endpoint", "service_method"},
    "browser_use": {"agent_url", "scenario_kind"},
    "payment_agent": {"testbed_url", "inner", "sandbox"},
    "mcp_agent": {"testbed_url", "inner", "sandbox"},
    "http_upload": {"upload_url"},
}

# Adapters that act on the world rather than only exchanging text. For these
# `sandbox` must be present AND true — the orchestrator enforces the same rule,
# but that must not be the only place it is checked. The value is the reason
# shown to the operator, so each family says what it would actually reach.
_SANDBOX_REQUIRED_KINDS = {
    "payment_agent": "drives an agent that spends money",
    "mcp_agent": "drives an agent against a live MCP server",
}


class TargetLoadError(ValueError):
    pass


def _expand_env(value):
    """Expand ${VAR} references in strings; recurse through dicts and lists."""
    if isinstance(value, str):
        return os.path.expandvars(value)
    if isinstance(value, dict):
        return {k: _expand_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand_env(v) for v in value]
    return value


def load_target_spec(target_arg: str) -> dict[str, Any]:
    """target_arg is either a path to JSON file or an inline JSON string."""
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
    spec = _expand_env(spec)
    return spec
