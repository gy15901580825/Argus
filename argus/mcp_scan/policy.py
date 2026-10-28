"""Which listed tools scan-mcp calls: read-only by default, others only by opt-in, env-like ones only by name."""
from __future__ import annotations

import re
from typing import Literal

from argus.assertions import SENSITIVE_TOOL_PATTERNS
from argus.mcp_scan.models import ToolInfo

CallTools = None | Literal["all"] | frozenset[str]

REASON_NOT_READONLY = "not annotated read-only"
REASON_DESTRUCTIVE = "annotated destructive"
REASON_ENV_LIKE = "listed, not called: looks like it returns environment or secrets"
REASON_CAP = "not tested: call cap reached"


# The shared pattern misses `read_env`: `_` is a word character, so `\benv` never matches inside a snake_case name.
_NAME_SPLIT = re.compile(r"[\s_.\-]+|(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")
_ENV_TOKENS = frozenset({"env", "environ", "environment", "envvars", "dotenv"})


def env_like(tool: ToolInfo) -> bool:
    if any(token.lower() in _ENV_TOKENS for token in _NAME_SPLIT.split(tool.name)):
        return True
    return SENSITIVE_TOOL_PATTERNS["env"].search(f"{tool.name} {tool.description}") is not None


def unknown_names(tools: list[ToolInfo], call_tools: CallTools) -> list[str]:
    if not isinstance(call_tools, frozenset):
        return []
    listed = {t.name for t in tools}
    return sorted(call_tools - listed)


def select(tools: list[ToolInfo], call_tools: CallTools) -> tuple[list[ToolInfo], dict[str, str]]:
    """The tools to call, in listing order, and the reason each other tool is not called."""
    named = call_tools if isinstance(call_tools, frozenset) else frozenset()
    chosen: list[ToolInfo] = []
    reasons: dict[str, str] = {}
    seen: set[str] = set()
    for tool in tools:
        # A name listed twice is one tool to the client; the first listing is the one called.
        if tool.name in seen:
            continue
        seen.add(tool.name)
        if tool.name in named:
            chosen.append(tool)
        elif env_like(tool):
            reasons[tool.name] = REASON_ENV_LIKE
        elif call_tools == "all" or (tool.read_only and not tool.destructive):
            chosen.append(tool)
        else:
            reasons[tool.name] = REASON_DESTRUCTIVE if tool.destructive else REASON_NOT_READONLY
    return chosen, reasons
