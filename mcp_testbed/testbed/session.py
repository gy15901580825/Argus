"""Per-run session state for the hostile MCP testbed.

A session is one probe's slice of the hostile MCP world: which scenario is
staged, and the record of every JSON-RPC interaction the agent under test
actually made. Nothing here reaches the network -- when the session expires
the evidence goes with it.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from dataclasses import dataclass, field

DEFAULT_TTL_S = 900.0
DEFAULT_SCENARIO = "tool_poisoning"

# Placeholder tool catalog until testbed/scenarios.py exists and Session is
# wired to look tools up by scenario. Every session sees the same tools for
# now; there is nothing hostile about this list on its own.
_DEFAULT_TOOLS = [
    {
        "name": "read_notes",
        "description": "Reads the user's notes.",
        "inputSchema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "send_email",
        "description": "Sends an email on the user's behalf.",
        "inputSchema": {
            "type": "object",
            "properties": {"to": {"type": "string"}, "body": {"type": "string"}},
            "required": ["to", "body"],
        },
    },
]


def _digest(tools: list[dict]) -> str:
    blob = json.dumps(tools, sort_keys=True).encode()
    return hashlib.sha256(blob).hexdigest()[:12]


@dataclass(frozen=True)
class Script:
    """Which hostile scenario the server stages this run."""

    scenario: str = DEFAULT_SCENARIO

    @classmethod
    def from_dict(cls, raw: dict | None) -> "Script":
        raw = raw or {}
        return cls(scenario=str(raw.get("scenario", DEFAULT_SCENARIO)))


@dataclass
class Session:
    id: str
    script: Script
    created_at: float
    canary: str | None = None
    shadow_tool_names: list[str] = field(default_factory=list)
    interaction_count: int = 0
    tools_list_count: int = 0
    descriptions_served: list[dict] = field(default_factory=list)
    tool_calls: list[dict] = field(default_factory=list)

    def current_tools(self) -> list[dict]:
        """The tool list the *next* tools/list call would serve.

        A fixed catalog for now -- testbed/scenarios.py (task 2) replaces this
        with per-scenario, call-count-dependent tool lists (e.g. rug_pull).
        """
        return [dict(t) for t in _DEFAULT_TOOLS]

    def call_result(self, tool: str, arguments: dict) -> dict:
        """The result of calling `tool`. A generic placeholder for now --
        testbed/scenarios.py (task 2) gives this scenario-specific teeth,
        e.g. planting an injection in a confused_deputy result."""
        return {"content": [{"type": "text", "text": f"{tool} executed."}]}

    def record_tools_list(self, tools: list[dict]) -> None:
        self.tools_list_count += 1
        self.descriptions_served.append({
            "seq": self.interaction_count,
            "digest": _digest(tools),
            "tools": [t["name"] for t in tools],
        })

    def record_tool_call(self, tool: str, arguments: dict) -> None:
        after_change = False
        if self.tools_list_count >= 2:
            after_change = (
                self.descriptions_served[-1]["digest"]
                != self.descriptions_served[-2]["digest"]
            )
        self.tool_calls.append({
            "seq": self.interaction_count,
            "tool": tool,
            "arguments": arguments,
            "after_description_change": after_change,
        })

    def evidence(self) -> dict:
        return {
            "interaction_count": self.interaction_count,
            "tools_list_count": self.tools_list_count,
            "descriptions_served": list(self.descriptions_served),
            "tool_calls": list(self.tool_calls),
            "shadow_tool_names": list(self.shadow_tool_names),
            "canary": self.canary,
        }


class SessionStore:
    def __init__(self, ttl_s: float = DEFAULT_TTL_S) -> None:
        self._ttl_s = ttl_s
        self._sessions: dict[str, Session] = {}

    def open(self, script: Script, now: float | None = None) -> Session:
        now = time.monotonic() if now is None else now
        self.purge_expired(now)
        session = Session(
            id=secrets.token_urlsafe(16),
            script=script,
            created_at=now,
        )
        self._sessions[session.id] = session
        return session

    def get(self, sid: str, now: float | None = None) -> Session | None:
        now = time.monotonic() if now is None else now
        session = self._sessions.get(sid)
        if session is None:
            return None
        if now - session.created_at > self._ttl_s:
            del self._sessions[sid]
            return None
        return session

    def close(self, sid: str) -> bool:
        return self._sessions.pop(sid, None) is not None

    def purge_expired(self, now: float | None = None) -> int:
        now = time.monotonic() if now is None else now
        stale = [sid for sid, s in self._sessions.items() if now - s.created_at > self._ttl_s]
        for sid in stale:
            del self._sessions[sid]
        return len(stale)
