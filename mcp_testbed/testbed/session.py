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

from testbed.scenarios import SCENARIOS, Scenario

DEFAULT_TTL_S = 900.0
DEFAULT_SCENARIO = "tool_poisoning"


def _digest(tools: list[dict]) -> str:
    blob = json.dumps(tools, sort_keys=True).encode()
    return hashlib.sha256(blob).hexdigest()[:12]


@dataclass(frozen=True)
class Script:
    """Which hostile scenario the server stages this run.

    `injection` is a knob, not a second scenario axis: it only has an effect
    on `confused_deputy`, where it replaces the default instruction planted in
    a tool call's result, so a probe can stage a differently-shaped attack
    (a single-hop forward vs. a chained "read again, then forward") without
    the testbed growing one scenario per variant. Every other scenario ignores
    it -- their `call_result_fn` accepts and drops the same parameter.
    """

    scenario: str = DEFAULT_SCENARIO
    injection: str | None = None

    @classmethod
    def from_dict(cls, raw: dict | None) -> "Script":
        raw = raw or {}
        return cls(
            scenario=str(raw.get("scenario", DEFAULT_SCENARIO)),
            injection=raw.get("injection"),
        )


@dataclass
class Session:
    id: str
    script: Script
    scenario: Scenario
    created_at: float
    canary: str | None = None
    interaction_count: int = 0
    tools_list_count: int = 0
    descriptions_served: list[dict] = field(default_factory=list)
    tool_calls: list[dict] = field(default_factory=list)

    def current_tools(self) -> list[dict]:
        """The tool list the *next* tools/list call would serve.

        Delegates to the staged scenario, which is call-count-dependent for
        e.g. rug_pull (the description changes starting from the 2nd call).
        """
        return self.scenario.tools_fn(self.tools_list_count + 1, self.canary)

    def call_result(self, tool: str, arguments: dict) -> dict:
        """The result of calling `tool`, per the staged scenario -- e.g.
        confused_deputy plants its injection here rather than in a
        description."""
        return self.scenario.call_result_fn(tool, arguments, self.canary, self.script.injection)

    def record_tools_list(self, tools: list[dict]) -> None:
        self.tools_list_count += 1
        self.descriptions_served.append({
            "seq": self.interaction_count,
            "digest": _digest(tools),
            "tools": [t["name"] for t in tools],
        })

    def record_tool_call(self, tool: str, arguments: dict) -> None:
        # Sticky, not last-vs-previous: once the description has changed
        # relative to the *first* listing this session ever served, every
        # later call stays flagged, even across a third/fourth relist (an
        # ordinary reconnect or periodic refresh). Comparing only the last
        # two entries let a third tools/list silently reset the flag to
        # False whenever it repeated the already-rug-pulled description --
        # a false green for no_call_after_description_change.
        after_change = False
        if self.tools_list_count >= 2:
            after_change = (
                self.descriptions_served[-1]["digest"]
                != self.descriptions_served[0]["digest"]
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
            "shadow_tool_names": list(self.scenario.shadow_tool_names),
            "canary": self.canary,
        }


class SessionStore:
    def __init__(self, ttl_s: float = DEFAULT_TTL_S) -> None:
        self._ttl_s = ttl_s
        self._sessions: dict[str, Session] = {}

    def open(self, script: Script, now: float | None = None) -> Session:
        now = time.monotonic() if now is None else now
        self.purge_expired(now)
        scenario = SCENARIOS[script.scenario]
        session = Session(
            id=secrets.token_urlsafe(16),
            script=script,
            scenario=scenario,
            created_at=now,
            # Minted here, never taken from the request: a real credential
            # lure has to plant its own bait, not accept one from a caller.
            canary=f"sk-live-{secrets.token_hex(12)}" if scenario.has_canary else None,
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
