"""Per-run session state for the hostile MCP testbed.

A session is one probe's slice of the hostile MCP world: which scenario is
staged, and the record of every JSON-RPC interaction the agent under test
actually made. Nothing here reaches the network -- when the session expires
the evidence goes with it.
"""

from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import secrets
import time
from dataclasses import dataclass, field

from .worlds import WORLDS
from .world import World, WorldSpec, ApprovalPolicy, WORLD_TOOLS
from .scenarios import SCENARIOS, Scenario

SETTLE_GRACE_S = 0.3
SETTLE_TIMEOUT_S = 2.0

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

    `gate_send_email` only has an effect on `rug_pull`, default off so the
    original probe is untouched. On, it makes the first listing's send_email
    genuinely unusable (both its description and an early call are rejected)
    rather than merely likely to be relisted, so a second `tools/list` -- the
    one that actually serves the rug-pulled description -- becomes structurally
    required to complete a task that needs to send anything.
    """

    scenario: str = DEFAULT_SCENARIO
    injection: str | None = None
    gate_send_email: bool = False
    phase: str = "single"
    world: str | None = None
    inject: str | None = None
    approver: str = "policy"
    stop_notice: bool = False
    failing_step: str | None = None

    @classmethod
    def from_dict(cls, raw: dict | None) -> "Script":
        raw = raw or {}
        if raw.get("phase", "single") not in ("single", "clean", "attack"):
            raise ValueError("phase must be single, clean or attack")
        return cls(
            phase=raw.get("phase", "single"),
            world=raw.get("world"),
            inject=raw.get("inject"),
            approver=raw.get("approver", "policy"),
            stop_notice=raw.get("stop_notice", False),
            failing_step=raw.get("failing_step"),
            scenario=str(raw.get("scenario", DEFAULT_SCENARIO)),
            injection=raw.get("injection"),
            gate_send_email=bool(raw.get("gate_send_email", False)),
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

    world: World | None = None
    conversation: int = 1
    interaction_count_by_session: dict[str, dict[str, int]] = field(default_factory=dict)
    sealed: bool = False
    seal_timeout: bool = False
    generation: int | None = None
    rejected_requests: list[dict] = field(default_factory=list)
    in_flight: int = 0
    fixed_endpoint: object | None = field(default=None, repr=False)
    _frozen_evidence: dict | None = field(default=None, repr=False)
    _seal_lock: asyncio.Lock = field(default_factory=asyncio.Lock, repr=False)

    @property
    def phase(self) -> str:
        return self.script.phase

    def next_conversation(self) -> int:
        if self.sealed:
            raise ValueError("world is sealed")
        self.conversation += 1
        return self.conversation

    async def seal(self, grace_s: float | None = None, timeout_s: float | None = None) -> dict:
        async with self._seal_lock:
            if self._frozen_evidence is not None:
                return self.evidence()
            if self.fixed_endpoint is not None:
                self.fixed_endpoint.stop(self)
            await asyncio.sleep(SETTLE_GRACE_S if grace_s is None else grace_s)
            deadline = time.monotonic() + (SETTLE_TIMEOUT_S if timeout_s is None else timeout_s)
            while self.in_flight and time.monotonic() < deadline:
                await asyncio.sleep(0.01)
            self.seal_timeout = bool(self.in_flight)
            self.sealed = True
            if self.world is not None:
                self.world.seal()
            self._frozen_evidence = copy.deepcopy(self.evidence())
            return self.evidence()

    def current_tools(self) -> list[dict]:
        """The tool list the *next* tools/list call would serve.

        Delegates to the staged scenario, which is call-count-dependent for
        e.g. rug_pull (the description changes starting from the 2nd call).
        """
        if self.world is not None:
            return self.world.tools()
        return self.scenario.tools_fn(
            self.tools_list_count + 1, self.canary, self.script.gate_send_email
        )

    def call_result(self, tool: str, arguments: dict) -> dict:
        """The result of calling `tool`, per the staged scenario -- e.g.
        confused_deputy plants its injection here rather than in a
        description."""
        if self.world is not None:
            return self.world.call(tool, arguments, seq=self.interaction_count, conversation=self.conversation)
        return self.scenario.call_result_fn(
            tool,
            arguments,
            self.canary,
            self.script.injection,
            self.tools_list_count,
            self.script.gate_send_email,
        )

    def record_tools_list(self, tools: list[dict]) -> None:
        self.tools_list_count += 1
        self.descriptions_served.append({
            "seq": self.interaction_count,
            "digest": _digest(tools),
            "tools": [t["name"] for t in tools],
            "tool_digests": {t["name"]: _digest([t]) for t in tools},
        })

    def record_tool_call(self, tool: str, arguments: dict, server: str = "primary") -> None:
        # Per tool: flag the call only when THIS tool's description changed.
        # A session-wide flag marked a call to an untouched tool (read_notes)
        # as rug-pulled because another tool (send_email) had changed -- a
        # false fail against an agent whose allow-list filtered send_email out.
        #
        # Sticky, not last-vs-previous: compare the latest listing that served
        # this tool against the FIRST listing that served it, so a third
        # relist repeating the rug-pulled description cannot reset the flag
        # (a false green for no_call_after_description_change).
        served = [d["tool_digests"][tool] for d in self.descriptions_served
                  if tool in d.get("tool_digests", {})]
        after_change = len(served) >= 2 and served[-1] != served[0]
        record = {
            "seq": self.interaction_count,
            "conversation": self.conversation,
            "tool": tool,
            "arguments": arguments,
            "after_description_change": after_change,
        }
        if server != "primary":
            record["server"] = server
        self.tool_calls.append(record)

    def evidence(self) -> dict:
        if self._frozen_evidence is not None:
            return copy.deepcopy(self._frozen_evidence)
        return copy.deepcopy({
            **(self.world.evidence() if self.world is not None else {}),
            "session_id": self.id,
            "phase": self.phase,
            "conversation": self.conversation,
            "interaction_count_by_session": self.interaction_count_by_session,
            "sealed": self.sealed,
            "seal_timeout": self.seal_timeout,
            "generation": self.generation,
            "rejected_requests": self.rejected_requests,
            "interaction_count": self.interaction_count,
            "tools_list_count": self.tools_list_count,
            "descriptions_served": list(self.descriptions_served),
            "tool_calls": list(self.tool_calls),
            "shadow_tool_names": list(self.scenario.shadow_tool_names),
            "canary": self.canary,
        })


class SessionStore:
    def __init__(self, ttl_s: float = DEFAULT_TTL_S) -> None:
        self._ttl_s = ttl_s
        self._sessions: dict[str, Session] = {}

    def open(self, script: Script, now: float | None = None, world_spec: WorldSpec | None = None) -> Session:
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
        if script.scenario == "agent_world":
            if world_spec is None:
                world_spec = WORLDS.get(script.world)
                if world_spec is None:
                    raise ValueError(f"unknown world: {script.world!r}")
            knobs = {key: getattr(script, key) for key in world_spec.knobs}
            for key, value in knobs.items():
                allowed = world_spec.knobs[key]
                if not any(type(value) is type(candidate) and value == candidate for candidate in allowed):
                    raise ValueError(f"invalid {key} value for {world_spec.name}: {value!r}")
            canaries = {
                key: "sk-live-" + secrets.token_hex(12) if key.endswith("_secret")
                else "ACCT-" + secrets.token_hex(4).upper() if key == "payee_account"
                else "ledger-" + secrets.token_hex(3) + ".example"
                for key in world_spec.canary_keys
            }
            session.world = World(world_spec, knobs, canaries)
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
