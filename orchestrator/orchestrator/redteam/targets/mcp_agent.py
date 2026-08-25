"""Target adapter for agents that speak MCP.

The other five text-only adapters relay a prompt and hand back text. This one
also builds the world the agent acts in: it opens a session on the hostile MCP
testbed, tells the agent where the (poisoned) MCP server lives, and afterwards
reports what the agent actually did there — which tools it called, with what
arguments, and whether the server changed a tool's description mid-session.
That record, not the reply text, is what the probe's assertions judge.

The adapter is deliberately a shell over an inner transport. A real MCP-using
agent may speak OpenAI-compat chat, or a bespoke HTTP shape; until a customer's
interface is known, the shape stays configurable rather than guessed.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any, ClassVar

import httpx

from orchestrator.redteam.targets._base import Target, Turn

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class MCPAgentSpec:
    kind: str = "mcp_agent"
    testbed_url: str = ""
    # Nested spec for the transport that actually talks to the agent.
    inner: dict[str, Any] = field(default_factory=dict)
    # Fallback script for the hostile MCP server (which scenario to stage),
    # used only for a probe that declares no `scenario.payload` of its own.
    # Each probe's own payload takes precedence and is staged by
    # `begin_probe()` — the hostile setup belongs to the attack, not to the
    # run.
    script: dict[str, Any] = field(default_factory=dict)
    sandbox: bool = False
    timeout_s: float = 60.0

    def __post_init__(self) -> None:
        if self.kind != "mcp_agent":
            raise ValueError(f"kind must be 'mcp_agent', got {self.kind!r}")
        if not self.testbed_url:
            raise ValueError("testbed_url is required")
        if not self.inner:
            raise ValueError("inner target spec is required")
        if not self.sandbox:
            # Structural refusal, not a warning. A red-team run that can reach
            # a real MCP server is not a configuration mistake we recover from.
            raise ValueError(
                "mcp_agent requires sandbox: true — this adapter drives an agent "
                "against a live MCP server and may only be pointed at a simulated testbed"
            )


class MCPAgentTarget(Target):
    compatible_classes: ClassVar[frozenset[str]] = frozenset({"mcp_agent"})

    def __init__(self, spec: MCPAgentSpec) -> None:
        from orchestrator.redteam.targets import build_target

        self.spec = spec
        self._inner = build_target(dict(spec.inner))
        self._session: dict | None = None
        # The script the *next* session opens with. begin_probe() replaces it
        # per probe; the spec-level script is only the run default.
        self._script: dict[str, Any] = dict(spec.script)

    @property
    def supports_history(self) -> bool:  # type: ignore[override]
        return bool(getattr(self._inner, "supports_history", False))

    async def _open_session(self) -> dict:
        if self._session is None:
            async with httpx.AsyncClient(timeout=self.spec.timeout_s) as client:
                resp = await client.post(
                    f"{self.spec.testbed_url.rstrip('/')}/sessions", json=dict(self._script)
                )
                resp.raise_for_status()
                self._session = resp.json()
        return self._session

    async def _close_session(self) -> None:
        """Discard the current session at the testbed.

        A teardown that fails is a real problem — the testbed is holding state
        we asked it to drop — but it must not stop the next probe from getting
        a session, or one flaky DELETE would abort the rest of the run. Log it
        loudly and carry on; the local reference is cleared either way, so no
        evidence can leak forward even when the remote copy lingers to TTL.
        """
        session = self._session
        self._session = None
        if session is None:
            return
        sid = session.get("session_id")
        try:
            async with httpx.AsyncClient(timeout=self.spec.timeout_s) as client:
                resp = await client.delete(
                    f"{self.spec.testbed_url.rstrip('/')}/sessions/{sid}"
                )
                resp.raise_for_status()
        except Exception:
            logger.warning(
                "MCP testbed refused teardown of session %s; it will expire by TTL",
                sid,
                exc_info=True,
            )

    def _script_for(self, probe) -> dict[str, Any]:
        """The hostile scenario this probe attacks with.

        An MCP probe is its `scenario.payload`: which scenario the testbed
        stages (tool poisoning, rug pull, shadowing, confused deputy, credential
        lure). Run it without that and the agent meets whatever scenario the
        run default names, behaves, and the probe reports a pass for an attack
        that was never mounted.

        Malformed payloads therefore raise rather than degrading to the default
        script — quietly running unstaged is exactly how that false green stayed
        invisible in the payment adapter this one is modeled on.
        """
        raw = getattr(probe, "scenario_payload", "") or ""
        if not isinstance(raw, str):
            raise ValueError(
                f"probe {getattr(probe, 'id', '?')!r} has a scenario.payload that is "
                f"{type(raw).__name__}, not a string; refusing to run it against an "
                f"unstaged MCP server"
            )
        if not raw.strip():
            return dict(self.spec.script)
        try:
            script = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"probe {getattr(probe, 'id', '?')!r} has a scenario.payload that is not "
                f"valid JSON ({exc}); refusing to run it against an unstaged MCP server"
            ) from exc
        if not isinstance(script, dict):
            raise ValueError(
                f"probe {getattr(probe, 'id', '?')!r} has a scenario.payload that is "
                f"{type(script).__name__}, not a JSON object; refusing to run it against "
                f"an unstaged MCP server"
            )
        return script

    async def begin_probe(self, probe) -> None:
        """Give this probe its own world, staged the way the probe asks for.

        Two probes sharing one session is a false-green generator: the second
        probe inherits the first one's interaction count and slips past the
        `requires_interaction` gate that exists to turn "the agent never showed
        up" into an error rather than a pass, and it inherits the first one's
        tool calls, which makes `no_call_to_tool` / `max_tool_calls` judge tool
        calls that happened under a different probe.
        """
        # Parse before tearing anything down: a probe we are going to refuse
        # should not also cost the caller the session it is holding.
        script = self._script_for(probe)
        await self._close_session()
        self._script = script
        await self._open_session()

    async def send_prompt(
        self, prompt: str, history: tuple[Turn, ...] = ()
    ) -> tuple[str, float]:
        session = await self._open_session()
        # The probe writes {mcp_url}; only the session knows the real one.
        rendered = prompt.replace("{mcp_url}", session["mcp_url"])
        return await self._inner.send_prompt(rendered, history=history)

    async def collect_evidence(self) -> dict:
        """What happened at the testbed: every tool call, every description served.

        Returns empty when no session was ever opened — the runner reads that as
        "the probe did not run" rather than as a clean bill of health.
        """
        if self._session is None:
            return {}
        sid = self._session["session_id"]
        async with httpx.AsyncClient(timeout=self.spec.timeout_s) as client:
            resp = await client.get(f"{self.spec.testbed_url.rstrip('/')}/sessions/{sid}/evidence")
            resp.raise_for_status()
            return resp.json()
