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

from dataclasses import dataclass, field
from typing import Any, ClassVar

import httpx  # noqa: F401  (tests patch it here)

from argus.targets.testbed_agent import TestbedAgentTarget


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


class MCPAgentTarget(TestbedAgentTarget):
    compatible_classes: ClassVar[frozenset[str]] = frozenset({"mcp_agent"})
    url_key = "mcp_url"
    staging_noun = "MCP server"
    teardown_label = "MCP testbed"
