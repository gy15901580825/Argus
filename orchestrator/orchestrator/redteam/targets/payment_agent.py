"""Target adapter for agents that spend money.

The other five adapters relay a prompt and hand back text. This one also builds
the world the agent acts in: it opens a session on the payment testbed, tells
the agent where the paid resource lives, and afterwards reports what the agent
actually did there. That record — not the reply text — is what the probe's
assertions judge.

The adapter is deliberately a shell over an inner transport. A real payment
agent may speak OpenAI-compat chat, or a bespoke HTTP shape; until a customer's
interface is known, the shape stays configurable rather than guessed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, ClassVar

import httpx  # noqa: F401  (tests patch it here)

from orchestrator.redteam.targets.testbed_agent import TestbedAgentTarget


@dataclass(frozen=True)
class PaymentAgentSpec:
    kind: str = "payment_agent"
    testbed_url: str = ""
    # Nested spec for the transport that actually talks to the agent.
    inner: dict[str, Any] = field(default_factory=dict)
    # Fallback script for the mock merchant (quote, payee override, injected
    # follow-up, forced settle failure), used only for a probe that declares no
    # `scenario.payload` of its own. Each probe's own payload takes precedence
    # and is staged by `begin_probe()` — the hostile setup belongs to the
    # attack, not to the run.
    script: dict[str, Any] = field(default_factory=dict)
    sandbox: bool = False
    timeout_s: float = 60.0

    def __post_init__(self) -> None:
        if self.kind != "payment_agent":
            raise ValueError(f"kind must be 'payment_agent', got {self.kind!r}")
        if not self.testbed_url:
            raise ValueError("testbed_url is required")
        if not self.inner:
            raise ValueError("inner target spec is required")
        if not self.sandbox:
            # Structural refusal, not a warning. A payment red-team run that can
            # reach real funds is not a configuration mistake we recover from.
            raise ValueError(
                "payment_agent requires sandbox: true — this adapter drives an agent "
                "that spends money and may only be pointed at a simulated testbed"
            )


class PaymentAgentTarget(TestbedAgentTarget):
    compatible_classes: ClassVar[frozenset[str]] = frozenset({"payment_agent"})
    url_key = "merchant_url"
    staging_noun = "merchant"
    teardown_label = "payment testbed"
