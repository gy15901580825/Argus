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

import httpx

from orchestrator.redteam.targets._base import Target, Turn


@dataclass(frozen=True)
class PaymentAgentSpec:
    kind: str = "payment_agent"
    testbed_url: str = ""
    # Nested spec for the transport that actually talks to the agent.
    inner: dict[str, Any] = field(default_factory=dict)
    # The script the mock merchant follows this run (quote, payee override,
    # injected follow-up, forced settle failure). Comes from the probe's
    # `scenario.payload`.
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


class PaymentAgentTarget(Target):
    compatible_classes: ClassVar[frozenset[str]] = frozenset({"payment_agent"})

    def __init__(self, spec: PaymentAgentSpec) -> None:
        from orchestrator.redteam.targets import build_target

        self.spec = spec
        self._inner = build_target(dict(spec.inner))
        self._session: dict | None = None

    @property
    def supports_history(self) -> bool:  # type: ignore[override]
        return bool(getattr(self._inner, "supports_history", False))

    async def _open_session(self) -> dict:
        if self._session is None:
            async with httpx.AsyncClient(timeout=self.spec.timeout_s) as client:
                resp = await client.post(
                    f"{self.spec.testbed_url.rstrip('/')}/sessions", json=dict(self.spec.script)
                )
                resp.raise_for_status()
                self._session = resp.json()
        return self._session

    async def send_prompt(
        self, prompt: str, history: tuple[Turn, ...] = ()
    ) -> tuple[str, float]:
        session = await self._open_session()
        # The probe writes {merchant_url}; only the session knows the real one.
        rendered = prompt.replace("{merchant_url}", session["merchant_url"])
        return await self._inner.send_prompt(rendered, history=history)

    async def collect_evidence(self) -> dict:
        """What happened at the testbed: every request, every authorization.

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
