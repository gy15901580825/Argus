"""Bind browser context to the shared target transport."""

from __future__ import annotations

from dataclasses import dataclass, field

from argus_transport import ExecutionPolicy, TransportContext
from argus_transport.browser import run_browser_transport
from argus_transport.security import Redactor


@dataclass(frozen=True)
class TargetAgentDriver:
    agent_url: str | None
    scenario_url: str
    prompt: str
    timeout_s: float = 60.0
    transport: dict | None = None
    policy: ExecutionPolicy | None = None
    history: tuple = ()
    conversation_id: str = ""
    session_id: str | None = None
    redactor: Redactor = field(default_factory=Redactor, repr=False, compare=False)

    def __repr__(self):
        return "TargetAgentDriver()"

    async def run(self):
        context = TransportContext(
            prompt=self.prompt,
            scenario_url=self.scenario_url,
            history=self.history,
            conversation_id=self.conversation_id,
            session_id=self.session_id,
        )
        return await run_browser_transport(
            context=context,
            transport=self.transport,
            agent_url=self.agent_url,
            timeout_s=self.timeout_s,
            policy=self.policy,
            redactor=self.redactor,
        )
