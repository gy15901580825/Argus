"""Drives a customer's browser-using agent by POSTing the scenario URL + user prompt."""

from __future__ import annotations

from dataclasses import dataclass

import httpx


@dataclass(frozen=True)
class TargetAgentDriver:
    agent_url: str
    scenario_url: str
    prompt: str
    timeout_s: float = 60.0

    async def run(self) -> dict:
        body = {"url": self.scenario_url, "prompt": self.prompt}
        async with httpx.AsyncClient(timeout=self.timeout_s) as client:
            resp = await client.post(self.agent_url, json=body)
            resp.raise_for_status()
            return resp.json()
