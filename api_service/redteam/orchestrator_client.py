"""HTTP client to orchestrator's /redteam/run SSE endpoint."""

from __future__ import annotations

import json
import os
from typing import AsyncIterator

import httpx


ORCHESTRATOR_URL = os.environ.get(
    "ORCHESTRATOR_URL",
    "http://argus-orchestrator-dev.dev.svc.cluster.local:8080",
)


class OrchestratorError(RuntimeError):
    """Raised when orchestrator's SSE stream emits `event: error`."""


async def create_run(target_spec: dict, probe_ids: list[str], per_run_cap_usd: float | None = None, suite: str | None = None) -> None:
    """Pre-flight cost-cap check via the lightweight /redteam/run/preflight endpoint.

    Raises httpx.HTTPStatusError on 402 (cost cap) or other 4xx/5xx.
    Does NOT start probe execution — stream_findings() does that separately.
    """
    body: dict = {"target": target_spec, "probe_ids": probe_ids}
    if suite is not None:
        body["suite"] = suite
    if per_run_cap_usd is not None:
        body["per_run_cap_usd"] = per_run_cap_usd
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(f"{ORCHESTRATOR_URL}/redteam/run/preflight", json=body)
        resp.raise_for_status()


async def stream_findings(target_spec: dict, probe_ids: list[str], per_run_cap_usd: float | None = None, suite: str | None = None) -> AsyncIterator[dict]:
    body: dict = {"target": target_spec, "probe_ids": probe_ids}
    if suite is not None:
        body["suite"] = suite
    if per_run_cap_usd is not None:
        body["per_run_cap_usd"] = per_run_cap_usd
    async with httpx.AsyncClient(timeout=600.0) as client:
        async with client.stream("POST", f"{ORCHESTRATOR_URL}/redteam/run", json=body) as resp:
            resp.raise_for_status()
            current_event = "message"  # SSE default per spec
            async for line in resp.aiter_lines():
                if line.startswith("event: "):
                    current_event = line[len("event: "):].strip()
                    if current_event == "end":
                        return
                elif line.startswith("data: "):
                    payload = line[len("data: "):]
                    if current_event == "error":
                        raise OrchestratorError(payload)
                    if payload.strip() and payload.strip() != "{}":
                        yield json.loads(payload)
                    current_event = "message"  # reset to default after each data
