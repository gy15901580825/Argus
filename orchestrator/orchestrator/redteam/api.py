"""FastAPI sub-router for redteam runs (called by api_service).

Auth: this endpoint has no authentication. api_service is the only v0 caller
and lives on the same cluster network; per-tenant isolation arrives in M3+.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict
from pathlib import Path
from typing import Any, AsyncIterator

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from orchestrator.redteam.cost_meter import CostMeter
from orchestrator.redteam.judge import Judge
from orchestrator.redteam.probe import load_all_probes
from orchestrator.redteam.runner import Runner
from orchestrator.redteam.targets import build_target


router = APIRouter(prefix="/redteam", tags=["redteam"])

PROBES_DIR = Path(__file__).parent / "probes"
RUBRICS_DIR = Path(__file__).parent / "rubrics"
DAILY_CAP_USD = float(os.environ.get("REDTEAM_DAILY_CAP_USD", "13.50"))  # ~$400/month
# Process-level meter — single tenant for v0; per-customer meters arrive in M3+.
_COST_METER = CostMeter(daily_cap_usd=DAILY_CAP_USD)


class RunRequest(BaseModel):
    # Raw dict — build_target() factory validates and constructs the right spec/target.
    # Accepts all 5 adapter kinds: openai_compat, anthropic_native, custom_http, grpc, browser_use.
    target: dict[str, Any]
    probe_ids: list[str]
    # Caller-supplied per-run cost cap (overrides singleton default when present).
    per_run_cap_usd: float | None = None


def _resolve_target_kind(target: Any) -> str:
    """Extract 'kind' from target dict, defaulting to 'openai_compat'."""
    if isinstance(target, dict):
        return target.get("kind", "openai_compat")
    return "openai_compat"


def _resolve_probe_ids(probe_ids: list[str]) -> list[str]:
    """Empty probe_ids list means 'run every probe in the library'.

    The CLI sends [] when the user passes --probes all, by historical
    convention. Without this resolution every loaded probe would be
    filtered out by the `not in requested` check below, causing the run
    to silently complete with zero findings.
    """
    if probe_ids:
        return probe_ids
    return [p.id for p in load_all_probes(PROBES_DIR)]


async def _run_probes(req: RunRequest, anthropic_api_key: str) -> AsyncIterator[dict]:
    # build_target() validates the dict and selects the right adapter — C1 fix.
    target = build_target(req.target)
    judge = Judge(api_key=anthropic_api_key, cost_meter=_COST_METER)
    runner = Runner(target=target, judge=judge, rubrics_dir=RUBRICS_DIR)

    requested = set(_resolve_probe_ids(req.probe_ids))
    for probe in load_all_probes(PROBES_DIR):
        if probe.id not in requested:
            continue
        async for finding in runner.run_probe(probe):
            # asdict() recurses dataclasses but does NOT convert UUIDs/datetimes.
            # When adding Finding fields, ensure they're JSON-serializable here.
            d = asdict(finding)
            d["id"] = str(finding.id)
            d["probed_at"] = finding.probed_at.isoformat()
            d["created_at"] = finding.created_at.isoformat()
            yield d


@router.post("/run/preflight", status_code=200)
async def preflight(req: RunRequest):
    """Lightweight cost-cap check — no probe execution.

    api_service calls this synchronously before creating the DB row so it can
    surface a 402 to the caller.  Returns 200 {} on pass, 402 on cost exceeded.
    """
    if not isinstance(req.target, dict):
        raise HTTPException(status_code=422, detail="target must be a JSON object")
    try:
        # Validate target dict is buildable before we run cost math — C1 fix.
        build_target(req.target)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    try:
        from orchestrator.redteam.cost_meter import CostExceededError
        kind = _resolve_target_kind(req.target)
        # Honor caller-supplied cap when present — C2 fix; I2 fix (kind from dict).
        # Resolve [] → full library so cost estimate reflects real run scope.
        _COST_METER.check_or_abort_pre_run(
            probe_ids=_resolve_probe_ids(req.probe_ids),
            target_kind=kind,
            iterative_rounds=1,
            per_run_cap_override=req.per_run_cap_usd,
        )
    except CostExceededError as e:
        raise HTTPException(status_code=402, detail=str(e))
    return {}


@router.post("/run")
async def run(req: RunRequest):
    anthropic_api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not anthropic_api_key:
        raise HTTPException(status_code=500, detail="ANTHROPIC_API_KEY not set in orchestrator env")

    if not isinstance(req.target, dict):
        raise HTTPException(status_code=422, detail="target must be a JSON object")
    try:
        build_target(req.target)  # validate early; actual target rebuilt inside _run_probes
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    # Pre-run cost check (Plan 4 T7) — happens before SSE streaming starts.
    try:
        from orchestrator.redteam.cost_meter import CostExceededError
        kind = _resolve_target_kind(req.target)
        # Resolve [] → full library so cost estimate reflects real run scope.
        _COST_METER.check_or_abort_pre_run(
            probe_ids=_resolve_probe_ids(req.probe_ids),
            target_kind=kind,
            iterative_rounds=1,
            per_run_cap_override=req.per_run_cap_usd,
        )
    except CostExceededError as e:
        raise HTTPException(status_code=402, detail=str(e))

    async def _sse() -> AsyncIterator[bytes]:
        try:
            async for finding_dict in _run_probes(req, anthropic_api_key):
                yield f"data: {json.dumps(finding_dict)}\n\n".encode()
            yield b"event: end\ndata: {}\n\n"
        except Exception as exc:
            payload = json.dumps({"detail": str(exc), "type": type(exc).__name__})
            yield f"event: error\ndata: {payload}\n\n".encode()

    return StreamingResponse(_sse(), media_type="text/event-stream")


@router.get("/probes")
async def list_probes() -> dict:
    """Returns list of probe ids the orchestrator currently has loaded."""
    from orchestrator.redteam.probe import load_all_probes
    probes = list(load_all_probes(PROBES_DIR))
    return {"probe_ids": [p.id for p in probes]}
