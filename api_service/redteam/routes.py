"""Red-team API routes."""

from __future__ import annotations

import os
from typing import Optional
from uuid import UUID

import httpx as _httpx
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Response
from pydantic import BaseModel

from auth import get_current_user
from models import UserResponse
from redteam import orchestrator_client, reports as report_render, runs
from redteam.schemas import TargetSpec  # discriminated union (5 kinds)


router = APIRouter(prefix="/redteam", tags=["redteam"])

ORCH_URL = os.environ.get("ORCHESTRATOR_URL", "http://argus-orchestrator.default.svc.cluster.local:8080")


class RunCreate(BaseModel):
    target: TargetSpec
    probe_ids: list[str]
    suite_name: str = "ad-hoc"
    per_run_cap_usd: Optional[float] = None  # Plan 4 T12: client override


class RunResponse(BaseModel):
    run_id: str


@router.post("/runs", response_model=RunResponse)
async def create_run(
    req: RunCreate,
    bg: BackgroundTasks,
    user: UserResponse = Depends(get_current_user),
) -> RunResponse:
    # Pre-flight: let orchestrator reject with 402 before we create the DB row.
    try:
        await orchestrator_client.create_run(req.target.model_dump(), req.probe_ids, per_run_cap_usd=req.per_run_cap_usd)
    except _httpx.HTTPStatusError as e:
        if e.response.status_code == 402:
            try:
                detail = e.response.json().get("detail", "cost cap exceeded")
            except Exception:
                detail = "cost cap exceeded"
            raise HTTPException(status_code=402, detail=detail)
        raise HTTPException(status_code=502, detail=f"orchestrator error: {e.response.status_code}")

    run_id = await runs.create_run(
        user_id=user.id,
        target_spec=req.target.model_dump(),
        probe_suite=req.suite_name,
    )
    bg.add_task(_consume_orchestrator_stream, run_id, req.target.model_dump(), req.probe_ids, req.per_run_cap_usd)
    return RunResponse(run_id=str(run_id))


@router.get("/runs/{run_id}")
async def get_run(run_id: UUID, user: UserResponse = Depends(get_current_user)) -> dict:
    row = await runs.get_run(run_id, user.id)
    if not row:
        raise HTTPException(status_code=404, detail="run not found")
    findings = await runs.list_findings(run_id)
    return {"id": str(run_id), "status": row["status"], "findings": findings}


@router.get("/runs/{run_id}/report")
async def get_run_report(
    run_id: UUID,
    format: str = Query("html", pattern="^(html|sarif|junit)$"),
    user: UserResponse = Depends(get_current_user),
):
    row = await runs.get_run(run_id, user.id)
    if not row:
        raise HTTPException(status_code=404, detail="run not found")
    findings = await runs.list_findings(run_id)
    run_dict = {
        "id": str(run_id),
        "status": row["status"],
        "started_at": str(row.get("started_at")) if row.get("started_at") else None,
        "finished_at": str(row.get("finished_at")) if row.get("finished_at") else None,
        "findings": [{**f, "id": str(f["id"]), "probed_at": str(f["probed_at"]) if f.get("probed_at") else None} for f in findings],
    }
    if format == "html":
        return Response(content=report_render.render_html(run_dict), media_type="text/html")
    if format == "sarif":
        return Response(content=report_render.render_sarif(run_dict), media_type="application/sarif+json")
    if format == "junit":
        return Response(content=report_render.render_junit(run_dict), media_type="application/xml")
    raise HTTPException(status_code=400, detail=f"unknown format {format!r}")


@router.get("/probes")
async def list_probes(user: UserResponse = Depends(get_current_user)) -> dict:
    """Proxy GET /redteam/probes from orchestrator. Auth-gated like the rest."""
    async with _httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.get(f"{ORCH_URL}/redteam/probes")
        resp.raise_for_status()
        return resp.json()


async def _consume_orchestrator_stream(run_id: UUID, target_spec: dict, probe_ids: list[str], per_run_cap_usd: Optional[float] = None) -> None:
    await runs.update_run_status(run_id, "running")
    try:
        async for finding in orchestrator_client.stream_findings(target_spec, probe_ids, per_run_cap_usd=per_run_cap_usd):
            await runs.insert_finding(run_id, finding)
        await runs.update_run_status(run_id, "completed")
    except Exception as e:
        await runs.update_run_status(run_id, "failed", summary={"error": str(e)})
