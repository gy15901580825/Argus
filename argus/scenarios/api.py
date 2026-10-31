from __future__ import annotations

import asyncio
import hmac
import json
import os
from pathlib import Path
from typing import Any
from uuid import UUID

import yaml
from fastapi import APIRouter, Depends, Header, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict, Field, SecretStr

from argus.scenarios.credentials import build_credential_provider
from argus.scenarios.models import IntegrationScenario, ObjectRecord, now, object_marker
from argus.scenarios.runner import ScenarioRunner
from argus.scenarios.runtime import build_drivers, validate_target_credentials, read_template
from argus.targets import build_target


def require_scenario_server_token(authorization: str | None = Header(None)):
    expected = os.getenv("ARGUS_SERVER_TOKEN", "")
    if not expected:
        raise HTTPException(503, "scenario server authentication is not configured")
    supplied = authorization[7:] if authorization and authorization.startswith("Bearer ") else ""
    if not hmac.compare_digest(expected.encode(), supplied.encode()):
        raise HTTPException(401, "missing or invalid bearer token")


router = APIRouter(prefix="/redteam", tags=["integration scenarios"], dependencies=[Depends(require_scenario_server_token)])
CATALOG_DIR = Path(__file__).parent / "catalog"
_active_runs: set[str] = set()


class ProviderSpec(BaseModel):
    kind: str
    config: dict[str, Any] = Field(default_factory=dict)
    drivers: dict[str, dict[str, Any]] = Field(default_factory=dict)


class ScenarioRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    run_id: UUID
    organization_id: UUID
    scenario: IntegrationScenario
    target: dict[str, Any]
    connections: dict[str, str]
    credential_provider: ProviderSpec
    run_token: SecretStr


class ScenarioCleanupRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    run_id: UUID
    organization_id: UUID
    scenario: IntegrationScenario
    target: dict[str, Any] = Field(default_factory=dict)
    connections: dict[str, str]
    credential_provider: ProviderSpec
    run_token: SecretStr
    objects: list[ObjectRecord] = Field(default_factory=list, max_length=100)


def catalog() -> list[IntegrationScenario]:
    directory = Path(os.getenv("ARGUS_SCENARIO_CATALOG_DIR", str(CATALOG_DIR)))
    scenarios = [IntegrationScenario.model_validate(yaml.safe_load(p.read_text())) for p in sorted(directory.glob("*.yaml"))]
    for scenario in scenarios:
        for spec in scenario.objects.values():
            if spec.template:
                spec.content, spec.template = read_template(directory, spec.template), None
        for control in scenario.controls:
            for key, name in control.replace.items():
                control.contents[key] = read_template(directory, name)
            control.replace = {}
    return scenarios


@router.get("/scenarios")
def list_scenarios():
    return [{"id": s.id, "name": s.name, "description": s.description, "scenario": s.model_dump(mode="json", by_alias=True)} for s in catalog()]


def create_runner(req, emit=None):
    validate_target_credentials(req.target)
    provider = build_credential_provider(req.credential_provider.kind, req.credential_provider.config, req.run_token, req.connections)
    names = {spec.driver for spec in req.scenario.objects.values()} | {s.driver for s in req.scenario.observe} | {s.driver for s in req.scenario.readiness if s.driver}
    drivers = build_drivers(names, provider, req.credential_provider.drivers)
    target = build_target(req.target)
    runner = ScenarioRunner(req.scenario, target, drivers, run_id=str(req.run_id), organization_id=str(req.organization_id),
                            connections=req.connections, target_identity=req.scenario.identities.get("target_agent", {}).get("declared_account", ""),
                            directory=Path(os.getenv("ARGUS_SCENARIO_RUN_DIR", "/tmp/argus-scenarios")), emit=emit)
    runner.ctx.secrets.add(req.run_token.get_secret_value())
    if req.target.get("api_key"):
        runner.ctx.secrets.add(req.target["api_key"])
    raw_headers = req.target.get("request_headers", {})
    for _, value in raw_headers.items() if isinstance(raw_headers, dict) else raw_headers:
        if isinstance(value, str):
            runner.ctx.secrets.add(value)
            if value.lower().startswith("bearer "):
                runner.ctx.secrets.add(value[7:])
    return runner


def encode(event: dict) -> bytes:
    return f"event: {event['type']}\ndata: {json.dumps(event)}\n\n".encode()


@router.post("/scenario/run")
async def run_scenario(req: ScenarioRunRequest):
    run_id = str(req.run_id)
    if run_id in _active_runs:
        raise HTTPException(409, "scenario run is already active")
    queue: asyncio.Queue = asyncio.Queue(maxsize=200)
    try:
        runner = create_runner(req, queue.put)
    except Exception:
        raise HTTPException(422, "scenario target or integration plugins are not configured") from None
    _active_runs.add(run_id)

    async def execute():
        try:
            result = await runner.run()
            await runner.event("finding", finding=runner.finding(result))
            await runner.event("end", outcome=result.outcome, complete=True)
        except asyncio.CancelledError:
            raise
        except Exception:
            await runner.event("error", detail="scenario execution failed")
        finally:
            _active_runs.discard(run_id)
            await queue.put(None)

    async def stream():
        task = asyncio.create_task(execute())
        try:
            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), 30)
                except asyncio.TimeoutError:
                    event = {"type": "heartbeat", "run_id": run_id, "organization_id": str(req.organization_id),
                             "phase": runner.phase, "heartbeat_at": now().isoformat()}
                if event is None:
                    break
                yield encode(event)
        finally:
            if not task.done():
                # A disconnected caller cannot strand cleanup behind a full SSE queue.
                runner.emit = None
                while not queue.empty():
                    queue.get_nowait()
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    return StreamingResponse(stream(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@router.post("/scenario/cleanup")
async def cleanup_scenario(req: ScenarioCleanupRequest):
    if str(req.run_id) in _active_runs:
        raise HTTPException(409, "cannot clean an active scenario")
    # Cleanup uses a target that never sends prompts; the configured provider enforces cleanup-only scopes.
    class CleanupTarget:
        async def aclose(self):
            pass

    try:
        provider = build_credential_provider(req.credential_provider.kind, req.credential_provider.config, req.run_token, req.connections)
        names = {obj.provider for obj in req.objects} | {s.driver for s in req.scenario.objects.values()} | {s.driver for s in req.scenario.observe}
        drivers = build_drivers(names, provider, req.credential_provider.drivers)
        runner = ScenarioRunner(req.scenario, CleanupTarget(), drivers, run_id=str(req.run_id), organization_id=str(req.organization_id),
                                connections=req.connections, target_identity="", directory=Path(os.getenv("ARGUS_SCENARIO_RUN_DIR", "/tmp/argus-scenarios")))
        runner.ctx.secrets.add(req.run_token.get_secret_value())
        for obj in req.objects:
            if obj.run_id != str(req.run_id) or obj.connection_id not in req.connections.values() or obj.marker != object_marker(str(req.run_id), obj.group, obj.logical_key, obj.control_name):
                raise ValueError("cleanup object identity mismatch")
            runner.ctx.registry.save(obj)
        await runner.cleanup()
        return runner.ctx.redact({"run_id": str(req.run_id), "organization_id": str(req.organization_id), "complete": not runner.cleanup_gaps and all(o.cleanup_status in {"deleted", "not_applicable"} for o in runner.ctx.registry.records.values()),
                                  "gaps": runner.cleanup_gaps, "objects": [o.model_dump(mode="json") for o in runner.ctx.registry.records.values()]})
    except Exception:
        raise HTTPException(422, "cleanup context or plugins are invalid") from None
