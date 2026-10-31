"""Hostile MCP testbed -- a deliberately malicious MCP server for red-team probes.

This service exists so a probe can answer "which tools did the agent call,
with what arguments" as a fact read straight off a request log, rather than as
a judge's opinion of the transcript. It opens a session per probe run, stages
one of the five hostile scenarios in `testbed/scenarios.py`, and reports every
JSON-RPC interaction back as evidence.
"""

from __future__ import annotations

import os
import hmac
import time

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse

from .fixed import FixedEndpoint, LeaseHeld, LeaseMismatch, DynamicOnly, FIXED_PROTOCOL_VERSIONS
from .rpc import handle_request
from .scenarios import SCENARIOS
from .session import Script, SessionStore

PUBLIC_BASE_URL = os.environ.get("TESTBED_PUBLIC_URL", "").rstrip("/")

CONTROL_TOKEN = os.environ.get("TESTBED_CONTROL_TOKEN", "")


def require_control(request: Request) -> None:
    if not CONTROL_TOKEN:
        raise HTTPException(503, "TESTBED_CONTROL_TOKEN is not set")
    supplied = request.headers.get("Authorization", "")
    if not hmac.compare_digest(supplied, "Bearer " + CONTROL_TOKEN):
        raise HTTPException(401, "invalid control token", headers={"WWW-Authenticate": "Bearer"})


app = FastAPI(title="Argus MCP testbed")
STORE = SessionStore()
FIXED = FixedEndpoint()


def _base_url(request: Request) -> str:
    return PUBLIC_BASE_URL or str(request.base_url).rstrip("/")


def _require(sid: str):
    session = STORE.get(sid)
    if session is None:
        raise HTTPException(status_code=404, detail="unknown or expired session")
    return session


@app.post("/sessions", dependencies=[Depends(require_control)])
async def open_session(request: Request):
    raw = await request.json() if await request.body() else {}
    try:
        script = Script.from_dict(raw)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    if script.scenario not in SCENARIOS:
        raise HTTPException(
            status_code=400,
            detail=(
                f"unknown scenario: {script.scenario!r}. "
                f"valid scenarios: {sorted(SCENARIOS)}"
            ),
        )
    session = STORE.open(script)
    return {
        "session_id": session.id,
        "mcp_url": f"{_base_url(request)}/s/{session.id}/mcp",
        "script": {"scenario": script.scenario},
    }


@app.post("/s/{sid}/mcp")
async def mcp(sid: str, request: Request):
    session = _require(sid)
    if session.sealed:
        raise HTTPException(409, "world is sealed")
    session.in_flight += 1
    try:
        body = await request.json()
        return handle_request(session, body)
    finally:
        session.in_flight -= 1


@app.get("/sessions/{sid}/evidence", dependencies=[Depends(require_control)])
async def get_evidence(sid: str):
    return _require(sid).evidence()


@app.delete("/sessions/{sid}", status_code=204, dependencies=[Depends(require_control)])
async def close_session(sid: str):
    session = STORE.get(sid)
    if session is not None and FIXED.active is session:
        await FIXED.close(session)
    if not STORE.close(sid):
        raise HTTPException(status_code=404, detail="unknown or expired session")
    return Response(status_code=204)


@app.post("/sessions/{sid}/conversations", dependencies=[Depends(require_control)])
async def next_conversation(sid: str):
    session = _require(sid)
    if session.sealed:
        raise HTTPException(409, "world is sealed")
    return {"conversation": session.next_conversation()}


@app.post("/sessions/{sid}/seal", dependencies=[Depends(require_control)])
async def seal_session(sid: str):
    return await _require(sid).seal()


@app.post("/lease", status_code=201, dependencies=[Depends(require_control)])
async def acquire_lease(request: Request):
    raw = await request.json() if await request.body() else {}
    try:
        lease = FIXED.acquire(raw.get("ttl_s"), time.monotonic())
    except LeaseHeld as exc:
        raise HTTPException(409, {"code": "lease_held", "expires_in": exc.expires_in}) from exc
    except (ValueError, TypeError) as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"lease_id": lease.lease_id, "ttl_s": lease.ttl_s}


@app.get("/lease/{lease_id}", dependencies=[Depends(require_control)])
async def inspect_lease(lease_id: str):
    FIXED._expire(time.monotonic())
    if not FIXED.lease or FIXED.lease.lease_id != lease_id:
        raise HTTPException(404, "unknown lease")
    return {"generation": FIXED.generation, "active_session_id": FIXED.active.id if FIXED.active else None,
            "rejected_requests": FIXED.rejected, "expires_in": max(0, FIXED.lease.expires_at - time.monotonic())}


@app.delete("/lease/{lease_id}", status_code=204, dependencies=[Depends(require_control)])
async def release_lease(lease_id: str):
    if not FIXED.lease or FIXED.lease.lease_id != lease_id:
        raise HTTPException(404, "unknown lease")
    if FIXED.active:
        await FIXED.close(FIXED.active)
    FIXED.release(lease_id)
    return Response(status_code=204)


@app.post("/lease/{lease_id}/activate", dependencies=[Depends(require_control)])
async def activate_world(lease_id: str, request: Request):
    raw = await request.json()
    session = _require(raw.get("session_id", ""))
    try:
        generation = await FIXED.activate(lease_id, session, time.monotonic())
    except LeaseMismatch as exc:
        raise HTTPException(409, {"code": "lease_mismatch"}) from exc
    except DynamicOnly as exc:
        raise HTTPException(422, {"code": "dynamic_only"}) from exc
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    return {"generation": generation, "mcp_url": _base_url(request) + "/mcp"}


@app.post("/mcp")
async def fixed_mcp(request: Request):
    now = time.monotonic()
    FIXED._expire(now)
    if FIXED.lease:
        FIXED.touch(FIXED.lease.lease_id, now)
    body = await request.json()
    method = body.get("method")
    route = FIXED.route(request.headers.get("Mcp-Session-Id"), method)
    if not route.ok:
        return JSONResponse({"detail": route.reason}, status_code=route.status)
    session = route.session
    session.in_flight += 1
    try:
        result = handle_request(session, body)
        if "id" not in body and isinstance(method, str) and method.startswith("notifications/"):
            return Response(status_code=202)
        if method == "initialize":
            requested = (body.get("params") or {}).get("protocolVersion")
            result["result"]["protocolVersion"] = requested if requested in FIXED_PROTOCOL_VERSIONS else FIXED_PROTOCOL_VERSIONS[-1]
            return JSONResponse(result, headers={"Mcp-Session-Id": FIXED.issue_session_id()})
        return result
    finally:
        session.in_flight -= 1
