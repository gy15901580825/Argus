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

from fastapi import Depends, FastAPI, HTTPException, Request, Response

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
