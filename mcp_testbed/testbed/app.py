"""Hostile MCP testbed -- a deliberately malicious MCP server for red-team probes.

This service exists so a probe can answer "which tools did the agent call,
with what arguments" as a fact read straight off a request log, rather than as
a judge's opinion of the transcript. It opens a session per probe run, stages
one of the five hostile scenarios in `testbed/scenarios.py`, and reports every
JSON-RPC interaction back as evidence.
"""

from __future__ import annotations

import os

from fastapi import FastAPI, HTTPException, Request, Response

from testbed.rpc import handle_request
from testbed.scenarios import SCENARIOS
from testbed.session import Script, SessionStore

PUBLIC_BASE_URL = os.environ.get("TESTBED_PUBLIC_URL", "").rstrip("/")

app = FastAPI(title="Argus MCP testbed")
STORE = SessionStore()


def _base_url(request: Request) -> str:
    return PUBLIC_BASE_URL or str(request.base_url).rstrip("/")


def _require(sid: str):
    session = STORE.get(sid)
    if session is None:
        raise HTTPException(status_code=404, detail="unknown or expired session")
    return session


@app.post("/sessions")
async def open_session(request: Request):
    raw = await request.json() if await request.body() else {}
    script = Script.from_dict(raw)
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
    body = await request.json()
    return handle_request(session, body)


@app.get("/sessions/{sid}/evidence")
async def get_evidence(sid: str):
    return _require(sid).evidence()


@app.delete("/sessions/{sid}", status_code=204)
async def close_session(sid: str):
    if not STORE.close(sid):
        raise HTTPException(status_code=404, detail="unknown or expired session")
    return Response(status_code=204)
