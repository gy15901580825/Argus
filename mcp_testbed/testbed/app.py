"""Hostile MCP testbed -- a deliberately malicious MCP server for red-team probes.

This service exists so a probe can answer "which tools did the agent call,
with what arguments" as a fact read straight off a request log, rather than as
a judge's opinion of the transcript. It opens a session per probe run, stages
one of the five hostile scenarios in `testbed/scenarios.py`, and reports every
JSON-RPC interaction back as evidence.
"""

from __future__ import annotations

import asyncio
import json
import os
import hmac
import time

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse
from anyio import CancelScope

from .fixed import FixedEndpoint, LeaseHeld, LeaseMismatch, DynamicOnly, FIXED_PROTOCOL_VERSIONS
from .rpc import ElicitPending, handle_request
from .scenarios import SCENARIOS
from .session import Script, Session, SessionStore

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
ELICIT_TIMEOUT_S = 10.0


class _ElicitLifetime:
    def __init__(self, session: Session, pending: ElicitPending):
        self.session = session
        self.pending = pending
        self.future = session._register_elicitation(pending.request["id"])
        self.reserved = True
        self.terminal_recorded = False
        session.in_flight += 1

    def record_once(self, response: dict | None) -> None:
        if self.terminal_recorded or self.session._frozen_evidence is not None:
            return
        if (
            response is not None and response.get("action") == "disconnected"
            and self.future.done() and not self.future.cancelled()
            and self.future.exception() is None
        ):
            received = self.future.result()
            if isinstance(received, dict):
                response = {**response, "content": received.get("content")}
        pending = self.pending
        self.session.world.record_elicitation(
            pending.tool, pending.request["params"], response,
            seq=pending.seq, conversation=pending.conversation,
        )
        self.terminal_recorded = True

    def finish(self) -> None:
        self.record_once({"action": "disconnected"})
        request_id = self.pending.request["id"]
        if self.session._elicitations.get(request_id) is self.future:
            del self.session._elicitations[request_id]
        if self.reserved:
            self.reserved = False
            self.session.in_flight -= 1


class _ElicitResponse(StreamingResponse):
    def __init__(
        self, session: Session, pending: ElicitPending, lifetime: _ElicitLifetime
    ):
        super().__init__(
            _elicit_stream(session, pending, _lifetime=lifetime),
            media_type="text/event-stream",
        )
        self._lifetime = lifetime

    async def __call__(self, scope, receive, send) -> None:
        try:
            await super().__call__(scope, receive, send)
        finally:
            try:
                with CancelScope(shield=True):
                    await self.body_iterator.aclose()
            finally:
                self._lifetime.finish()


async def _elicit_stream(
    session: Session, pending: ElicitPending, *, _lifetime: _ElicitLifetime
):
    try:
        if session._frozen_evidence is not None:
            return
        session.world.elicitation_sent(
            seq=pending.seq, conversation=pending.conversation
        )
        yield f"event: message\ndata: {json.dumps(pending.request)}\n\n"
        response = await session.wait_elicitation(
            pending.request["id"], ELICIT_TIMEOUT_S
        )
        if session._frozen_evidence is not None:
            return
        _lifetime.record_once(response)
        result = session.world.call(
            pending.tool, pending.arguments,
            seq=pending.seq, conversation=pending.conversation,
        )
        final = {"jsonrpc": "2.0", "id": pending.call_id, "result": result}
        yield f"event: message\ndata: {json.dumps(final)}\n\n"
    except (asyncio.CancelledError, GeneratorExit):
        _lifetime.record_once({"action": "disconnected"})
        raise
    finally:
        _lifetime.finish()


def _respond(session: Session, body: dict) -> dict | Response:
    if (
        session.world is not None
        and session.world.spec.elicit is not None
        and session._frozen_evidence is not None
    ):
        raise HTTPException(409, "world is sealed")
    if "method" not in body and "id" in body and ("result" in body or "error" in body):
        session.interaction_count += 1
        counts = session.interaction_count_by_session.setdefault(
            str(session.conversation), {"requests": 0, "tool_calls": 0}
        )
        counts["requests"] += 1
        session.resolve_elicitation(body)
        return Response(status_code=202)
    result = handle_request(session, body)
    if isinstance(result, ElicitPending):
        lifetime = _ElicitLifetime(session, result)
        try:
            return _ElicitResponse(session, result, lifetime)
        except BaseException:
            lifetime.finish()
            raise
    return result


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
    try:
        session = STORE.open(script)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    result = {
        "session_id": session.id,
        "mcp_url": f"{_base_url(request)}/s/{session.id}/mcp",
        "script": {"scenario": script.scenario},
    }
    if session.world is not None and session.world.spec.second_tools is not None:
        result["mcp_url_2"] = f"{_base_url(request)}/s/{session.id}/mcp2"
    if session.world is not None and "user_secret" in session.world.canaries:
        result["user_secret"] = session.world.canaries["user_secret"]
    return result


@app.post("/s/{sid}/mcp2")
async def second_mcp(sid: str, request: Request):
    session = _require(sid)
    if session.world is None or session.world.spec.second_tools is None:
        raise HTTPException(404, "this session has no second MCP server")
    if session.sealed:
        raise HTTPException(409, "world is sealed")
    session.in_flight += 1
    try:
        body = await request.json()
        return handle_request(session, body, server="second")
    finally:
        session.in_flight -= 1


@app.post("/s/{sid}/mcp")
async def mcp(sid: str, request: Request):
    session = _require(sid)
    if session.sealed:
        raise HTTPException(409, "world is sealed")
    session.in_flight += 1
    try:
        body = await request.json()
        return _respond(session, body)
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
        result = _respond(session, body)
        if "id" not in body and isinstance(method, str) and method.startswith("notifications/"):
            return Response(status_code=202)
        if method == "initialize":
            requested = (body.get("params") or {}).get("protocolVersion")
            result["result"]["protocolVersion"] = requested if requested in FIXED_PROTOCOL_VERSIONS else FIXED_PROTOCOL_VERSIONS[-1]
            session.protocol_version = result["result"]["protocolVersion"]
            return JSONResponse(result, headers={"Mcp-Session-Id": FIXED.issue_session_id()})
        return result
    finally:
        session.in_flight -= 1
