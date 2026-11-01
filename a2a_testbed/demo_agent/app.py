"""OpenAI-compatible Planner and A2A Reviewer and Executor endpoints."""

from __future__ import annotations

import secrets
import re
from http import HTTPStatus
import os
import json
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from . import client, roles


@asynccontextmanager
async def lifespan(application):
    configure_environment()
    yield


app = FastAPI(lifespan=lifespan)
state = None


def configure(
    *,
    peer_base_url: str,
    credentials: dict[str, str],
    driver_credential: str = "",
    weaknesses: str = "safe",
) -> None:
    global state
    state = roles.DemoState.configured(credentials, driver_credential, weaknesses)
    client.configure(peer_base_url)


def configure_environment() -> None:
    global state
    origin = os.environ.get("TESTBED_ORIGIN", "").strip()
    credentials = os.environ.get("A2A_AGENT_CREDENTIALS", "")
    driver = os.environ.get("A2A_DRIVER_CREDENTIAL", "")
    if not origin and not credentials and not driver:
        return
    try:
        parsed = json.loads(credentials)
        if not isinstance(parsed, dict):
            raise ValueError()
        configure(
            peer_base_url=origin,
            credentials=parsed,
            driver_credential=driver,
            weaknesses=os.environ.get("DEMO_WEAKNESSES", "safe"),
        )
    except Exception:
        state = None
        client.peer_base_url = ""
        client.agent_base_url = ""
        raise ValueError("invalid A2A demo environment configuration") from None


def response(data, status=200):
    return JSONResponse(data, status_code=status, media_type="application/a2a+json")


def protocol_error_json(code_name: str, http_status: int) -> dict:
    statuses = {
        400: "INVALID_ARGUMENT",
        401: "UNAUTHENTICATED",
        403: "PERMISSION_DENIED",
        404: "NOT_FOUND",
        409: "ABORTED",
        413: "RESOURCE_EXHAUSTED",
        429: "RESOURCE_EXHAUSTED",
        500: "INTERNAL",
        503: "UNAVAILABLE",
    }
    details = []
    if code_name.endswith("Error"):
        reason = re.sub(
            r"(?<!^)(?=[A-Z])", "_", code_name.removesuffix("Error")
        ).upper()
        details.append(
            {
                "@type": "type.googleapis.com/google.rpc.ErrorInfo",
                "reason": reason,
                "domain": "a2a-protocol.org",
            }
        )
    return {
        "error": {
            "code": http_status,
            "status": statuses.get(http_status, "UNKNOWN"),
            "message": HTTPStatus(http_status).phrase,
            "details": details,
        }
    }


def protocol_error(code_name: str, status: int):
    return response(protocol_error_json(code_name, status), status)


def listener_url(request: Request) -> str:
    host, port = request.scope["server"]
    host = {"0.0.0.0": "127.0.0.1", "::": "::1"}.get(host, host)
    if ":" in host:
        host = "[" + host + "]"
    return f"http://{host}:{port or 80}"


@app.get("/healthz")
async def health():
    return {"status": "ok"}


@app.post("/v1/chat/completions")
async def chat(request: Request):
    if state is None:
        return response({"error": "agent is not configured"}, 503)
    client.set_agent_origin(listener_url(request))
    body = await request.json()
    prompt = next(
        (
            m.get("content", "")
            for m in reversed(body.get("messages", []))
            if m.get("role") == "user"
        ),
        "",
    )
    try:
        text = await roles.planner(state, prompt)
    except (ValueError, KeyError, TypeError) as exc:
        return response({"error": str(exc)}, 400)
    return {
        "id": "chat-" + secrets.token_hex(8),
        "object": "chat.completion",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": text},
                "finish_reason": "stop",
            }
        ],
    }


@app.get("/agents/{role}/.well-known/agent-card.json")
async def card(role: str, request: Request):
    if role not in ("reviewer", "executor"):
        return protocol_error("agent_unknown", 404)
    root = listener_url(request) + "/agents/" + role
    return response(
        {
            "name": role.title(),
            "description": "Reviews and executes approved invoice payments.",
            "version": "1",
            "supportedInterfaces": [
                {"url": root, "protocolBinding": "HTTP+JSON", "protocolVersion": "1.0"}
            ],
            "capabilities": {},
            "defaultInputModes": ["application/json"],
            "defaultOutputModes": ["application/json"],
            "skills": [
                {"id": "payment_review", "name": "Review payment", "tags": ["invoice"]}
            ],
            "securitySchemes": {
                "bearer": {"httpAuthSecurityScheme": {"scheme": "Bearer"}}
            },
            "securityRequirements": [{"schemes": {"bearer": {"list": []}}}],
        }
    )


@app.post("/agents/{role}/message:send")
async def receive(role: str, request: Request):
    if state is None:
        return protocol_error("agent_unavailable", 503)
    if role not in ("reviewer", "executor"):
        return protocol_error("agent_unknown", 404)
    credential = request.headers.get("Authorization", "")
    caller = next(
        (name for name, value in state.credentials.items() if value == credential),
        (
            "driver"
            if state.driver_credential and state.driver_credential == credential
            else None
        ),
    )
    allowed = ("planner",) if role == "reviewer" else ("reviewer", "driver")
    if caller not in allowed:
        return protocol_error("UnauthenticatedError", 401)
    if request.headers.get("A2A-Version") != "1.0":
        return protocol_error("VersionNotSupportedError", 400)
    client.set_agent_origin(listener_url(request))
    try:
        body = await request.json()
    except ValueError:
        return protocol_error("InvalidArgumentError", 400)
    msg = body.get("message") if isinstance(body, dict) else None
    if (
        not isinstance(msg, dict)
        or not isinstance(msg.get("messageId"), str)
        or not msg["messageId"]
        or msg.get("role") != "ROLE_USER"
        or not isinstance(msg.get("parts"), list)
        or not msg["parts"]
    ):
        return protocol_error("InvalidArgumentError", 400)
    for part in msg["parts"]:
        if (
            not isinstance(part, dict)
            or sum(key in part for key in ("text", "data", "url", "raw")) != 1
        ):
            return protocol_error("InvalidArgumentError", 400)
        if any(
            key in part and not isinstance(part[key], str)
            for key in ("text", "url", "raw")
        ):
            return protocol_error("InvalidArgumentError", 400)
        if "data" in part and not isinstance(part["data"], dict):
            return protocol_error("InvalidArgumentError", 400)
    if caller != "driver":
        await roles.observe(state, role, "message_received", caller, msg)
    data, _ = roles.contents(msg)
    if role == "executor":
        data.setdefault("operation", "release_payment")
    try:
        text, completed = await (
            roles.reviewer(state, data, msg)
            if role == "reviewer"
            else roles.execute(state, data, msg)
        )
    except (ValueError, KeyError, TypeError) as exc:
        text, completed = str(exc), False
    task_id = "T-" + secrets.token_hex(8)
    task = {
        "id": task_id,
        "contextId": msg.get("contextId") or "C-" + secrets.token_hex(8),
        "status": {
            "state": "TASK_STATE_COMPLETED" if completed else "TASK_STATE_REJECTED",
            "message": {
                "messageId": task_id + "-reply",
                "role": "ROLE_AGENT",
                "parts": [{"text": text}],
            },
        },
    }
    return response({"task": task})
