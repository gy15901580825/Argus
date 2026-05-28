import json
import logging
import os
import time
import httpx
import base64
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, Depends, Request, Header
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from typing import Dict, Any, Optional

from auth import get_current_user, get_optional_user
from models import UserResponse, ScriptCreate, ScriptResponse, WizardState, WizardInput
from database import database
from r2_storage import r2_storage
from subscription_middleware import check_and_increment_quota, get_user_plan
import re

from wizard_state_store import (
    initialize_wizard_state, apply_wizard_input, append_round_from_event,
    set_dispatched, synthesize_fast_forward,
    StaleRoundError, InvalidTransitionError,
)
from models import BoundContext
from agent_connectivity import check_client_agent_connected, check_cdp_reachable
from metrics import (
    WIZARD_ROUNDS_TOTAL, WIZARD_DISPATCH_TOOL_TOTAL,
    WIZARD_VALIDATION_ERRORS_TOTAL, WIZARD_BACKS_TOTAL,
    WIZARD_ABORTS_TOTAL, WIZARD_FAST_FORWARDS_TOTAL,
    WIZARD_LOCAL_SETUP_CHECKS_TOTAL, WIZARD_ROUND_LATENCY_SECONDS,
)

router = APIRouter()
logger = logging.getLogger("OrchestratorRouter")

# Orchestrator URL — env var override so dev/staging can point at a different namespace
ORCHESTRATOR_URL = os.getenv(
    "ORCHESTRATOR_URL",
    "http://argus-orchestrator.default.svc.cluster.local:8080",
)

class CommandRequest(BaseModel):
    """Request model for agent command execution"""
    agent_id: str = Field(..., description="ID of the agent to execute the command on")
    tool_name: str = Field(..., description="Name of the tool to execute")
    arguments: Dict[str, Any] = Field(..., description="Arguments for the tool")

class SSHConfigModel(BaseModel):
    """SSH configuration for remote test execution"""
    remote_ip: str = Field(..., description="Remote host IPv4 address")
    username: str = Field(..., description="SSH username")
    pem_key_base64: str = Field(..., description="PEM private key encoded as base64")
    pytest_args: Optional[str] = Field("--alluredir=./allure-results -v", description="Pytest arguments")

class StrategyRequest(BaseModel):
    """Request model for strategy generation"""
    content: str = Field(..., description="The source content to analyze and generate test strategy for")
    context: Optional[Dict[str, Any]] = Field(None, description="Additional context information for strategy generation")
    session_id: Optional[str] = Field(None, description="Optional session ID for tracking the request")
    user_id: Optional[str] = Field(None, description="Optional user ID for user-specific strategy generation")
    local_test_enabled: Optional[bool] = Field(False, description="Enable local client agent testing")
    remote_test_enabled: Optional[bool] = Field(False, description="Enable remote test execution via test-runner or SSH")
    ssh_config: Optional[SSHConfigModel] = Field(None, description="SSH configuration for remote test execution")
    # NEW: wizard fields
    cdp_url: Optional[str] = Field(None, description="CDP URL for local Web UI testing")
    user_persona: Optional[str] = Field(None, description="Persona label")
    wizardInput: Optional[WizardInput] = Field(None, description="User's click/input for current wizard round")

@router.post("/orchestrator/run_command")
async def run_command(request: CommandRequest):
    """
    Proxy command to Orchestrator service.
    No authentication required.
    """
    logger.info(f"Sending command to agent {request.agent_id}")
    
    url = f"{ORCHESTRATOR_URL}/orchestrator/run_command"
    
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                url,
                json=request.dict(),
                timeout=60.0 # Increase timeout for agent operations
            )
            
            # Raise exception for 4xx/5xx status codes
            response.raise_for_status()
            
            return response.json()
            
        except httpx.HTTPStatusError as e:
            logger.error(f"Orchestrator returned error: {e.response.text}")
            # Try to return the detailed error from orchestrator if JSON
            try:
                error_detail = e.response.json()
                raise HTTPException(status_code=e.response.status_code, detail=error_detail)
            except ValueError:
                raise HTTPException(status_code=e.response.status_code, detail=str(e))
                
        except httpx.RequestError as e:
            logger.error(f"Error connecting to orchestrator: {e}")
            raise HTTPException(status_code=503, detail="Orchestrator service unavailable")
        except Exception as e:
            logger.error(f"Unexpected error proxying command: {e}")
            raise HTTPException(status_code=500, detail="Internal server error")

@router.post("/orchestrator/cancel-web-ui-test")
async def cancel_web_ui_test(
    request: Request,
    current_user: UserResponse = Depends(get_current_user),
):
    """
    Proxy cancel request to Orchestrator service.
    Sends the authenticated user's ID so the orchestrator can find and cancel the active task.
    """
    url = f"{ORCHESTRATOR_URL}/orchestrator/v1/cancel-web-ui-test"
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                url,
                json={"user_id": str(current_user.id)},
                timeout=15.0,
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            try:
                error_detail = e.response.json()
                raise HTTPException(status_code=e.response.status_code, detail=error_detail)
            except ValueError:
                raise HTTPException(status_code=e.response.status_code, detail=str(e))
        except httpx.RequestError as e:
            logger.error(f"Error connecting to orchestrator for cancel: {e}")
            raise HTTPException(status_code=503, detail="Orchestrator service unavailable")

@router.post("/orchestrator/strategy/stream")
async def stream_strategy(
    request: StrategyRequest,
    x_trial_token: Optional[str] = Header(None, alias="x-trial-token"),
    current_user: Optional[UserResponse] = Depends(get_optional_user),
):
    """
    Stream strategy generation from Orchestrator service.
    Returns Server-Sent Events (SSE) stream.

    Supports optional trial token authentication via x-trial-token header.
    When a trial token is provided, it is validated and consumed atomically
    before the stream begins.

    For authenticated users, checks subscription quota before streaming.
    """
    # If trial token provided, validate and consume it before streaming
    if x_trial_token:
        logger.info(f"Trial token provided: {x_trial_token[:8]}...")

        # Validate the token
        validate_query = """
            SELECT token, target_url, is_consumed, expires_at
            FROM trial_tokens
            WHERE token = :token
        """
        row = await database.fetch_one(query=validate_query, values={"token": x_trial_token})

        if not row:
            raise HTTPException(status_code=401, detail="Invalid trial token")
        if row["is_consumed"]:
            raise HTTPException(status_code=410, detail="Trial token has already been used. Sign up to continue testing.")
        if row["expires_at"] < datetime.now(timezone.utc):
            raise HTTPException(status_code=410, detail="Trial token has expired. Sign up to continue testing.")

        # Consume the token atomically
        consume_query = """
            UPDATE trial_tokens
            SET is_consumed = TRUE, consumed_at = NOW()
            WHERE token = :token AND is_consumed = FALSE AND expires_at > NOW()
        """
        await database.execute(query=consume_query, values={"token": x_trial_token})
        logger.info(f"Trial token consumed: {x_trial_token[:8]}...")

    # For authenticated users: check quota and inject plan
    user_plan = "free"
    if current_user and not x_trial_token:
        await check_and_increment_quota(current_user.id)
        user_plan = await get_user_plan(current_user.id)
        logger.info(f"User {current_user.id} plan={user_plan}, quota incremented")

    logger.info(f"Requesting strategy generation (local_test={request.local_test_enabled})")

    url = f"{ORCHESTRATOR_URL}/orchestrator/v1/strategy/stream"

    # ---- Wizard lifecycle -----------------------------------------------
    wizard_state_dict: Optional[dict] = None
    synthesized_event_prefix: list = []

    if request.session_id and current_user:
        row = await database.fetch_one(
            "SELECT wizard_state FROM chat_sessions WHERE id = :id AND user_id = :uid",
            {"id": request.session_id, "uid": str(current_user.id)},
        )
        # databases.Record has no .get(); use subscript and guard the None case.
        raw = row["wizard_state"] if row else None
        if isinstance(raw, str):
            raw = json.loads(raw)

        # "First turn" = no completed assistant turn yet. The frontend persists the
        # user's message before /strategy/stream is called, so checking *any*
        # message would always be truthy and skip wizard init forever.
        has_assistant_message = await database.fetch_val(
            "SELECT 1 FROM chat_messages WHERE session_id = :sid AND role = 'assistant' LIMIT 1",
            {"sid": request.session_id},
        )

        if raw is None and not has_assistant_message and _flag_enabled():
            test_env = "cloud"
            if request.local_test_enabled:
                test_env = "my_machine"
            elif request.remote_test_enabled and request.ssh_config:
                test_env = "remote_ssh"

            bound_context_args = {
                "test_env": test_env,
                "ssh_config_present": bool(request.ssh_config),
                "cdp_url_present": bool(request.cdp_url),
                "persona": request.user_persona,
                "url": (request.context or {}).get("url"),
                "client_agent_connected": await check_client_agent_connected(current_user.id),
                "cdp_browser_reachable": await check_cdp_reachable(current_user.id, request.cdp_url),
            }

            # Spec §7.3: when the user's first message + bound_context fully
            # specify all four pre-confirm slots, synthesize the rounds and
            # jump straight to round_n=5 (confirm). Otherwise fall through to
            # the regular round-by-round init.
            parsed = _try_parse_message_into_slots(
                message=request.content or "",
                bound_context_args=bound_context_args,
            )
            if parsed is not None:
                new_ws = synthesize_fast_forward(
                    bound_context=BoundContext(**bound_context_args),
                    parsed_slots=parsed,
                    now=time.time(),
                )
                # Bucket fast-forwards by # of bound (vs parsed) slots.
                bound_slot_count = sum(
                    1 for r in new_ws.rounds if r.answer_kind == "bound_context_skip"
                )
                WIZARD_FAST_FORWARDS_TOTAL.labels(
                    matched_fields_count=str(bound_slot_count),
                ).inc()
                logger.info("wizard_fast_forwarded", extra={
                    "session_id": request.session_id,
                    "user_id": str(current_user.id),
                    "bound_slot_count": bound_slot_count,
                })
            else:
                new_ws = initialize_wizard_state(**bound_context_args)
            await _save_wizard_state(request.session_id, new_ws)
            logger.info("wizard_session_started", extra={
                "session_id": request.session_id,
                "user_id": str(current_user.id),
                "bound_context": new_ws.bound_context.model_dump(exclude_none=True),
                "round_n": new_ws.round_n,
            })
            wizard_state_dict = new_ws.model_dump()
        elif raw is not None:
            ws = WizardState.model_validate(raw)
            ws = ws.model_copy(update={
                "bound_context": ws.bound_context.model_copy(update={
                    "client_agent_connected": await check_client_agent_connected(current_user.id),
                    "cdp_browser_reachable": await check_cdp_reachable(current_user.id, request.cdp_url),
                })
            })

            if request.wizardInput:
                # Capture the round label we're about to leave (only meaningful for back).
                pre_apply_label = ws.rounds[-1].round_label if ws.rounds else "other"
                try:
                    ws = apply_wizard_input(ws, request.wizardInput, now=time.time())
                except StaleRoundError:
                    WIZARD_VALIDATION_ERRORS_TOTAL.labels(error_type="stale_round").inc()
                    raise HTTPException(
                        status_code=409,
                        detail={
                            "reason": "stale_round",
                            "current_round_n": ws.round_n,
                            "wizard_state": ws.model_dump(),
                        },
                    )
                except InvalidTransitionError as e:
                    WIZARD_VALIDATION_ERRORS_TOTAL.labels(error_type="invalid_transition").inc()
                    raise HTTPException(status_code=400, detail=str(e))

                logger.info("wizard_answered", extra={
                    "session_id": request.session_id,
                    "round_n": request.wizardInput.roundN,
                    "answer_kind": request.wizardInput.kind,
                    "answer_preview": (request.wizardInput.value or "")[:50],
                })

                if request.wizardInput.kind == "back":
                    to_label = ws.rounds[-1].round_label if ws.rounds else "other"
                    WIZARD_BACKS_TOTAL.labels(
                        from_round_label=pre_apply_label,
                        to_round_label=to_label,
                    ).inc()

            if request.wizardInput and request.wizardInput.kind == "abort":
                at_label = ws.rounds[-1].round_label if ws.rounds else "other"
                rounds_used = len([r for r in ws.rounds if r.answer_kind in ("option_click", "free_text")])
                await _save_wizard_state(request.session_id, ws)
                synthesized_event_prefix.append(
                    _sse_event("wizard_aborted", {
                        "at_round_label": at_label, "rounds_used": rounds_used,
                    })
                )
                WIZARD_ABORTS_TOTAL.labels(at_round_label=at_label).inc()
                logger.info("wizard_aborted", extra={
                    "session_id": request.session_id,
                    "at_round_label": at_label,
                    "rounds_used": rounds_used,
                })

                async def _abort_only():
                    for frame in synthesized_event_prefix:
                        yield frame

                return StreamingResponse(_abort_only(), media_type="text/event-stream")

            await _save_wizard_state(request.session_id, ws)
            wizard_state_dict = ws.model_dump()
    # ---- End wizard lifecycle -------------------------------------------

    # Build request data excluding wizardInput; inject plan + wizard_state
    request_data = request.model_dump(exclude={"wizardInput"})
    if current_user:
        if request_data.get("context") is None:
            request_data["context"] = {}
        request_data["context"]["subscription_plan"] = user_plan
        request_data["context"]["user_id"] = str(current_user.id)
    if wizard_state_dict is not None:
        request_data["wizard_state"] = wizard_state_dict

    async def event_stream():
        for frame in synthesized_event_prefix:
            yield frame
        async with httpx.AsyncClient() as hx:
            try:
                async with hx.stream(
                    "POST",
                    url,
                    json=request_data,
                    timeout=httpx.Timeout(connect=30.0, read=600.0, write=30.0, pool=30.0),
                ) as response:
                    response.raise_for_status()
                    async for chunk in _intercept_and_persist(
                        response.aiter_text(), session_id=request.session_id,
                    ):
                        yield chunk

            except httpx.HTTPStatusError as e:
                logger.error(f"Orchestrator error: {e.response.text if hasattr(e, 'response') else e}")
                yield f"event: error\ndata: {json.dumps({'error': str(e)})}\n\n"

            except httpx.RequestError as e:
                logger.error(f"Connect to orchestrator: {e}")
                yield "event: error\ndata: {\"error\": \"Orchestrator unavailable\"}\n\n"

    return StreamingResponse(event_stream(), media_type="text/event-stream")


# ---------------------------------------------------------------------------
# Wizard helpers
# ---------------------------------------------------------------------------

_DISPATCH_TOOLS = {"run_web_ui_cloud", "run_web_ui_local", "run_api_test",
                   "discover_apis", "fetch_page"}


def _flag_enabled() -> bool:
    return os.getenv("WIZARD_MODE_ENABLED", "false").lower() == "true"


def _sse_event(event_type: str, payload: dict) -> str:
    return f"event: {event_type}\ndata: {json.dumps(payload)}\n\n"


# Conservative regex-based slot parser for the wizard fast-forward path
# (spec §7.3). Returns a dict keyed by the four pre-confirm slot labels
# (intent, run_where, persona, target_url) when the message + bound_context
# together cover ALL four; returns None otherwise.
_INTENT_PATTERNS: list[tuple[str, str]] = [
    (r"\bweb\s*ui\s*test(?:ing)?\b", "Web UI test"),
    (r"\bui\s*test(?:ing)?\b", "Web UI test"),
    (r"\bbrowser\s*test(?:ing)?\b", "Web UI test"),
    (r"\bapi\s*test(?:ing)?\b", "API test"),
]
_RUN_WHERE_PATTERNS: list[tuple[str, str]] = [
    (r"\bon\s+cloud\b|\bin\s+the\s+cloud\b|\bon\s+the\s+cloud\b", "cloud"),
    (r"\bon\s+my\s+machine\b|\blocally\b|\bmy\s+machine\b", "my_machine"),
]
_PERSONA_PATTERN = re.compile(r"\bas\s+(?:an?\s+)?(\w+)\b", re.IGNORECASE)
_URL_PATTERN = re.compile(r"https?://\S+")


def _try_parse_message_into_slots(
    *, message: str, bound_context_args: dict,
) -> Optional[dict]:
    """Conservatively parse a user message into the four pre-confirm slots.

    Bound context wins over parsed values: if bound_context_args already has
    test_env / persona / url, those slot values are taken from there. The
    function returns None unless ALL four slots end up filled — caller uses
    that as the gate for the fast-forward path.
    """
    if not message:
        return None
    msg = message.lower()
    parsed: dict[str, str] = {}

    # intent — only from message text (no bound-context source)
    for pat, value in _INTENT_PATTERNS:
        if re.search(pat, msg):
            parsed["intent"] = value
            break

    # run_where — bound wins, else parse
    if bound_context_args.get("test_env"):
        parsed["run_where"] = bound_context_args["test_env"]
    else:
        for pat, value in _RUN_WHERE_PATTERNS:
            if re.search(pat, msg):
                parsed["run_where"] = value
                break

    # persona — bound wins, else `as <word>` capture (case-insensitive on raw msg)
    if bound_context_args.get("persona"):
        parsed["persona"] = bound_context_args["persona"]
    else:
        m = _PERSONA_PATTERN.search(message)
        if m:
            persona_word = m.group(1).strip().lower()
            # Don't pick up trailing prepositions / articles erroneously.
            if persona_word and persona_word not in {"a", "an", "the"}:
                parsed["persona"] = persona_word

    # target_url — bound wins, else first http(s) URL in raw message
    if bound_context_args.get("url"):
        parsed["target_url"] = bound_context_args["url"]
    else:
        m = _URL_PATTERN.search(message)
        if m:
            parsed["target_url"] = m.group(0).rstrip(".,;:!?)")

    if not _all_slots_filled(parsed, bound_context_args):
        return None
    return parsed


def _all_slots_filled(parsed: dict, bound_context_args: dict) -> bool:
    """All four pre-confirm slots present (either from message or bound)."""
    for slot in ("intent", "run_where", "persona", "target_url"):
        if not parsed.get(slot):
            return False
    return True


async def _save_wizard_state(session_id: str, ws: WizardState) -> None:
    # CAST(:ws AS jsonb), not :ws::jsonb — sqlalchemy.text() parses `::` as the
    # start of a type cast and rejects the named parameter that immediately
    # precedes it.
    await database.execute(
        "UPDATE chat_sessions SET wizard_state = CAST(:ws AS jsonb), "
        "updated_at = CURRENT_TIMESTAMP WHERE id = :id",
        values={"ws": ws.model_dump_json(), "id": session_id},
    )


async def _intercept_and_persist(source, *, session_id: Optional[str]):
    buffer = ""
    async for chunk in source:
        buffer += chunk
        while "\n\n" in buffer:
            frame, buffer = buffer.split("\n\n", 1)
            yield frame + "\n\n"
            if session_id:
                await _apply_event_to_state(session_id, frame)


async def _apply_event_to_state(session_id: str, frame: str) -> None:
    event_type, payload = _parse_sse_frame(frame)
    if event_type is None:
        return
    row = await database.fetch_one(
        "SELECT wizard_state FROM chat_sessions WHERE id = :id",
        {"id": session_id},
    )
    raw = row["wizard_state"] if row else None
    if isinstance(raw, str):
        raw = json.loads(raw)
    if raw is None:
        return
    ws = WizardState.model_validate(raw)

    if event_type == "wizard_round":
        ws = append_round_from_event(ws, payload)
    elif event_type == "planner_step":
        if payload.get("type") == "tool_use_start" and payload.get("tool_name") in _DISPATCH_TOOLS:
            ws = set_dispatched(ws, tool=payload["tool_name"], now=time.time())
            tool_name = payload["tool_name"]
            rounds_used = len([r for r in ws.rounds if r.answer_kind in ("option_click", "free_text")])
            last_label = ws.rounds[-1].round_label if ws.rounds else "other"
            WIZARD_DISPATCH_TOOL_TOTAL.labels(tool=tool_name).inc()
            WIZARD_ROUNDS_TOTAL.labels(
                round_label=last_label, dispatched_tool=tool_name,
            ).observe(rounds_used)
            logger.info("wizard_dispatched", extra={
                "session_id": session_id,
                "tool": tool_name,
                "rounds_used": rounds_used,
            })
    else:
        return

    await _save_wizard_state(session_id, ws)


def _parse_sse_frame(frame: str) -> tuple:
    # Orchestrator emits wizard_round/aborted/guide as `data: {event_type, payload}`
    # without an `event:` SSE prefix line (server.py:565). Fall back to reading
    # event_type from the JSON body when the SSE line is absent — otherwise the
    # interceptor never sees the wizard_round and round 1 never gets persisted.
    lines = [line for line in frame.splitlines() if line]
    event_type = None
    data_lines: list = []
    for line in lines:
        if line.startswith("event: "):
            event_type = line[len("event: "):].strip()
        elif line.startswith("data: "):
            data_lines.append(line[len("data: "):])
    if not data_lines:
        return None, {}
    try:
        payload = json.loads("".join(data_lines))
    except json.JSONDecodeError:
        return event_type, {}
    if event_type is None and isinstance(payload, dict):
        event_type = payload.get("event_type")
    if not event_type:
        return None, {}
    if isinstance(payload, dict) and isinstance(payload.get("payload"), str):
        try:
            payload = json.loads(payload["payload"])
        except json.JSONDecodeError:
            pass
    return event_type, payload if isinstance(payload, dict) else {}


class ScriptUploadRequest(BaseModel):
    """Request model for uploading script content"""
    name: str = Field(..., description="Name of the script")
    content: str = Field(..., description="The actual script content")
    description: Optional[str] = Field(None, description="Optional description")
    version: Optional[str] = Field("1.0.0", description="Script version")

@router.post("/orchestrator/strategy/upload-script", response_model=ScriptResponse)
async def upload_and_save_script(
    request: ScriptUploadRequest,
    current_user: UserResponse = Depends(get_current_user)
):
    """
    Upload script content to R2 storage and save metadata to the database.
    Falls back to base64 data URI if R2 is not configured.
    """
    logger.info(f"Uploading script for user {current_user.id}: {request.name}")
    
    # Try to upload to R2 first
    script_address = None
    if r2_storage.is_available():
        try:
            # Determine content type based on filename
            content_type = "text/plain"
            if request.name.endswith('.py'):
                content_type = "text/x-python"
            elif request.name.endswith('.sh'):
                content_type = "application/x-sh"
            elif request.name.endswith('.js'):
                content_type = "application/javascript"
            
            # Upload to R2
            script_address = await r2_storage.upload_script(
                content=request.content,
                filename=request.name,
                user_id=str(current_user.id),
                content_type=content_type
            )
            
            if script_address:
                logger.info(f"Successfully uploaded script to R2: {script_address}")
        except Exception as e:
            logger.error(f"Failed to upload to R2: {e}")
    
    # Fallback to base64 data URI if R2 upload failed or not configured
    if not script_address:
        logger.info("R2 upload not available or failed, using base64 data URI")
        encoded_content = base64.b64encode(request.content.encode('utf-8')).decode('utf-8')
        script_address = f"data:text/plain;base64,{encoded_content}"
    
    query = """
        INSERT INTO scripts (name, script_address, description, owner_id, version)
        VALUES (:name, :script_address, :description, :owner_id, :version)
        RETURNING id, name, script_address, description, owner_id, version, created_at, updated_at
    """
    
    try:
        result = await database.fetch_one(
            query=query,
            values={
                "name": request.name,
                "script_address": script_address,
                "description": request.description,
                "owner_id": current_user.id,
                "version": request.version
            }
        )
        
        return ScriptResponse(
            id=result["id"],
            name=result["name"],
            script_address=result["script_address"],
            description=result["description"],
            owner_id=result["owner_id"],
            version=result["version"],
            created_at=result["created_at"],
            updated_at=result["updated_at"],
            owner_name=current_user.username
        )
    except Exception as e:
        logger.error(f"Error saving script: {e}")
        raise HTTPException(status_code=500, detail="Failed to save script")

@router.post("/orchestrator/strategy/save-script", response_model=ScriptResponse)
async def save_generated_script(
    script: ScriptCreate,
    current_user: UserResponse = Depends(get_current_user)
):
    """
    Save a generated script to the database after strategy generation completes.
    This endpoint is called by the frontend after receiving the script URL from orchestrator.
    
    Deprecated: Use /orchestrator/strategy/upload-script instead for better control.
    """
    logger.info(f"Saving script for user {current_user.id}: {script.name}")
    
    query = """
        INSERT INTO scripts (name, script_address, description, owner_id, version)
        VALUES (:name, :script_address, :description, :owner_id, :version)
        RETURNING id, name, script_address, description, owner_id, version, created_at, updated_at
    """
    
    try:
        result = await database.fetch_one(
            query=query,
            values={
                "name": script.name,
                "script_address": script.script_address,
                "description": script.description,
                "owner_id": current_user.id,
                "version": script.version
            }
        )
        
        return ScriptResponse(
            id=result["id"],
            name=result["name"],
            script_address=result["script_address"],
            description=result["description"],
            owner_id=result["owner_id"],
            version=result["version"],
            created_at=result["created_at"],
            updated_at=result["updated_at"],
            owner_name=current_user.username
        )
    except Exception as e:
        logger.error(f"Error saving script: {e}")
        raise HTTPException(status_code=500, detail="Failed to save script")
