import asyncio
import json
import logging
import uuid
import os
import httpx
from typing import Dict, Optional, Any
from dotenv import load_dotenv

# Load environment variables
# Try current directory first, then parent directory
load_dotenv()
if not os.getenv("GOOGLE_API_KEY"):
    load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"))

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# Import ADK Agent Logic
from orchestrator.agent import stream_test_strategy, create_test_strategy

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("OrchestratorAPI")

app = FastAPI(
    title="Argus Orchestrator API",
    version="1.0.0",
    description="""
    Argus Orchestrator API provides endpoints for generating test strategies using AI agents.
    
    ## Features
    
    * **Stream Strategy Generation**: Generate test strategies with real-time streaming responses
    * **Server-Sent Events (SSE)**: Receive progress updates as the strategy is being generated
    * **WebSocket Agent Connections**: Support for agent connections via WebSocket
    * **Agent Command Execution**: Execute commands on connected agents
    
    ## API Endpoints
    
    * `/orchestrator/v1/strategy/stream` - Stream test strategy creation process
    * `/orchestrator/v1/strategy/create` - Create test strategy (non-streaming)
    * `/agent/connect` - WebSocket endpoint for agent connections
    * `/orchestrator/run_command` - Execute commands on connected agents
    """,
    docs_url="/docs",  # Swagger UI at /docs
    redoc_url="/redoc",  # ReDoc at /redoc
    openapi_url="/openapi.json",  # OpenAPI schema at /openapi.json
)

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================================
# WebSocket Agent Connection Management
# ============================================================================

# Import the global connection manager from separate module to avoid circular imports
from connection_manager import connection_manager
from orchestrator.redteam.api import router as redteam_router
app.include_router(redteam_router)

# API Service URL for querying user agents
API_SERVICE_URL = os.getenv("API_SERVICE_URL", "http://argus-api-service.default.svc.cluster.local:8881")

async def get_user_agent_id(user_id: str, auth_token: Optional[str] = None) -> Optional[str]:
    """
    Query API Service to get the user's active agent_id.
    Returns the first active agent found, or None.
    
    Args:
        user_id: The user ID to query agents for
        auth_token: Optional OAuth bearer token for HTTP authentication (NOT for matching agent records)
    """
    logger.info("=" * 80)
    logger.info("🔍 GET USER AGENT ID")
    logger.info(f"User ID: {user_id}")
    logger.info(f"Has OAuth Token: {bool(auth_token)}")
    logger.info("=" * 80)
    
    try:
        headers = {
            "x-user-id": user_id,
            "x-internal-call": "true"  # Mark as internal service call
        }
        if auth_token:
            # Add Authorization header for API authentication
            if not auth_token.startswith("Bearer "):
                auth_token = f"Bearer {auth_token}"
            headers["Authorization"] = auth_token
            logger.info("📝 Using OAuth token for API authentication")
        else:
            logger.info("ℹ️  No OAuth token - using internal service authentication")
            
        logger.info(f"📡 Requesting: {API_SERVICE_URL}/api/v1/agent/list")
        logger.info(f"Headers: {list(headers.keys())}")
        
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{API_SERVICE_URL}/api/v1/agent/list",
                headers=headers,
                timeout=10.0
            )
            
            logger.info(f"📥 Response Status: {response.status_code}")
            response.raise_for_status()
            data = response.json()
            
            agents = data.get("agents", [])
            logger.info(f"Found {len(agents)} agent(s) for user {user_id}")
            
            if agents:
                logger.info("📋 Agent details:")
                for idx, agent in enumerate(agents, 1):
                    logger.info(f"  {idx}. Agent ID: {agent.get('agent_id')}")
                    logger.info(f"     Status: {agent.get('status')}")
                    logger.info(f"     Name: {agent.get('agent_name')}")
            
            # Find the first active agent
            for agent in agents:
                if agent.get('status') == 'active':
                    agent_id = agent.get('agent_id')
                    logger.info(f"✅ Selected active agent: {agent_id}")
                    logger.info("=" * 80)
                    return agent_id
            
            logger.warning(f"⚠️ No active agents found for user {user_id}")
            if agents:
                logger.info("💡 Found agents but none are active:")
                for agent in agents:
                    logger.info(f"   - {agent.get('agent_id')}: status={agent.get('status')}")
            else:
                logger.info("💡 No agents registered for this user")
                logger.info("Troubleshooting:")
                logger.info("  1. Start the client agent application")
                logger.info("  2. Ensure client agent uses correct API token for registration")
                logger.info("  3. Verify client agent registration succeeded")
                logger.info(f"  4. Confirm user_id matches: {user_id}")
            
            logger.info("=" * 80)
            return None
    except httpx.HTTPStatusError as e:
        logger.error(f"❌ HTTP error: {e.response.status_code}")
        logger.error(f"Response: {e.response.text}")
        logger.info("=" * 80)
        return None
    except Exception as e:
        logger.error(f"❌ Error fetching user agent: {e}")
        logger.exception(e)
        logger.info("=" * 80)
        return None

@app.websocket("/agent/connect")
async def websocket_endpoint(websocket: WebSocket):
    """
    WebSocket endpoint for agent connections.
    
    Agents connect to this endpoint to establish a bidirectional communication channel.
    The agent must provide an 'x-agent-id' header for identification.
    
    **Protocol**: JSON-RPC 2.0
    **Authentication**: Via 'x-agent-id' header (handled by API Gateway)
    """
    # Agent authentication is handled by the API Gateway before reaching this service.
    # We rely on the 'x-agent-id' header being present.
    
    headers = websocket.headers
    agent_id = headers.get("x-agent-id")
    
    if not agent_id:
        await websocket.close(code=1008, reason="Missing Agent ID")
        return

    await connection_manager.connect(websocket, agent_id)
    
    try:
        while True:
            data = await websocket.receive_json()
            # Handle incoming messages (responses from agent)
            if data.get("jsonrpc") == "2.0":
                if "method" in data:
                    # It's a request from Agent (e.g. heartbeat or log)
                    logger.info(f"Received request from agent {agent_id}: {data}")
                    if data["method"] == "ping":
                        await websocket.send_json({"jsonrpc": "2.0", "result": "pong", "id": data.get("id")})
                elif "result" in data or "error" in data:
                    # It's a response to our command
                    connection_manager.handle_response(data)
    except WebSocketDisconnect:
        await connection_manager.disconnect(agent_id)
    except Exception as e:
        logger.error(f"Error in websocket connection: {e}")
        await connection_manager.disconnect(agent_id)

class CommandRequest(BaseModel):
    """Request model for agent command execution"""
    agent_id: str = Field(..., description="ID of the agent to execute the command on")
    tool_name: str = Field(..., description="Name of the tool to execute")
    arguments: Dict[str, Any] = Field(..., description="Arguments for the tool")

@app.post(
    "/orchestrator/run_command",
    tags=["Agent"],
    summary="Execute Command on Agent",
    description="""
    Execute a command (tool) on a connected agent via WebSocket.
    
    This endpoint sends a JSON-RPC 2.0 command to a connected agent and waits for the result.
    The agent must be connected via the `/agent/connect` WebSocket endpoint.
    
    **Note**: This is an internal API endpoint for orchestrator-to-agent communication.
    """,
    responses={
        200: {
            "description": "Command executed successfully",
            "content": {
                "application/json": {
                    "example": {
                        "status": "success",
                        "result": {...}
                    }
                }
            }
        },
        404: {
            "description": "Agent not connected"
        },
        504: {
            "description": "Command timed out"
        },
        500: {
            "description": "Internal server error"
        }
    }
)
async def run_command(request: CommandRequest):
    """
    Execute a command on a connected agent.
    
    **Request Body:**
    - `agent_id`: ID of the agent (required)
    - `tool_name`: Name of the tool to execute (required)
    - `arguments`: Arguments for the tool (required)
    
    **Response:**
    - Returns the result from the agent
    """
    try:
        result = await connection_manager.send_command(
            request.agent_id, 
            "tools/call", 
            {"name": request.tool_name, "arguments": request.arguments}
        )
        return {"status": "success", "result": result}
    except Exception as e:
        logger.error(f"Error executing command on agent {request.agent_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ============================================================================
# Cancel Web UI Test Endpoint
# ============================================================================

class CancelWebUITestRequest(BaseModel):
    """Request model for cancelling a Web UI test"""
    user_id: str = Field(..., description="User ID whose active task should be cancelled")

@app.post(
    "/orchestrator/v1/cancel-web-ui-test",
    tags=["Agent"],
    summary="Cancel Web UI Test",
    description="Cancel an active Web UI test running on a client agent.",
)
async def cancel_web_ui_test(request: CancelWebUITestRequest, req: Request):
    """
    Cancel the active Web UI test for the given user.
    Sends cancel_web_ui_test command to the client agent via WebSocket.
    """
    from orchestrator.agents.common.client_web_ui_agent import _active_tasks

    entry = _active_tasks.get(request.user_id)
    if not entry:
        raise HTTPException(status_code=404, detail="No active Web UI test found for this user")

    agent_id, task_id = entry
    logger.info(f"Cancel request: user={request.user_id}, agent={agent_id}, task={task_id}")

    if agent_id not in connection_manager.active_connections:
        _active_tasks.pop(request.user_id, None)
        raise HTTPException(status_code=404, detail="Client agent is no longer connected")

    try:
        await asyncio.wait_for(
            connection_manager.send_command(
                agent_id,
                "tools/call",
                {"name": "cancel_web_ui_test", "arguments": {"task_id": task_id}},
            ),
            timeout=10.0,
        )
    except Exception as exc:
        logger.warning(f"Failed to send cancel for task {task_id}: {exc}")
        raise HTTPException(status_code=502, detail=f"Failed to cancel task: {exc}")

    _active_tasks.pop(request.user_id, None)
    return {"status": "cancelled", "task_id": task_id}

# ============================================================================
# Strategy Generation Endpoints
# ============================================================================

class SSHConfigModel(BaseModel):
    """SSH configuration for remote test execution"""
    remote_ip: str = Field(..., description="Remote host IPv4 address")
    username: str = Field(..., description="SSH username")
    pem_key_base64: str = Field(..., description="PEM private key encoded as base64")
    pytest_args: Optional[str] = Field("--alluredir=./allure-results -v", description="Pytest arguments")

class StrategyRequest(BaseModel):
    """Request model for strategy generation"""
    content: str = Field(
        ...,
        description="The source content to analyze and generate test strategy for",
        example="A web application with user authentication and payment processing"
    )
    context: Optional[Dict[str, Any]] = Field(
        None,
        description="Additional context information for strategy generation",
        example={"project_type": "web", "tech_stack": ["React", "Node.js"]}
    )
    session_id: Optional[str] = Field(
        None,
        description="Optional session ID for tracking the request. If not provided, a new UUID will be generated",
        example="550e8400-e29b-41d4-a716-446655440000"
    )
    user_id: Optional[str] = Field(
        None,
        description="Optional user ID for user-specific strategy generation",
        example="user123"
    )
    local_test_enabled: Optional[bool] = Field(
        False,
        description="Enable local client agent testing"
    )
    remote_test_enabled: Optional[bool] = Field(
        False,
        description="Enable remote test execution via test-runner service"
    )
    ssh_config: Optional[SSHConfigModel] = Field(
        None,
        description="SSH configuration for remote test execution"
    )
    cdp_url: Optional[str] = Field(
        None,
        description=(
            "Chrome DevTools Protocol URL for connecting to a locally running Chrome instance. "
            "Start Chrome with --remote-debugging-port=9222 and provide the URL here, e.g. "
            "'http://localhost:9222'. When set, the Web UI Testing agent will control your "
            "existing browser session instead of launching a new headless browser."
        ),
        example="http://localhost:9222"
    )
    wizard_state: Optional[Dict[str, Any]] = Field(
        None,
        description="Server-side WizardState JSON from chat_sessions.wizard_state",
    )

    class Config:
        schema_extra = {
            "example": {
                "content": "A web application with user authentication and payment processing",
                "context": {
                    "project_type": "web",
                    "tech_stack": ["React", "Node.js", "PostgreSQL"]
                },
                "session_id": "550e8400-e29b-41d4-a716-446655440000",
                "user_id": "user123",
                "local_test_enabled": False
            }
        }

@app.post(
    "/orchestrator/v1/strategy/stream",
    tags=["Strategy"],
    summary="Stream Test Strategy Generation",
    description="""
    Generate a test strategy for the provided content using AI agents.
    
    This endpoint streams the strategy generation process in real-time using Server-Sent Events (SSE).
    The response is a stream of events that include:
    
    * Progress updates from different agents
    * Intermediate results
    * Final strategy output
    * Error messages (if any)
    
    The stream will end with an `event: done` event when the strategy generation is complete.
    """,
    response_description="Server-Sent Events stream containing strategy generation progress and results",
    responses={
        200: {
            "description": "Successful response - SSE stream",
            "content": {
                "text/event-stream": {
                    "example": "data: {\"type\": \"progress\", \"author\": \"agent\", \"text\": \"Analyzing content...\"}\n\n"
                }
            }
        },
        422: {
            "description": "Validation error - invalid request parameters"
        },
        500: {
            "description": "Internal server error during strategy generation"
        }
    }
)
async def stream_strategy(request: StrategyRequest, req: Request):
    """
    Stream the test strategy creation process using Server-Sent Events (SSE).
    
    **Request Body:**
    - `content`: The source content to analyze (required)
    - `context`: Additional context information (optional)
    - `session_id`: Session identifier for tracking (optional, auto-generated if not provided)
    - `user_id`: User identifier (optional)
    - `local_test_enabled`: Enable local client agent testing (optional)
    
    **Response:**
    - Content-Type: `text/event-stream`
    - Format: Server-Sent Events (SSE)
    - Events include progress updates, results, and completion status
    """
    session_id = request.session_id or str(uuid.uuid4())
    logger.info(f"Starting strategy stream for session {session_id}, local_test={request.local_test_enabled}")
    
    # Extract auth token - check both cases since HTTP/2 converts headers to lowercase
    auth_token = req.headers.get("Authorization") or req.headers.get("authorization")
    logger.info(f"Auth token from request headers: {'present' if auth_token else 'None'}")
    if auth_token:
        # Log first 20 chars for debugging
        logger.info(f"Auth token preview: {auth_token[:20]}...")

    async def event_generator():
        next_event_task = None
        try:
            logger.info("event_generator started")
            event_count = 0
            # Create an iterator for the async generator
            iterator = stream_test_strategy(
                source_content=request.content,
                context=request.context,
                session_id=session_id,
                user_id=request.user_id,
                local_test_enabled=request.local_test_enabled,
                remote_test_enabled=request.remote_test_enabled,
                auth_token=auth_token,
                ssh_config=request.ssh_config.model_dump() if request.ssh_config else None,
                cdp_url=request.cdp_url,
                wizard_state=request.wizard_state,
            ).__aiter__()

            # Create the first task
            next_event_task = asyncio.create_task(iterator.__anext__())

            while True:
                try:
                    # Check if client disconnected
                    if await req.is_disconnected():
                        logger.info(f"Client disconnected for session {session_id}, cancelling agent task")
                        next_event_task.cancel()
                        # Wait for the task to fully absorb the cancellation before
                        # closing the iterator — prevents concurrent generator access.
                        try:
                            await asyncio.wait_for(
                                asyncio.shield(next_event_task), timeout=2.0
                            )
                        except (asyncio.CancelledError, asyncio.TimeoutError, Exception):
                            pass
                        await iterator.aclose()   # sends GeneratorExit → ClientWebUIAgent catches it
                        break

                    # Wait for next event with a short timeout so disconnect
                    # is detected quickly (every 3 s instead of 15 s).
                    done, _ = await asyncio.wait({next_event_task}, timeout=3.0)

                    if next_event_task in done:
                        # Event received or generator finished
                        try:
                            event = next_event_task.result()
                            
                            event_count += 1
                            logger.info(f"Received event #{event_count}, type: {type(event).__name__}")
                            
                            # Process and yield event
                            if isinstance(event, dict):
                                # Check if it's an artifact event and emit with event type
                                if event.get("type") == "artifact":
                                    yield f"event: artifact\ndata: {json.dumps(event)}\n\n"
                                else:
                                    yield f"data: {json.dumps(event)}\n\n"
                            else:
                                try:
                                    event_data = {
                                        "type": "progress",
                                        "author": getattr(event, "author", "unknown"),
                                    }
                                    if hasattr(event, "content") and event.content and hasattr(event.content, "parts"):
                                         parts_text = []
                                         for part in event.content.parts:
                                             if hasattr(part, "text") and part.text is not None:
                                                 parts_text.append(str(part.text))
                                         combined = "\n".join(parts_text)
                                         # The planner wraps tool passthrough events as
                                         # {"event_type": ..., "payload": "<json>"}. The
                                         # legacy ClientWebUIAgent wire format is just
                                         # json.dumps(payload). Unwrap so the frontend's
                                         # web_ui_bug / web_ui_artifact synthesis sees the
                                         # payload directly. planner_step keeps the wrapper —
                                         # the frontend timeline decodes it explicitly.
                                         if combined.startswith("{"):
                                             try:
                                                 wrapper = json.loads(combined)
                                             except json.JSONDecodeError:
                                                 wrapper = None
                                             if (isinstance(wrapper, dict)
                                                     and "event_type" in wrapper
                                                     and "payload" in wrapper
                                                     and wrapper["event_type"] != "planner_step"):
                                                 et = wrapper["event_type"]
                                                 payload = wrapper["payload"]
                                                 if isinstance(payload, str):
                                                     try:
                                                         payload_obj = json.loads(payload)
                                                     except json.JSONDecodeError:
                                                         payload_obj = {"message": payload}
                                                 else:
                                                     payload_obj = payload
                                                 if et == "log" and isinstance(payload_obj, dict):
                                                     combined = payload_obj.get("message", "")
                                                 elif et == "error" and isinstance(payload_obj, dict):
                                                     combined = f"❌ {payload_obj.get('message', '')}"
                                                 elif et in {"ssh_result", "result", "web_ui_bug", "web_ui_artifact"} and isinstance(payload_obj, dict):
                                                     # Re-emit with the typed event at the SSE top level,
                                                     # matching the legacy ApiTestingAgent / ClientWebUIAgent
                                                     # wire format. Without this, the frontend would see
                                                     # type:"progress" and fail to synthesize the
                                                     # ssh_result / result card on /chat.
                                                     typed = {"author": event_data["author"], **payload_obj}
                                                     typed["type"] = et
                                                     yield f"data: {json.dumps(typed, default=str)}\n\n"
                                                     next_event_task = asyncio.create_task(iterator.__anext__())
                                                     continue
                                                 elif et in {"wizard_round", "wizard_aborted", "wizard_guide"}:
                                                     # Frontend api.ts:780 + api_service _parse_sse_frame
                                                     # both expect {event_type, payload:str} at the SSE top
                                                     # level. Keep payload as the original JSON string so
                                                     # `typeof parsed.payload === 'string'` holds.
                                                     typed = {"event_type": et, "payload": payload,
                                                              "author": event_data["author"]}
                                                     yield f"data: {json.dumps(typed, default=str)}\n\n"
                                                     next_event_task = asyncio.create_task(iterator.__anext__())
                                                     continue
                                                 else:
                                                     combined = json.dumps(payload_obj, default=str)
                                         event_data["text"] = combined
                                    elif hasattr(event, "delta") and event.delta: # Handle ModelDelta events
                                         # Delta is often a Content object too
                                         if hasattr(event.delta, "parts"):
                                            parts_text = []
                                            for part in event.delta.parts:
                                                if hasattr(part, "text") and part.text is not None:
                                                    parts_text.append(str(part.text))
                                            event_data["text"] = "\n".join(parts_text)
                                            # Mark as delta so frontend can append instead of replace if needed
                                            event_data["is_delta"] = True
                                         else:
                                             event_data["text"] = str(event.delta)
                                             event_data["is_delta"] = True
                                    yield f"data: {json.dumps(event_data)}\n\n"
                                except Exception as serialize_err:
                                    logger.warning(f"Could not serialize event: {serialize_err}")
                                    yield f"data: {json.dumps({'type': 'unknown', 'raw': str(event)})}\n\n"
                            
                            # Queue up the next event
                            next_event_task = asyncio.create_task(iterator.__anext__())
                            
                        except StopAsyncIteration:
                            break
                        except Exception as e:
                            logger.error(f"Error in strategy generator: {e}")
                            yield f"event: error\ndata: {json.dumps({'error': str(e)})}\n\n"
                            break
                    else:
                        # Timeout occurred - send keep-alive
                        yield ": ping\n\n"
                        # Loop continues, waiting for the SAME next_event_task

                except (asyncio.CancelledError, GeneratorExit):
                    logger.info(f"Request cancelled for session {session_id}")
                    break
                except Exception as e:
                    logger.error(f"Error in event loop: {e}")
                    break
            
            # Signal end of stream
            if not await req.is_disconnected():
                logger.info(f"event_generator completed, total events: {event_count}")
                yield "event: done\ndata: {}\n\n"
            
        except (asyncio.CancelledError, GeneratorExit):
            logger.info(f"Generator cancelled for session {session_id}")
        except Exception as e:
            import traceback
            tb_str = traceback.format_exc()
            logger.error(f"Error in stream: {e}\n{tb_str}")
            try:
                yield f"event: error\ndata: {json.dumps({'error': str(e)})}\n\n"
            except Exception:
                pass
        finally:
            # CRITICAL CLEANUP: Ensure pending task is cancelled if we exit loop early
            if next_event_task and not next_event_task.done():
                logger.info(f"Cancelling pending generation task for session {session_id}")
                next_event_task.cancel()
                try:
                    # Give it a tiny bit of time to cancel
                    await asyncio.wait({next_event_task}, timeout=1.0)
                except Exception:
                    pass
            logger.info(f"event_generator cleanup finished for session {session_id}")

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "X-Accel-Buffering": "no",       # disable nginx/APISIX proxy buffering for SSE
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
        },
    )


class StrategyResponse(BaseModel):
    """Response model for strategy creation"""
    success: bool = Field(..., description="Whether the strategy creation was successful")
    response: Optional[str] = Field(None, description="Response message")
    generated_content: Optional[Dict[str, Any]] = Field(None, description="Generated test strategy content")
    error: Optional[str] = Field(None, description="Error message if creation failed")


@app.post(
    "/orchestrator/v1/strategy/create",
    tags=["Strategy"],
    summary="Create Test Strategy",
    description="""
    Generate a test strategy for the provided content using AI agents.
    
    This endpoint creates a test strategy synchronously and returns the complete result.
    For real-time progress updates, use the `/orchestrator/v1/strategy/stream` endpoint instead.
    
    The response includes:
    
    * Success status
    * Generated test strategy content
    * Error message (if any)
    """,
    response_model=StrategyResponse,
    responses={
        200: {
            "description": "Successful response - strategy created",
            "content": {
                "application/json": {
                    "example": {
                        "success": True,
                        "response": "Processing complete",
                        "generated_content": {
                            "test_strategy": "..."
                        }
                    }
                }
            }
        },
        422: {
            "description": "Validation error - invalid request parameters"
        },
        500: {
            "description": "Internal server error during strategy generation"
        }
    }
)
async def create_strategy(request: StrategyRequest):
    """
    Create a test strategy for the provided content.
    
    **Request Body:**
    - `content`: The source content to analyze (required)
    - `context`: Additional context information (optional)
    - `session_id`: Session identifier for tracking (optional, auto-generated if not provided)
    - `user_id`: User identifier (optional)
    - `local_test_enabled`: Enable local client agent testing (optional)
    
    **Response:**
    - Content-Type: `application/json`
    - Returns complete strategy generation result
    """
    session_id = request.session_id or str(uuid.uuid4())
    logger.info(f"Creating strategy for session {session_id}, local_test={request.local_test_enabled}")
    
    try:
        result = await create_test_strategy(
            source_content=request.content,
            context=request.context,
            session_id=session_id,
            user_id=request.user_id,
            local_test_enabled=request.local_test_enabled
        )
        
        if result["success"]:
            return StrategyResponse(
                success=True,
                response=result.get("response"),
                generated_content=result.get("generated_content"),
                error=None
            )
        else:
            # Return error response with 200 status but success=False
            return StrategyResponse(
                success=False,
                response=None,
                generated_content=None,
                error=result.get("error", "Unknown error occurred")
            )
            
    except Exception as e:
        logger.error(f"Error creating strategy: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error: {str(e)}"
        )


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8080))
    uvicorn.run(app, host="0.0.0.0", port=port)
