import hmac
import logging
import os
from dotenv import load_dotenv

# Load .env from this directory, then the parent; existing values are never overridden.
load_dotenv()
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"))

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("OrchestratorAPI")

app = FastAPI(
    title="Argus Orchestrator API",
    version="1.0.0",
    description="""
    Argus Orchestrator API serves the red-team engine and the client-agent WebSocket hub.
    
    ## API Endpoints
    
    * `/redteam/*` - Red-team runs, probes, suites and coverage
    * `/agent/connect` - WebSocket endpoint for agent connections
    """,
    docs_url="/docs",  # Swagger UI at /docs
    redoc_url="/redoc",  # ReDoc at /redoc
    openapi_url="/openapi.json",  # OpenAPI schema at /openapi.json
)

# No browser UI ships with the engine, so cross-origin access is off unless
# CORS_ALLOW_ORIGINS (comma-separated) names the origins to allow.
_cors_origins = [o.strip() for o in os.getenv("CORS_ALLOW_ORIGINS", "").split(",") if o.strip()]
if _cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins,
        allow_methods=["*"],
        allow_headers=["*"],
    )


def log_agent_auth_mode() -> None:
    """Warn at startup when /agent/connect accepts agents without a secret."""
    if not os.getenv("AGENT_CONNECT_SECRET"):
        logger.warning(
            "AGENT_CONNECT_SECRET is not set: /agent/connect accepts unauthenticated agents. "
            "Run the orchestrator only on localhost or a trusted network."
        )


log_agent_auth_mode()

# ============================================================================
# WebSocket Agent Connection Management
# ============================================================================

# Import the global connection manager from separate module to avoid circular imports
from argus.connection_manager import connection_manager
from argus.api import router as redteam_router
app.include_router(redteam_router)

@app.websocket("/agent/connect")
async def websocket_endpoint(websocket: WebSocket):
    """
    WebSocket endpoint for agent connections.
    
    Agents connect to this endpoint to establish a bidirectional communication channel.
    The agent must provide an 'x-agent-id' header for identification.
    
    **Protocol**: JSON-RPC 2.0
    **Authentication**: when AGENT_CONNECT_SECRET is set, the 'x-agent-secret' header
    must match it; otherwise any client that reaches this endpoint is accepted.
    """
    headers = websocket.headers
    agent_id = headers.get("x-agent-id")
    
    if not agent_id:
        await websocket.close(code=1008, reason="Missing Agent ID")
        return

    secret = os.getenv("AGENT_CONNECT_SECRET")
    if secret and not hmac.compare_digest(
        headers.get("x-agent-secret", "").encode(), secret.encode()
    ):
        await websocket.close(code=1008, reason="Invalid agent secret")
        return

    if not await connection_manager.connect(websocket, agent_id):
        return
    
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

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8080))
    # Protocol pings drop a dead agent socket within ~40 s, which frees its id
    # for reconnect (duplicate ids are refused while the old socket is live).
    uvicorn.run(app, host="0.0.0.0", port=port, ws_ping_interval=20.0, ws_ping_timeout=20.0)
