import hmac
import ipaddress
import logging
import os
import sys
from dotenv import load_dotenv

# Load .env from this directory, then the parent; existing values are never overridden.
load_dotenv()
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"))

from fastapi import Depends, FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
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
      (needs `Authorization: Bearer <token>` when ARGUS_SERVER_TOKEN is set)
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



# auto_error=False: the scheme is declared in OpenAPI, but whether a token is
# required depends on ARGUS_SERVER_TOKEN, checked below.
_bearer = HTTPBearer(auto_error=False)


def require_server_token(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> None:
    """When ARGUS_SERVER_TOKEN is set, require `Authorization: Bearer <token>`."""
    # Read per request so the token is never cached at import time.
    token = os.getenv("ARGUS_SERVER_TOKEN", "")
    if not token:
        return
    supplied = credentials.credentials if credentials else ""
    if not hmac.compare_digest(supplied.encode(), token.encode()):
        raise HTTPException(status_code=401, detail="missing or invalid bearer token",
                            headers={"WWW-Authenticate": "Bearer"})


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def startup_error(
    host: str, token: str, agent_secret: str, allow_unauthenticated: bool
) -> str | None:
    """Why the server must not start on `host`, or None when it may."""
    # /redteam/run sends requests to a caller-named target, and /agent/connect hands
    # probe payloads to whoever connects, so off loopback each needs its own secret.
    # The API token never stands in for the agent secret: they are different principals.
    if _is_loopback(host) or allow_unauthenticated:
        return None
    missing = []
    if not token:
        missing.append("ARGUS_SERVER_TOKEN is not set, so /redteam/* would accept anyone's runs")
    if not agent_secret:
        missing.append("AGENT_CONNECT_SECRET is not set, so anyone could register on /agent/connect")
    if not missing:
        return None
    return (
        f"Refusing to start: ARGUS_SERVER_HOST={host} is reachable from other machines and "
        + "; ".join(missing) + ". "
        "Set ARGUS_SERVER_TOKEN (callers send 'Authorization: Bearer <token>') and "
        "AGENT_CONNECT_SECRET (client agents send it as x-agent-secret), or bind to 127.0.0.1. "
        "ARGUS_SERVER_ALLOW_UNAUTHENTICATED=1 skips this check and leaves both /redteam/* and "
        "/agent/connect open to anything that reaches the port; use it only behind a proxy "
        "that authenticates both."
    )

# ============================================================================
# WebSocket Agent Connection Management
# ============================================================================

# Import the global connection manager from separate module to avoid circular imports
from argus.connection_manager import connection_manager
from argus.api import router as redteam_router
app.include_router(redteam_router, dependencies=[Depends(require_server_token)])

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
        await connection_manager.disconnect(agent_id, connection=websocket)
    except Exception as e:
        logger.error(f"Error in websocket connection: {e}")
        await connection_manager.disconnect(agent_id, connection=websocket)

def main() -> None:
    import uvicorn
    host = os.getenv("ARGUS_SERVER_HOST") or "127.0.0.1"
    token = os.getenv("ARGUS_SERVER_TOKEN", "")
    agent_secret = os.getenv("AGENT_CONNECT_SECRET", "")
    allow = os.getenv("ARGUS_SERVER_ALLOW_UNAUTHENTICATED") == "1"
    error = startup_error(host, token, agent_secret, allow)
    if error:
        print(error, file=sys.stderr)
        sys.exit(1)
    log_agent_auth_mode()
    if not token and not _is_loopback(host):
        logger.warning("ARGUS_SERVER_ALLOW_UNAUTHENTICATED=1: /redteam/* on %s accepts unauthenticated requests.", host)
    port = int(os.getenv("PORT", 8080))
    # Protocol pings drop a dead agent socket within ~40 s, which frees its id
    # for reconnect (duplicate ids are refused while the old socket is live).
    uvicorn.run(app, host=host, port=port, ws_ping_interval=20.0, ws_ping_timeout=20.0)


if __name__ == "__main__":
    main()
