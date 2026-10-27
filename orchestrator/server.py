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

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8080))
    uvicorn.run(app, host="0.0.0.0", port=port)
