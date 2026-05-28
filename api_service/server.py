import asyncio
import json
import logging
import uuid
import os
import httpx
from typing import Dict, Optional, Any
from dotenv import load_dotenv

from fastapi import FastAPI, HTTPException, Request, Depends, Header
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from database import database
from routers import blogs, categories, tags, media, blog_authors, documents, orchestrator, scripts, agents, chat, trial, web_ui_tasks, llm, subscription, profile, admin, legacy_export, organizations
from redteam import routes as redteam_routes
from auth import get_current_user_dual_auth, get_current_user
from models import UserResponse

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("Argus API Service")

# Microsoft Entra External ID (CIAM) Configuration
CIAM_TENANT_NAME = os.getenv("CIAM_TENANT_NAME", "")
CIAM_TENANT_ID = os.getenv("CIAM_TENANT_ID", "")
CIAM_BACKEND_CLIENT_ID = os.getenv("CIAM_BACKEND_CLIENT_ID", "")
CIAM_BACKEND_CLIENT_SECRET = os.getenv("CIAM_BACKEND_CLIENT_SECRET", "")
ENABLE_TEST_MODE = os.getenv("ENABLE_TEST_MODE", "false").lower() == "true"

app = FastAPI(title="Argus API Service", version="1.0.0")

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include Routers
app.include_router(redteam_routes.router, prefix="/api/v1", tags=["RedTeam"])
app.include_router(blogs.router, prefix="/api/v1", tags=["Blogs"])
app.include_router(categories.router, prefix="/api/v1", tags=["Blog Categories"])
app.include_router(tags.router, prefix="/api/v1", tags=["Blog Tags"])
app.include_router(media.router, prefix="/api/v1", tags=["Blog Media"])
app.include_router(blog_authors.router, prefix="/api/v1", tags=["Blog Authors"])
app.include_router(documents.router, prefix="/api/v1", tags=["Documents"])
app.include_router(orchestrator.router, prefix="/api/v1", tags=["Orchestrator"])
app.include_router(scripts.router, prefix="/api/v1", tags=["Scripts"])
app.include_router(agents.router, prefix="/api/v1", tags=["Agents"])
app.include_router(chat.router, prefix="/api/v1", tags=["Chat"])
app.include_router(trial.router, prefix="/api/v1", tags=["Trial"])
app.include_router(web_ui_tasks.router, prefix="/api/v1", tags=["WebUITasks"])
app.include_router(llm.router, prefix="/api/v1", tags=["LLM"])
app.include_router(subscription.router, prefix="/api/v1", tags=["Subscription"])
app.include_router(profile.router, prefix="/api/v1", tags=["Profile"])
app.include_router(admin.router, prefix="/api/v1", tags=["Admin"])
app.include_router(organizations.router, prefix="/api/v1", tags=["Organizations"])
app.include_router(legacy_export.router, tags=["Legacy Export"])

@app.on_event("startup")
async def startup():
    await database.connect()
    logger.info("Database connected")

@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()
    logger.info("Database disconnected")

class AgentRegisterRequest(BaseModel):
    agent_name: str
    agent_type: Optional[str] = "custom"
    agent_config: Optional[str] = None
    status: str = "active"
    current_task_id: Optional[str] = None
    description: Optional[str] = None

class AgentStatusUpdate(BaseModel):
    agent_id: str
    status: str

@app.post("/api/v1/internal/agent/status")
async def update_agent_status_internal(
    request: AgentStatusUpdate,
    x_orchestrator_secret: str = Header(None, alias="x-orchestrator-secret")
):
    """
    Internal endpoint for Orchestrator to update agent status (e.g. online/offline).
    Protected by a shared secret.
    """
    # Verify secret
    expected_secret = os.getenv("ORCHESTRATOR_SECRET", "default_secret_change_me")
    if x_orchestrator_secret != expected_secret:
        logger.warning(f"Invalid orchestrator secret provided: {x_orchestrator_secret[:5]}...")
        raise HTTPException(status_code=403, detail="Invalid orchestrator secret")
    
    # Update status
    # We update updated_at only if status changes or periodically? Let's update it always to show last seen.
    query = "UPDATE client_agent SET status = :status, updated_at = NOW() WHERE id = :agent_id"
    await database.execute(query=query, values={"status": request.status, "agent_id": request.agent_id})
    logger.info(f"Internal update: Agent {request.agent_id} status set to {request.status}")
    return {"status": "success"}

@app.post("/api/v1/agent/register")
async def register_agent(
    request: AgentRegisterRequest,
    auth_data: tuple = Depends(get_current_user_dual_auth)
):
    """
    Register or update a client agent.
    Supports both JWT and API token authentication.
    """
    try:
        user, jwt_payload = auth_data
        user_id = user.id
        auth_method = "JWT" if jwt_payload else "API token"
        
        logger.info(f"=== Agent Registration Request ===")
        logger.info(f"Agent name: {request.agent_name}, Type: {request.agent_type}")
        logger.info(f"User: {user.username} (ID: {user_id}), Auth method: {auth_method}")
        if jwt_payload:
            logger.info(f"JWT scopes: {jwt_payload.get('scope', 'none')}")
        
        logger.info(f"Registering agent {request.agent_name} for user {user.username} (ID: {user_id})...")
        
    except HTTPException as e:
        logger.error(f"Authentication failed for agent registration: {e.status_code} - {e.detail}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error during authentication: {type(e).__name__}: {str(e)}", exc_info=True)
        raise HTTPException(status_code=401, detail=f"Authentication failed: {str(e)}")
    
    try:
        
        # 2. Upsert Agent
        # Check if agent exists for this user
        agent_query = "SELECT id FROM client_agent WHERE user_id = :user_id AND agent_name = :agent_name"
        agent_result = await database.fetch_one(query=agent_query, values={"user_id": user_id, "agent_name": request.agent_name})
        
        if agent_result:
            # Update
            logger.info(f"Agent {request.agent_name} already exists, updating...")
            update_query = """
                UPDATE client_agent 
                SET agent_type = :agent_type, 
                    agent_config = :agent_config, 
                    status = :status,
                    current_task_id = :current_task_id,
                    description = :description,
                    updated_at = NOW()
                WHERE id = :agent_id
            """
            values = {
                "agent_type": request.agent_type,
                "agent_config": request.agent_config,
                "status": request.status,
                "current_task_id": request.current_task_id,
                "description": request.description,
                "agent_id": agent_result["id"]
            }
            await database.execute(query=update_query, values=values)
            agent_id = agent_result["id"]
            logger.info(f"Updated agent {agent_id}")
        else:
            # Insert
            logger.info(f"Creating new agent {request.agent_name}...")
            insert_query = """
                INSERT INTO client_agent (user_id, agent_name, agent_type, agent_config, status, current_task_id, description)
                VALUES (:user_id, :agent_name, :agent_type, :agent_config, :status, :current_task_id, :description)
                RETURNING id
            """
            values = {
                "user_id": user_id,
                "agent_name": request.agent_name,
                "agent_type": request.agent_type,
                "agent_config": request.agent_config,
                "status": request.status,
                "current_task_id": request.current_task_id,
                "description": request.description
            }
            agent_id = await database.execute(query=insert_query, values=values)
            logger.info(f"Registered new agent {agent_id}")
            
        logger.info(f"=== Agent Registration Successful: agent_id={agent_id} ===")
        return {"status": "success", "agent_id": str(agent_id)}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error registering agent: {type(e).__name__}: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/agent/list")
async def list_user_agents(
    request: Request, 
    authorization: Optional[str] = Header(None, alias="Authorization"),
    x_api_token: Optional[str] = Header(None, alias="x-api-token")
):
    """
    List all agents for the specified user.
    Supports three authentication methods:
    1. Internal service calls: x-user-id header
    2. External calls with JWT: Authorization Bearer <jwt_token>
    3. External calls with API token: x-api-token header
    Returns agent_id, agent_name, status, etc.
    """
    # Log request for debugging
    logger.info(f"=== /api/v1/agent/list request ===")
    logger.info(f"Authorization: {authorization[:50] if authorization else 'None'}")
    logger.info(f"x-api-token: {'***' + x_api_token[-10:] if x_api_token else 'None'}")
    logger.info(f"x-user-id: {request.headers.get('x-user-id', 'None')}")
    
    # Check for x-user-id header first (internal service call)
    user_id_from_header = request.headers.get("x-user-id")
    
    if user_id_from_header:
        # Internal service call
        user_id = user_id_from_header
        logger.info(f"Listing agents for user {user_id} (internal call)")
    elif authorization or x_api_token:
        # External call with JWT token or API token
        try:
            current_user, jwt_payload = await get_current_user_dual_auth(
                authorization=authorization,
                x_api_token=x_api_token
            )
            user_id = str(current_user.id)
            auth_type = "JWT" if jwt_payload else "API token"
            logger.info(f"Listing agents for user {user_id} ({auth_type} auth)")
        except HTTPException as e:
            logger.error(f"Authentication failed: {e.status_code} - {e.detail}")
            raise
        except Exception as e:
            logger.error(f"Unexpected authentication error: {type(e).__name__}: {str(e)}")
            raise HTTPException(status_code=401, detail=f"Authentication failed: {str(e)}")
    else:
        # No valid authentication
        logger.error("No authentication provided")
        raise HTTPException(
            status_code=401, 
            detail="Authentication required: provide Authorization, x-api-token, or x-user-id header"
        )
    
    try:
        # Query all agents belonging to this user
        query = """
            SELECT id, agent_name, agent_type, status, description, created_at
            FROM client_agent 
            WHERE user_id = :user_id AND status = 'active'
            ORDER BY created_at DESC
        """
        agents = await database.fetch_all(query=query, values={"user_id": user_id})
        
        return {
            "agents": [
                {
                    "agent_id": str(agent["id"]),
                    "agent_name": agent["agent_name"],
                    "agent_type": agent["agent_type"],
                    "status": agent["status"],
                    "description": agent["description"],
                    "created_at": agent["created_at"].isoformat() if agent["created_at"] else None
                }
                for agent in agents
            ]
        }
    except Exception as e:
        logger.error(f"Error listing agents: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/auth/get_oauth_config")
async def get_oauth_config():
    """
    Get OAuth configuration for testing purposes.
    Only available when ENABLE_TEST_MODE is true.

    WARNING: This endpoint exposes client credentials and should only be used in development.
    """
    if not ENABLE_TEST_MODE:
        raise HTTPException(status_code=403, detail="Test mode not enabled")

    if not CIAM_BACKEND_CLIENT_ID or not CIAM_BACKEND_CLIENT_SECRET:
        raise HTTPException(
            status_code=500,
            detail="Entra External ID not configured. Please set CIAM_BACKEND_CLIENT_ID and CIAM_BACKEND_CLIENT_SECRET"
        )

    return {
        "client_id": CIAM_BACKEND_CLIENT_ID,
        "client_secret": CIAM_BACKEND_CLIENT_SECRET,  # Only expose in test mode
        "token_endpoint": f"https://{CIAM_TENANT_NAME}.ciamlogin.com/{CIAM_TENANT_ID}/oauth2/v2.0/token",
        "ciam_tenant_name": CIAM_TENANT_NAME,
    }

@app.post("/api/v1/auth/login")
async def login_with_password(request: Request):
    """
    Login with username and password, get JWT access token.
    Uses Microsoft Entra External ID ROPC (Resource Owner Password Credentials) flow.

    Client Agent should use this endpoint instead of calling CIAM directly.
    This way, client_secret never leaves the server.
    """
    try:
        body = await request.json()
        username = body.get("username")
        password = body.get("password")

        if not username or not password:
            raise HTTPException(status_code=400, detail="Username and password required")

        if not CIAM_BACKEND_CLIENT_ID or not CIAM_BACKEND_CLIENT_SECRET:
            raise HTTPException(
                status_code=500,
                detail="Entra External ID not configured on server"
            )

        # CIAM ROPC token endpoint (no policy path, unlike B2C)
        token_url = f"https://{CIAM_TENANT_NAME}.ciamlogin.com/{CIAM_TENANT_ID}/oauth2/v2.0/token"

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                token_url,
                data={
                    "grant_type": "password",
                    "client_id": CIAM_BACKEND_CLIENT_ID,
                    "client_secret": CIAM_BACKEND_CLIENT_SECRET,
                    "username": username,
                    "password": password,
                    "scope": f"openid {CIAM_BACKEND_CLIENT_ID} offline_access",
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )

            if not response.is_success:
                error_data = response.json() if response.text else {}
                raise HTTPException(
                    status_code=response.status_code,
                    detail=error_data.get("error_description", "Authentication failed")
                )

            token_data = response.json()

            # Return token to client (same response format as before)
            return {
                "access_token": token_data.get("access_token"),
                "token_type": token_data.get("token_type", "Bearer"),
                "expires_in": token_data.get("expires_in", 3600),
                "refresh_token": token_data.get("refresh_token"),
                "scope": token_data.get("scope")
            }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/api/v1/get_token")
async def get_api_token(request: Request):
    """
    Get or create API token for a user after OAuth login.
    Called by frontend after successful OAuth callback.

    Request body should contain:
    - user_id: User ID from auth provider
    - username: Username
    - email: Email
    
    Returns:
    - token: API token for the user
    """
    try:
        body = await request.json()
        user_id = body.get("user_id")
        username = body.get("username")
        email = body.get("email")
        terms_accepted_at_raw = body.get("terms_accepted_at")
        terms_accepted_at = None
        if terms_accepted_at_raw:
            from datetime import datetime
            try:
                terms_accepted_at = datetime.fromisoformat(terms_accepted_at_raw.replace("Z", "+00:00")).replace(tzinfo=None)
            except (ValueError, AttributeError):
                terms_accepted_at = None

        # Validate required fields (email can be generated)
        if not user_id or not username:
            raise HTTPException(status_code=400, detail="user_id and username required")
        
        # If email is not provided, generate one
        if not email:
            email = f"{username}@argus.local"
        
        logger.info(f"Getting API token for user: id={user_id}, username={username}, email={email}")
        
        # Check if user exists (prioritize id and username over email)
        query = """
            SELECT id, username, email, api_token, is_active, role
            FROM users
            WHERE id = :user_id OR username = :username
        """
        user = await database.fetch_one(
            query=query, 
            values={"user_id": user_id, "username": username}
        )
        
        if user:
            # User exists - return existing token or generate new one
            if not user["is_active"]:
                raise HTTPException(status_code=403, detail="User account is inactive")

            api_token = user["api_token"]
            if not api_token:
                # Generate new API token
                import secrets
                api_token = secrets.token_urlsafe(32)

            # Always update username/email from latest CIAM claims
            # (fixes stale data if CIAM profile was updated after initial registration)
            update_query = """
                UPDATE users
                SET api_token = COALESCE(:api_token, api_token),
                    username = :username,
                    email = :email,
                    updated_at = NOW()
                WHERE id = :user_id
            """
            await database.execute(
                query=update_query,
                values={
                    "api_token": api_token,
                    "user_id": user["id"],
                    "username": username,
                    "email": email,
                }
            )
            logger.info(f"Updated user {user['id']}: username={username}, email={email}")

            return {"token": api_token, "role": user["role"]}
        else:
            # User doesn't exist - create new user with API token
            import secrets
            api_token = secrets.token_urlsafe(32)
            
            create_query = """
                INSERT INTO users (id, username, email, api_token, role, is_active, terms_accepted_at, created_at, updated_at)
                VALUES (:user_id, :username, :email, :api_token, :role, true, :terms_accepted_at, NOW(), NOW())
                RETURNING id
            """
            await database.execute(
                query=create_query,
                values={
                    "user_id": user_id,
                    "username": username,
                    "email": email,
                    "api_token": api_token,
                    "role": "ORDINARY_USER",
                    "terms_accepted_at": terms_accepted_at,
                }
            )
            logger.info(f"Created new user {user_id} with API token")

            return {"token": api_token, "role": "ORDINARY_USER"}
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting API token: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/api/v1/auth/token_info")
async def get_token_info(auth_data: tuple = Depends(get_current_user_dual_auth)):
    """
    Get information about the current authentication token.
    Works with both JWT and API tokens.
    """
    user, jwt_payload = auth_data
    
    response = {
        "user_id": str(user.id),
        "username": user.username,
        "email": user.email,
        "token_type": "jwt" if jwt_payload else "api_token"
    }
    
    if jwt_payload:
        # Add JWT-specific information
        response.update({
            "scopes": jwt_payload.get("scope", "").split() if isinstance(jwt_payload.get("scope"), str) else jwt_payload.get("scopes", []),
            "issued_at": jwt_payload.get("iat"),
            "expires_at": jwt_payload.get("exp"),
            "issuer": jwt_payload.get("iss"),
            "subject": jwt_payload.get("sub")
        })
    
    return response

@app.post("/api/v1/auth/refresh")
async def refresh_token(refresh_token: str):
    """
    Refresh an access token using a refresh token.
    
    Note: This is a placeholder. Actual implementation depends on whether
    the auth provider issues refresh tokens in the current flow.
    """
    raise HTTPException(
        status_code=501,
        detail="Token refresh not implemented. Client Credentials flow typically doesn't use refresh tokens. Request a new token instead."
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8881)
