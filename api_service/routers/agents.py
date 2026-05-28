import logging
import os
from fastapi import APIRouter, HTTPException, Depends, Header, Request
from typing import Optional, List
from uuid import UUID

from database import database
from models import AgentListResponse, AgentInfo, AgentStatusUpdate, UserResponse
from auth import get_current_user, get_optional_user

router = APIRouter()
logger = logging.getLogger("AgentsRouter")

ORCHESTRATOR_SECRET = os.getenv("ORCHESTRATOR_SECRET", "default_secret_change_me")

async def get_user_id_from_request(
    request: Request,
    x_user_id: Optional[str] = Header(None),
    x_internal_call: Optional[str] = Header(None),
    current_user: Optional[UserResponse] = Depends(get_optional_user)
) -> str:
    """
    Extract user_id from request, supporting:
    1. OAuth token (for external API calls) -> returns current_user.id
    2. x-user-id + x-internal-call headers (for internal service-to-service calls)
    
    Security:
    - Internal calls (x-internal-call=true) bypass OAuth requirement
    - APISIX should strip x-internal-call from external requests
    - Internal calls should only be allowed within K8s cluster
    """
    # Priority 1: OAuth authenticated user
    if current_user:
        logger.info(f"🔐 OAuth authenticated user: {current_user.id}")
        return str(current_user.id)
    
    # Priority 2: Internal service call (e.g., from orchestrator)
    if x_user_id and x_internal_call == "true":
        logger.info(f"🔓 Internal service call for user: {x_user_id}")
        return x_user_id
    
    # Priority 3: APISIX-injected x-user-id (already OAuth validated by gateway)
    if x_user_id:
        logger.info(f"🌐 APISIX validated user: {x_user_id}")
        return x_user_id
        
    logger.error("❌ No valid authentication found")
    raise HTTPException(status_code=401, detail="Authentication required")

@router.get("/agent/list", response_model=AgentListResponse)
async def list_agents(
    user_id: str = Depends(get_user_id_from_request)
):
    """
    List agents for the current user.
    
    Note: 
    - This endpoint uses OAuth authentication (Bearer token in Authorization header)
    - OAuth token is different from agent's api_token stored in database
    - Query only uses user_id to filter agents, not api_token
    """
    logger.info("=" * 80)
    logger.info("📋 LIST AGENTS REQUEST")
    logger.info(f"User ID: {user_id}")
    logger.info("=" * 80)
    
    query = """
        SELECT id, agent_name, agent_type, status, description, created_at
        FROM client_agent
        WHERE user_id = :user_id
    """
    try:
        rows = await database.fetch_all(query=query, values={"user_id": user_id})
        
        logger.info(f"Found {len(rows)} agent(s) in database")
        
        agents = [
            AgentInfo(
                agent_id=str(row["id"]), # Use ID as agent_id
                agent_name=row["agent_name"],
                agent_type=row["agent_type"],
                status=row["status"],
                description=row["description"],
                created_at=row["created_at"]
            )
            for row in rows
        ]
        
        if agents:
            logger.info("📋 Agent details:")
            for idx, agent in enumerate(agents, 1):
                logger.info(f"  {idx}. Agent ID: {agent.agent_id}")
                logger.info(f"     Name: {agent.agent_name}")
                logger.info(f"     Status: {agent.status}")
                logger.info(f"     Type: {agent.agent_type}")
        else:
            logger.warning(f"⚠️ No agents found for user {user_id}")
            logger.info("Troubleshooting:")
            logger.info("  1. Client agent has not registered yet")
            logger.info("  2. Check if client agent registration succeeded")
            logger.info("  3. Verify the api_token used by client agent")
            logger.info("  4. Check database table 'client_agent'")
        
        logger.info("=" * 80)
        return AgentListResponse(agents=agents)
    except Exception as e:
        logger.error(f"❌ Error listing agents: {e}")
        logger.exception(e)
        logger.info("=" * 80)
        raise HTTPException(status_code=500, detail="Internal server error")

@router.post("/internal/agent/status")
async def update_agent_status(
    status_update: AgentStatusUpdate,
    x_orchestrator_secret: str = Header(...)
):
    """
    Update agent status (Internal endpoint called by Orchestrator).
    """
    if x_orchestrator_secret != ORCHESTRATOR_SECRET:
        raise HTTPException(status_code=403, detail="Invalid secret")
        
    query = """
        UPDATE client_agent
        SET status = :status, updated_at = NOW()
        WHERE id = :agent_id
    """
    try:
        # We assume agent_id is the UUID
        await database.execute(query=query, values={
            "status": status_update.status,
            "agent_id": status_update.agent_id
        })
        return {"status": "success"}
    except Exception as e:
        logger.error(f"Error updating agent status: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")
