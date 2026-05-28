import os
import json as _json
from fastapi import APIRouter, Depends, Header, HTTPException, Query
from typing import List
from uuid import UUID
from datetime import datetime

from database import database
from auth import get_current_user
from models import (
    UserResponse,
    ChatSessionCreate, ChatSessionUpdate, ChatSessionResponse,
    BulkDeleteRequest,
    ChatMessageCreate, ChatMessageResponse
)

router = APIRouter()

_PLANNER_HISTORY_CONTENT_CAP = 500

@router.post("/chat/sessions", response_model=ChatSessionResponse)
async def create_chat_session(
    session: ChatSessionCreate,
    current_user: UserResponse = Depends(get_current_user)
):
    query = """
        INSERT INTO chat_sessions (user_id, title)
        VALUES (:user_id, :title)
        RETURNING *
    """
    return await database.fetch_one(query=query, values={"user_id": current_user.id, "title": session.title})

@router.get("/chat/sessions", response_model=List[ChatSessionResponse])
async def list_chat_sessions(
    limit: int = 50,
    offset: int = 0,
    current_user: UserResponse = Depends(get_current_user)
):
    query = """
        SELECT * FROM chat_sessions
        WHERE user_id = :user_id
        ORDER BY updated_at DESC
        LIMIT :limit OFFSET :offset
    """
    return await database.fetch_all(query=query, values={"user_id": current_user.id, "limit": limit, "offset": offset})

@router.get("/chat/sessions/{session_id}", response_model=ChatSessionResponse)
async def get_chat_session(
    session_id: UUID,
    current_user: UserResponse = Depends(get_current_user)
):
    query = "SELECT * FROM chat_sessions WHERE id = :id AND user_id = :user_id"
    session = await database.fetch_one(query=query, values={"id": session_id, "user_id": current_user.id})
    if not session:
        raise HTTPException(status_code=404, detail="Chat session not found")
    return session

@router.put("/chat/sessions/{session_id}", response_model=ChatSessionResponse)
async def update_chat_session(
    session_id: UUID,
    session_update: ChatSessionUpdate,
    current_user: UserResponse = Depends(get_current_user)
):
    # Check ownership
    check_query = "SELECT * FROM chat_sessions WHERE id = :id AND user_id = :user_id"
    existing_session = await database.fetch_one(query=check_query, values={"id": session_id, "user_id": current_user.id})
    if not existing_session:
        raise HTTPException(status_code=404, detail="Chat session not found")

    query = """
        UPDATE chat_sessions
        SET title = :title, updated_at = CURRENT_TIMESTAMP
        WHERE id = :id
        RETURNING *
    """
    return await database.fetch_one(query=query, values={"id": session_id, "title": session_update.title})

@router.delete("/chat/sessions/{session_id}")
async def delete_chat_session(
    session_id: UUID,
    current_user: UserResponse = Depends(get_current_user)
):
    # Check ownership
    check_query = "SELECT * FROM chat_sessions WHERE id = :id AND user_id = :user_id"
    existing_session = await database.fetch_one(query=check_query, values={"id": session_id, "user_id": current_user.id})
    if not existing_session:
        raise HTTPException(status_code=404, detail="Chat session not found")

    query = "DELETE FROM chat_sessions WHERE id = :id"
    await database.execute(query=query, values={"id": session_id})
    return {"message": "Chat session deleted"}

@router.post("/chat/sessions/bulk-delete")
async def bulk_delete_chat_sessions(
    payload: BulkDeleteRequest,
    current_user: UserResponse = Depends(get_current_user),
):
    query = """
        DELETE FROM chat_sessions
        WHERE id = ANY(:ids) AND user_id = :user_id
        RETURNING id
    """
    rows = await database.fetch_all(
        query=query,
        values={"ids": payload.ids, "user_id": current_user.id},
    )
    deleted_ids = [str(r["id"]) for r in rows]
    return {"deleted_count": len(deleted_ids), "deleted_ids": deleted_ids}

@router.post("/chat/sessions/{session_id}/messages", response_model=ChatMessageResponse)
async def create_chat_message(
    session_id: UUID,
    message: ChatMessageCreate,
    current_user: UserResponse = Depends(get_current_user)
):
    # Check ownership of session
    check_query = "SELECT * FROM chat_sessions WHERE id = :id AND user_id = :user_id"
    session = await database.fetch_one(query=check_query, values={"id": session_id, "user_id": current_user.id})
    if not session:
        raise HTTPException(status_code=404, detail="Chat session not found")

    # Insert message. chunks is JSONB; use CAST so the databases lib can bind
    # a plain string parameter (mirrors wizard_state in routers/orchestrator.py).
    query = """
        INSERT INTO chat_messages (session_id, role, content, chunks)
        VALUES (:session_id, :role, :content, CAST(:chunks AS jsonb))
        RETURNING *
    """
    new_message = await database.fetch_one(query=query, values={
        "session_id": session_id,
        "role": message.role,
        "content": message.content,
        "chunks": _json.dumps(message.chunks) if message.chunks is not None else None,
    })
    
    # Update session updated_at
    update_session_query = "UPDATE chat_sessions SET updated_at = CURRENT_TIMESTAMP WHERE id = :id"
    await database.execute(query=update_session_query, values={"id": session_id})
    
    return new_message

@router.get("/chat/sessions/{session_id}/messages", response_model=List[ChatMessageResponse])
async def list_chat_messages(
    session_id: UUID,
    current_user: UserResponse = Depends(get_current_user)
):
    # Check ownership of session
    check_query = "SELECT * FROM chat_sessions WHERE id = :id AND user_id = :user_id"
    session = await database.fetch_one(query=check_query, values={"id": session_id, "user_id": current_user.id})
    if not session:
        raise HTTPException(status_code=404, detail="Chat session not found")

    query = """
        SELECT * FROM chat_messages
        WHERE session_id = :session_id
        ORDER BY created_at ASC
    """
    return await database.fetch_all(query=query, values={"session_id": session_id})


@router.get("/chat/sessions/{session_id}/planner-history")
async def get_planner_history(
    session_id: UUID,
    limit: int = Query(5, ge=1, le=20),
    x_user_id: str = Header(None),
    x_service_secret: str = Header(None),
):
    """Service-to-service endpoint: return last N*2 user/assistant messages,
    with content truncated to 500 chars. Consumed by the orchestrator planner
    to load core history for prompt caching."""
    expected = os.getenv("ORCHESTRATOR_SECRET", "default_secret_change_me")
    if x_service_secret != expected:
        raise HTTPException(status_code=401, detail="Invalid service secret")
    if not x_user_id:
        raise HTTPException(status_code=400, detail="Missing x-user-id")

    owner_q = "SELECT id FROM chat_sessions WHERE id = :id AND user_id = :uid"
    row = await database.fetch_one(
        query=owner_q, values={"id": session_id, "uid": x_user_id}
    )
    if not row:
        raise HTTPException(status_code=404, detail="Chat session not found")

    q = """
        SELECT role, content FROM chat_messages
        WHERE session_id = :sid AND role IN ('user', 'assistant')
        ORDER BY created_at ASC
        LIMIT :lim
    """
    rows = await database.fetch_all(
        query=q, values={"sid": session_id, "lim": limit * 2}
    )
    messages = [
        {
            "role": r["role"],
            "content": (r["content"] or "")[:_PLANNER_HISTORY_CONTENT_CAP],
        }
        for r in rows
    ]
    return {"messages": messages}
