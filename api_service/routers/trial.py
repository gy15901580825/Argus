import logging
import secrets
import os
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, EmailStr, Field
from typing import Optional
from urllib.parse import quote

from auth import require_admin, require_trial_create_permission
from database import database
from models import UserResponse

router = APIRouter()
logger = logging.getLogger("TrialRouter")

FRONTEND_URL = os.getenv("FRONTEND_URL", "https://example.com")
MAX_TOKENS_PER_EMAIL = 3


class TrialCreateRequest(BaseModel):
    email: EmailStr = Field(..., description="Recipient email address")
    target_url: str = Field(..., description="The API URL to test")
    expires_hours: int = Field(168, description="Token expiry in hours (default 168 = 7 days)")


class TrialCreateResponse(BaseModel):
    token: str
    trial_url: str
    expires_at: datetime


class TrialValidateRequest(BaseModel):
    token: str = Field(..., description="The trial token to validate")


class TrialValidateResponse(BaseModel):
    valid: bool
    target_url: Optional[str] = None
    email: Optional[str] = None
    reason: Optional[str] = None


class TrialConsumeRequest(BaseModel):
    token: str = Field(..., description="The trial token to consume")


class TrialConsumeResponse(BaseModel):
    success: bool
    reason: Optional[str] = None


@router.post("/trial/create", response_model=TrialCreateResponse)
async def create_trial_token(
    request: TrialCreateRequest,
    current_user: UserResponse = Depends(require_trial_create_permission),
):
    """
    Create a one-time trial token for anonymous API testing.
    Allowed: Admin, 'tester', 'w.lee'
    """
    logger.info(f"User {current_user.username} creating trial token for {request.email}")

    # Rate-limit: check unconsumed token count for this email
    count_query = """
        SELECT COUNT(*) as cnt FROM trial_tokens
        WHERE email = :email AND is_consumed = FALSE AND expires_at > NOW()
    """
    row = await database.fetch_one(query=count_query, values={"email": request.email})
    if row and row["cnt"] >= MAX_TOKENS_PER_EMAIL:
        raise HTTPException(
            status_code=429,
            detail=f"Email {request.email} already has {MAX_TOKENS_PER_EMAIL} active trial tokens. Wait for them to expire or be consumed.",
        )

    token = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + timedelta(hours=request.expires_hours)

    insert_query = """
        INSERT INTO trial_tokens (token, email, target_url, expires_at)
        VALUES (:token, :email, :target_url, :expires_at)
    """
    await database.execute(
        query=insert_query,
        values={
            "token": token,
            "email": request.email,
            "target_url": request.target_url,
            "expires_at": expires_at,
        },
    )

    trial_url = f"{FRONTEND_URL}/chat?trialUrl={quote(request.target_url, safe='')}&token={token}"

    logger.info(f"Created trial token for {request.email}, expires {expires_at.isoformat()}")

    return TrialCreateResponse(
        token=token,
        trial_url=trial_url,
        expires_at=expires_at,
    )


@router.post("/trial/validate", response_model=TrialValidateResponse)
async def validate_trial_token(request: TrialValidateRequest):
    """
    Validate a trial token. Public endpoint, no auth required.
    """
    query = """
        SELECT token, email, target_url, is_consumed, expires_at
        FROM trial_tokens
        WHERE token = :token
    """
    row = await database.fetch_one(query=query, values={"token": request.token})

    if not row:
        return TrialValidateResponse(valid=False, reason="not_found")

    if row["is_consumed"]:
        return TrialValidateResponse(valid=False, reason="consumed")

    if row["expires_at"] < datetime.now(timezone.utc):
        return TrialValidateResponse(valid=False, reason="expired")

    return TrialValidateResponse(
        valid=True,
        target_url=row["target_url"],
        email=row["email"],
    )


@router.post("/trial/consume", response_model=TrialConsumeResponse)
async def consume_trial_token(request: TrialConsumeRequest):
    """
    Consume a trial token (mark as used). Public endpoint, no auth required.
    Uses atomic UPDATE with conditions to prevent double-consumption.
    """
    update_query = """
        UPDATE trial_tokens
        SET is_consumed = TRUE, consumed_at = NOW()
        WHERE token = :token AND is_consumed = FALSE AND expires_at > NOW()
    """
    # The databases library doesn't return rowcount from execute directly,
    # so we validate first then update
    validate_query = """
        SELECT is_consumed, expires_at FROM trial_tokens WHERE token = :token
    """
    row = await database.fetch_one(query=validate_query, values={"token": request.token})

    if not row:
        return TrialConsumeResponse(success=False, reason="not_found")

    if row["is_consumed"]:
        return TrialConsumeResponse(success=False, reason="consumed")

    if row["expires_at"] < datetime.now(timezone.utc):
        return TrialConsumeResponse(success=False, reason="expired")

    await database.execute(query=update_query, values={"token": request.token})

    logger.info(f"Trial token consumed: {request.token[:8]}...")
    return TrialConsumeResponse(success=True)
