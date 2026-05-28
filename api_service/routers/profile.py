import logging
import re
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional
from database import database
from auth import get_current_user
from models import UserResponse
from redteam.audit import log_audit

logger = logging.getLogger("Profile")

router = APIRouter()

# Synthetic email domains the Microsoft Entra External ID flow falls back to
# when the real email claim isn't captured. Users with these as their email
# can't receive any communication; force them to set a real address.
_SYNTHETIC_EMAIL_DOMAINS = (
    "@yourtenant.onmicrosoft.com",
    "@argus.local",
)
_EMAIL_REGEX = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")


class ProfileUpdate(BaseModel):
    username: Optional[str] = None
    email: Optional[str] = None
    display_name: Optional[str] = None
    avatar: Optional[str] = None


class ProfileResponse(BaseModel):
    id: str
    username: str
    email: str
    display_name: Optional[str] = None
    avatar: Optional[str] = None
    role: str
    created_at: str
    updated_at: str


@router.get("/profile")
async def get_profile(current_user: UserResponse = Depends(get_current_user)):
    """Get the current user's profile."""
    return {
        "id": str(current_user.id),
        "username": current_user.username,
        "email": current_user.email,
        "display_name": current_user.display_name,
        "avatar": current_user.avatar,
        "role": current_user.role.value,
        "created_at": current_user.created_at.isoformat(),
        "updated_at": current_user.updated_at.isoformat(),
    }


@router.patch("/profile")
async def update_profile(
    update: ProfileUpdate,
    current_user: UserResponse = Depends(get_current_user),
):
    """Update the current user's profile."""
    # Build dynamic SET clause from non-None fields
    fields = {}
    if update.username is not None:
        if len(update.username.strip()) == 0:
            raise HTTPException(status_code=400, detail="Username cannot be empty")
        fields["username"] = update.username.strip()
    if update.email is not None:
        new_email = update.email.strip().lower()
        if len(new_email) == 0:
            raise HTTPException(status_code=400, detail="Email cannot be empty")
        if not _EMAIL_REGEX.match(new_email):
            raise HTTPException(status_code=400, detail="Invalid email format")
        # Block synthetic Microsoft Entra fallback domains. These get inserted
        # when the CIAM signup flow doesn't capture the user's real email; the
        # whole point of this PATCH is to replace one with a deliverable address.
        if any(new_email.endswith(d) for d in _SYNTHETIC_EMAIL_DOMAINS):
            raise HTTPException(
                status_code=400,
                detail="That looks like an auto-generated Microsoft account email. "
                       "Please enter the real email you want to receive Argus communications at.",
            )
        fields["email"] = new_email
    if update.display_name is not None:
        fields["display_name"] = update.display_name.strip() or None
    if update.avatar is not None:
        fields["avatar"] = update.avatar.strip() or None

    if not fields:
        raise HTTPException(status_code=400, detail="No fields to update")

    # Check username uniqueness if changing
    if "username" in fields:
        existing = await database.fetch_one(
            "SELECT id FROM users WHERE username = :username AND id != :user_id",
            values={"username": fields["username"], "user_id": str(current_user.id)},
        )
        if existing:
            raise HTTPException(status_code=409, detail="Username already taken")

    # Check email uniqueness if changing
    if "email" in fields:
        existing = await database.fetch_one(
            "SELECT id FROM users WHERE email = :email AND id != :user_id",
            values={"email": fields["email"], "user_id": str(current_user.id)},
        )
        if existing:
            raise HTTPException(status_code=409, detail="Email already in use")

    set_parts = [f"{k} = :{k}" for k in fields]
    set_parts.append("updated_at = NOW()")
    set_clause = ", ".join(set_parts)

    query = f"""
        UPDATE users SET {set_clause}
        WHERE id = :user_id
        RETURNING id, username, email, display_name, avatar, role, is_active, created_at, updated_at
    """
    values = {**fields, "user_id": str(current_user.id)}

    row = await database.fetch_one(query=query, values=values)
    if not row:
        raise HTTPException(status_code=404, detail="User not found")

    if "email" in fields and fields["email"] != current_user.email:
        await log_audit(
            action="email_changed",
            user_id=str(current_user.id),
            resource_type="user",
            resource_id=str(current_user.id),
            metadata={
                "from_email": current_user.email,
                "to_email": fields["email"],
            },
        )

    return {
        "id": str(row["id"]),
        "username": row["username"],
        "email": row["email"],
        "display_name": row["display_name"],
        "avatar": row["avatar"],
        "role": row["role"],
        "created_at": row["created_at"].isoformat() if row["created_at"] else None,
        "updated_at": row["updated_at"].isoformat() if row["updated_at"] else None,
    }
