import logging
from typing import List
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from database import database
from auth import require_admin
from models import UserResponse, BlogAuthorCreate, BlogAuthorResponse

router = APIRouter()
logger = logging.getLogger("BlogAuthorsRouter")


@router.get("/blog/authors", response_model=List[BlogAuthorResponse])
async def list_blog_authors():
    """List all designated blog authors."""
    return await database.fetch_all(
        "SELECT * FROM blog_authors ORDER BY granted_at DESC"
    )


@router.post("/blog/authors", response_model=BlogAuthorResponse)
async def grant_blog_author(
    body: BlogAuthorCreate,
    current_user: UserResponse = Depends(require_admin),
):
    """Designate a user as blog author (admin only)."""
    # Verify user exists
    user = await database.fetch_one(
        "SELECT id FROM users WHERE id = :id", {"id": body.user_id}
    )
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    query = """
        INSERT INTO blog_authors (user_id, display_name, bio, granted_by)
        VALUES (:user_id, :display_name, :bio, :granted_by)
        ON CONFLICT (user_id) DO UPDATE
            SET display_name = EXCLUDED.display_name, bio = EXCLUDED.bio
        RETURNING *
    """
    return await database.fetch_one(query=query, values={
        "user_id": body.user_id,
        "display_name": body.display_name,
        "bio": body.bio,
        "granted_by": current_user.id,
    })


@router.delete("/blog/authors/{user_id}")
async def revoke_blog_author(
    user_id: UUID,
    current_user: UserResponse = Depends(require_admin),
):
    """Revoke blog author rights (admin only)."""
    existing = await database.fetch_one(
        "SELECT user_id FROM blog_authors WHERE user_id = :id", {"id": user_id}
    )
    if not existing:
        raise HTTPException(status_code=404, detail="Blog author not found")
    await database.execute(
        "DELETE FROM blog_authors WHERE user_id = :id", {"id": user_id}
    )
    return {"status": "success"}
