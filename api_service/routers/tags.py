import logging
import re
from typing import List
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from database import database
from auth import require_admin
from models import UserResponse, TagCreate, TagResponse

router = APIRouter()
logger = logging.getLogger("TagsRouter")


def _slugify(name: str) -> str:
    slug = name.lower().strip()
    slug = re.sub(r"[^a-z0-9\s-]", "", slug)
    slug = re.sub(r"[\s]+", "-", slug)
    return re.sub(r"-+", "-", slug).strip("-")


@router.get("/blog/tags", response_model=List[TagResponse])
async def list_tags():
    """List all tags with post counts."""
    query = """
        SELECT t.*, COALESCE(cnt.n, 0) AS post_count
        FROM blog_tags t
        LEFT JOIN (
            SELECT tag_id, COUNT(*) AS n FROM blog_tag_map GROUP BY tag_id
        ) cnt ON cnt.tag_id = t.id
        ORDER BY t.name
    """
    return await database.fetch_all(query=query)


@router.post("/blog/tags", response_model=TagResponse)
async def create_tag(
    body: TagCreate,
    current_user: UserResponse = Depends(require_admin),
):
    slug = body.slug or _slugify(body.name)
    query = """
        INSERT INTO blog_tags (name, slug)
        VALUES (:name, :slug)
        RETURNING *, 0 AS post_count
    """
    try:
        return await database.fetch_one(query=query, values={"name": body.name, "slug": slug})
    except Exception as e:
        if "duplicate key" in str(e).lower():
            raise HTTPException(status_code=409, detail="Tag slug already exists")
        raise


@router.delete("/blog/tags/{tag_id}")
async def delete_tag(
    tag_id: UUID,
    current_user: UserResponse = Depends(require_admin),
):
    existing = await database.fetch_one(
        "SELECT id FROM blog_tags WHERE id = :id", {"id": tag_id}
    )
    if not existing:
        raise HTTPException(status_code=404, detail="Tag not found")
    await database.execute("DELETE FROM blog_tag_map WHERE tag_id = :id", {"id": tag_id})
    await database.execute("DELETE FROM blog_tags WHERE id = :id", {"id": tag_id})
    return {"status": "success"}
