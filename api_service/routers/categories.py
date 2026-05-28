import logging
import re
from typing import List
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from database import database
from auth import require_admin
from models import UserResponse, CategoryCreate, CategoryResponse

router = APIRouter()
logger = logging.getLogger("CategoriesRouter")


def _slugify(name: str) -> str:
    slug = name.lower().strip()
    slug = re.sub(r"[^a-z0-9\s-]", "", slug)
    slug = re.sub(r"[\s]+", "-", slug)
    return re.sub(r"-+", "-", slug).strip("-")


@router.get("/blog/categories", response_model=List[CategoryResponse])
async def list_categories():
    """List all blog categories with post counts."""
    query = """
        SELECT c.*, COALESCE(cnt.n, 0) AS post_count
        FROM blog_categories c
        LEFT JOIN (
            SELECT category_id, COUNT(*) AS n
            FROM blogs WHERE is_published = TRUE
            GROUP BY category_id
        ) cnt ON cnt.category_id = c.id
        ORDER BY c.sort_order, c.name
    """
    return await database.fetch_all(query=query)


@router.get("/blog/categories/{slug}", response_model=CategoryResponse)
async def get_category(slug: str):
    query = """
        SELECT c.*, COALESCE(cnt.n, 0) AS post_count
        FROM blog_categories c
        LEFT JOIN (
            SELECT category_id, COUNT(*) AS n
            FROM blogs WHERE is_published = TRUE
            GROUP BY category_id
        ) cnt ON cnt.category_id = c.id
        WHERE c.slug = :slug
    """
    row = await database.fetch_one(query=query, values={"slug": slug})
    if not row:
        raise HTTPException(status_code=404, detail="Category not found")
    return row


@router.post("/blog/categories", response_model=CategoryResponse)
async def create_category(
    body: CategoryCreate,
    current_user: UserResponse = Depends(require_admin),
):
    slug = body.slug or _slugify(body.name)
    query = """
        INSERT INTO blog_categories (name, slug, description, parent_id, sort_order)
        VALUES (:name, :slug, :description, :parent_id, :sort_order)
        RETURNING *, 0 AS post_count
    """
    try:
        return await database.fetch_one(query=query, values={
            "name": body.name, "slug": slug, "description": body.description,
            "parent_id": body.parent_id, "sort_order": body.sort_order,
        })
    except Exception as e:
        if "duplicate key" in str(e).lower():
            raise HTTPException(status_code=409, detail="Category slug already exists")
        raise


@router.put("/blog/categories/{cat_id}", response_model=CategoryResponse)
async def update_category(
    cat_id: UUID,
    body: CategoryCreate,
    current_user: UserResponse = Depends(require_admin),
):
    slug = body.slug or _slugify(body.name)
    query = """
        UPDATE blog_categories
        SET name = :name, slug = :slug, description = :description,
            parent_id = :parent_id, sort_order = :sort_order
        WHERE id = :id
        RETURNING *, 0 AS post_count
    """
    row = await database.fetch_one(query=query, values={
        "id": cat_id, "name": body.name, "slug": slug,
        "description": body.description, "parent_id": body.parent_id,
        "sort_order": body.sort_order,
    })
    if not row:
        raise HTTPException(status_code=404, detail="Category not found")
    return row


@router.delete("/blog/categories/{cat_id}")
async def delete_category(
    cat_id: UUID,
    current_user: UserResponse = Depends(require_admin),
):
    existing = await database.fetch_one(
        "SELECT id FROM blog_categories WHERE id = :id", {"id": cat_id}
    )
    if not existing:
        raise HTTPException(status_code=404, detail="Category not found")
    await database.execute(
        "UPDATE blogs SET category_id = NULL WHERE category_id = :id", {"id": cat_id}
    )
    await database.execute(
        "DELETE FROM blog_categories WHERE id = :id", {"id": cat_id}
    )
    return {"status": "success"}
