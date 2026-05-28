import logging
from typing import List, Optional
from uuid import UUID
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from database import database
from auth import get_current_user, get_optional_user, require_admin
from models import (
    UserResponse,
    BlogCreate, BlogUpdate, BlogResponse, BlogListItem,
    CommentCreate, CommentResponse,
)

router = APIRouter()
logger = logging.getLogger("BlogsRouter")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _require_blog_author_or_admin(user: UserResponse) -> None:
    """Raise 403 unless user is admin OR a designated blog author."""
    if user.role in ("SUPER_ADMIN", "CONTENT_ADMIN"):
        return
    row = await database.fetch_one(
        "SELECT user_id FROM blog_authors WHERE user_id = :uid",
        {"uid": user.id},
    )
    if not row:
        raise HTTPException(status_code=403, detail="Blog author privileges required")


async def _attach_tags(blog_id: UUID) -> List[dict]:
    rows = await database.fetch_all(
        """SELECT t.id, t.name, t.slug
           FROM blog_tags t
           JOIN blog_tag_map m ON m.tag_id = t.id
           WHERE m.blog_id = :bid""",
        {"bid": blog_id},
    )
    return [dict(r) for r in rows]


async def _sync_tags(blog_id: UUID, tag_ids: List[UUID]) -> None:
    await database.execute(
        "DELETE FROM blog_tag_map WHERE blog_id = :bid", {"bid": blog_id}
    )
    for tid in tag_ids:
        await database.execute(
            "INSERT INTO blog_tag_map (blog_id, tag_id) VALUES (:bid, :tid) ON CONFLICT DO NOTHING",
            {"bid": blog_id, "tid": tid},
        )


def _generate_slug(title: str) -> str:
    import re
    slug = title.lower().strip()
    slug = re.sub(r"[^a-z0-9\s-]", "", slug)
    slug = re.sub(r"[\s]+", "-", slug)
    slug = re.sub(r"-+", "-", slug).strip("-")
    return slug


# ---------------------------------------------------------------------------
# Public — List blogs (lightweight)
# ---------------------------------------------------------------------------

@router.get("/blogs", response_model=List[BlogListItem])
async def list_blogs(
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    category: Optional[str] = Query(None, description="Category slug"),
    tag: Optional[str] = Query(None, description="Tag slug"),
    q: Optional[str] = Query(None, description="Full-text search query"),
    featured: Optional[bool] = None,
    status: Optional[str] = None,
    include_unpublished: bool = False,
    current_user: Optional[UserResponse] = Depends(get_optional_user),
):
    """List blogs with filtering, search, and pagination."""

    show_all = False
    if include_unpublished or (status and status != "published"):
        if current_user and current_user.role in ("SUPER_ADMIN", "CONTENT_ADMIN"):
            show_all = True

    conditions = []
    values: dict = {"limit": limit, "offset": offset}

    if not show_all:
        conditions.append("b.status = 'published' AND b.is_published = TRUE")

    if status and show_all:
        conditions.append("b.status = :status")
        values["status"] = status

    if category:
        conditions.append("c.slug = :cat_slug")
        values["cat_slug"] = category

    if tag:
        conditions.append(
            "EXISTS (SELECT 1 FROM blog_tag_map m JOIN blog_tags t ON t.id = m.tag_id WHERE m.blog_id = b.id AND t.slug = :tag_slug)"
        )
        values["tag_slug"] = tag

    if q:
        conditions.append("b.search_vector @@ plainto_tsquery('english', :q)")
        values["q"] = q

    if featured is not None:
        conditions.append("b.featured = :featured")
        values["featured"] = featured

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

    order = "ORDER BY ts_rank(b.search_vector, plainto_tsquery('english', :q)) DESC" if q else "ORDER BY b.published_at DESC NULLS LAST, b.created_at DESC"

    query = f"""
        SELECT b.id, b.title, b.slug, b.summary, b.author_id,
               b.is_published, b.published_at, b.created_at,
               b.category_id, b.cover_image_url, b.reading_time_min,
               b.view_count, b.featured, b.status,
               u.display_name AS author_name,
               c.name AS category_name, c.slug AS category_slug
        FROM blogs b
        JOIN users u ON b.author_id = u.id
        LEFT JOIN blog_categories c ON b.category_id = c.id
        {where}
        {order}
        LIMIT :limit OFFSET :offset
    """

    rows = await database.fetch_all(query=query, values=values)
    results = []
    for r in rows:
        item = dict(r)
        item["tags"] = await _attach_tags(r["id"])
        results.append(item)
    return results


# ---------------------------------------------------------------------------
# Public — Get single blog by ID or slug
# ---------------------------------------------------------------------------

@router.get("/blogs/by-slug/{slug}", response_model=BlogResponse)
async def get_blog_by_slug(slug: str, request: Request):
    """Get a published blog by its slug. Increments view count."""
    query = """
        SELECT b.*, u.display_name AS author_name,
               c.name AS category_name, c.slug AS category_slug
        FROM blogs b
        JOIN users u ON b.author_id = u.id
        LEFT JOIN blog_categories c ON b.category_id = c.id
        WHERE b.slug = :slug AND b.is_published = TRUE
    """
    blog = await database.fetch_one(query=query, values={"slug": slug})
    if not blog:
        raise HTTPException(status_code=404, detail="Blog not found")

    # Increment view count + record view
    await database.execute(
        "UPDATE blogs SET view_count = view_count + 1 WHERE id = :id",
        {"id": blog["id"]},
    )
    await database.execute(
        "INSERT INTO blog_views (blog_id, viewer_ip, user_agent) VALUES (:bid, :ip, :ua)",
        {
            "bid": blog["id"],
            "ip": request.client.host if request.client else None,
            "ua": request.headers.get("user-agent", "")[:500],
        },
    )

    result = dict(blog)
    result["tags"] = await _attach_tags(blog["id"])
    result["view_count"] = (result.get("view_count") or 0) + 1
    return result


@router.get("/blogs/{id}", response_model=BlogResponse)
async def get_blog(id: UUID, request: Request):
    """Get a blog by ID. Increments view count for published blogs."""
    query = """
        SELECT b.*, u.display_name AS author_name,
               c.name AS category_name, c.slug AS category_slug
        FROM blogs b
        JOIN users u ON b.author_id = u.id
        LEFT JOIN blog_categories c ON b.category_id = c.id
        WHERE b.id = :id
    """
    blog = await database.fetch_one(query=query, values={"id": id})
    if not blog:
        raise HTTPException(status_code=404, detail="Blog not found")

    if blog["is_published"]:
        await database.execute(
            "UPDATE blogs SET view_count = view_count + 1 WHERE id = :id",
            {"id": blog["id"]},
        )
        await database.execute(
            "INSERT INTO blog_views (blog_id, viewer_ip, user_agent) VALUES (:bid, :ip, :ua)",
            {
                "bid": blog["id"],
                "ip": request.client.host if request.client else None,
                "ua": request.headers.get("user-agent", "")[:500],
            },
        )

    result = dict(blog)
    result["tags"] = await _attach_tags(blog["id"])
    return result


# ---------------------------------------------------------------------------
# Admin — Create blog
# ---------------------------------------------------------------------------

@router.post("/blogs", response_model=BlogResponse)
async def create_blog(
    blog: BlogCreate,
    current_user: UserResponse = Depends(get_current_user),
):
    """Create a new blog post. Requires admin or blog author role."""
    await _require_blog_author_or_admin(current_user)

    slug = blog.slug or _generate_slug(blog.title)
    is_published = blog.status == "published"
    published_at = datetime.utcnow() if is_published else None

    query = """
        INSERT INTO blogs (
            title, content, slug, summary, author_id,
            category_id, cover_image_url,
            meta_title, meta_description, og_image_url, canonical_url,
            content_format, featured, status, scheduled_at, locale,
            is_published, published_at
        ) VALUES (
            :title, :content, :slug, :summary, :author_id,
            :category_id, :cover_image_url,
            :meta_title, :meta_description, :og_image_url, :canonical_url,
            :content_format, :featured, :status, :scheduled_at, :locale,
            :is_published, :published_at
        )
        RETURNING *
    """
    values = {
        "title": blog.title,
        "content": blog.content,
        "slug": slug,
        "summary": blog.summary,
        "author_id": current_user.id,
        "category_id": blog.category_id,
        "cover_image_url": blog.cover_image_url,
        "meta_title": blog.meta_title,
        "meta_description": blog.meta_description,
        "og_image_url": blog.og_image_url,
        "canonical_url": blog.canonical_url,
        "content_format": blog.content_format,
        "featured": blog.featured,
        "status": blog.status,
        "scheduled_at": blog.scheduled_at,
        "locale": blog.locale,
        "is_published": is_published,
        "published_at": published_at,
    }

    try:
        new_blog = await database.fetch_one(query=query, values=values)
    except Exception as e:
        if "duplicate key" in str(e).lower() and "slug" in str(e).lower():
            raise HTTPException(status_code=409, detail="A blog with this slug already exists")
        raise HTTPException(status_code=500, detail=str(e))

    # Sync tags
    if blog.tag_ids:
        await _sync_tags(new_blog["id"], blog.tag_ids)

    result = dict(new_blog)
    result["author_name"] = current_user.display_name
    result["category_name"] = None
    result["category_slug"] = None
    if blog.category_id:
        cat = await database.fetch_one(
            "SELECT name, slug FROM blog_categories WHERE id = :id",
            {"id": blog.category_id},
        )
        if cat:
            result["category_name"] = cat["name"]
            result["category_slug"] = cat["slug"]
    result["tags"] = await _attach_tags(new_blog["id"])
    return result


# ---------------------------------------------------------------------------
# Admin — Update blog
# ---------------------------------------------------------------------------

@router.put("/blogs/{id}", response_model=BlogResponse)
async def update_blog(
    id: UUID,
    blog_update: BlogUpdate,
    current_user: UserResponse = Depends(get_current_user),
):
    """Update a blog post. Requires admin or blog author role."""
    await _require_blog_author_or_admin(current_user)

    existing = await database.fetch_one("SELECT * FROM blogs WHERE id = :id", {"id": id})
    if not existing:
        raise HTTPException(status_code=404, detail="Blog not found")

    update_fields = []
    values: dict = {"id": id}

    field_map = {
        "title": blog_update.title,
        "content": blog_update.content,
        "slug": blog_update.slug,
        "summary": blog_update.summary,
        "category_id": blog_update.category_id,
        "cover_image_url": blog_update.cover_image_url,
        "meta_title": blog_update.meta_title,
        "meta_description": blog_update.meta_description,
        "og_image_url": blog_update.og_image_url,
        "canonical_url": blog_update.canonical_url,
        "content_format": blog_update.content_format,
        "featured": blog_update.featured,
        "scheduled_at": blog_update.scheduled_at,
    }

    for col, val in field_map.items():
        if val is not None:
            update_fields.append(f"{col} = :{col}")
            values[col] = val

    # Handle status + is_published synchronisation
    if blog_update.status is not None:
        update_fields.append("status = :status")
        values["status"] = blog_update.status
        if blog_update.status == "published" and not existing["is_published"]:
            update_fields.append("is_published = TRUE")
            update_fields.append("published_at = NOW()")
        elif blog_update.status == "draft":
            update_fields.append("is_published = FALSE")
            update_fields.append("published_at = NULL")
    elif blog_update.is_published is not None:
        update_fields.append("is_published = :is_published")
        values["is_published"] = blog_update.is_published
        if blog_update.is_published and not existing["is_published"]:
            update_fields.append("published_at = NOW()")
            update_fields.append("status = 'published'")
        elif not blog_update.is_published:
            update_fields.append("published_at = NULL")
            update_fields.append("status = 'draft'")

    if not update_fields and blog_update.tag_ids is None:
        # Nothing to change
        result = dict(existing)
        result["author_name"] = current_user.display_name
        result["tags"] = await _attach_tags(id)
        return result

    if update_fields:
        update_fields.append("updated_at = NOW()")
        query = f"""
            UPDATE blogs SET {", ".join(update_fields)}
            WHERE id = :id
            RETURNING *
        """
        try:
            updated = await database.fetch_one(query=query, values=values)
        except Exception as e:
            if "duplicate key" in str(e).lower() and "slug" in str(e).lower():
                raise HTTPException(status_code=409, detail="A blog with this slug already exists")
            raise HTTPException(status_code=500, detail=str(e))
    else:
        updated = existing

    # Sync tags if provided
    if blog_update.tag_ids is not None:
        await _sync_tags(id, blog_update.tag_ids)

    # Build response
    author = await database.fetch_one(
        "SELECT display_name FROM users WHERE id = :id", {"id": updated["author_id"]}
    )
    cat = await database.fetch_one(
        "SELECT name, slug FROM blog_categories WHERE id = :id",
        {"id": updated["category_id"]},
    ) if updated["category_id"] else None

    result = dict(updated)
    result["author_name"] = author["display_name"] if author else None
    result["category_name"] = cat["name"] if cat else None
    result["category_slug"] = cat["slug"] if cat else None
    result["tags"] = await _attach_tags(id)
    return result


# ---------------------------------------------------------------------------
# Admin — Delete blog
# ---------------------------------------------------------------------------

@router.delete("/blogs/{id}")
async def delete_blog(
    id: UUID,
    current_user: UserResponse = Depends(require_admin),
):
    """Delete a blog post (Admin only)."""
    existing = await database.fetch_one("SELECT id FROM blogs WHERE id = :id", {"id": id})
    if not existing:
        raise HTTPException(status_code=404, detail="Blog not found")

    await database.execute("DELETE FROM blog_tag_map WHERE blog_id = :id", {"id": id})
    await database.execute("DELETE FROM blogs WHERE id = :id", {"id": id})
    return {"status": "success", "message": "Blog deleted"}


# ---------------------------------------------------------------------------
# Comments
# ---------------------------------------------------------------------------

@router.get("/blogs/{id}/comments", response_model=List[CommentResponse])
async def list_comments(id: UUID):
    """List approved comments for a blog."""
    query = """
        SELECT c.*, u.display_name AS user_name
        FROM comments c
        JOIN users u ON c.user_id = u.id
        WHERE c.blog_id = :blog_id AND c.status = 'approved'
        ORDER BY c.created_at ASC
    """
    return await database.fetch_all(query=query, values={"blog_id": id})


@router.post("/blogs/{id}/comments", response_model=CommentResponse)
async def add_comment(
    id: UUID,
    comment: CommentCreate,
    current_user: UserResponse = Depends(get_current_user),
):
    """Add a comment to a blog."""
    blog_check = await database.fetch_one(
        "SELECT id FROM blogs WHERE id = :id AND is_published = TRUE", {"id": id}
    )
    if not blog_check:
        raise HTTPException(status_code=404, detail="Blog not found")

    query = """
        INSERT INTO comments (content, user_id, blog_id, parent_comment_id)
        VALUES (:content, :user_id, :blog_id, :parent_comment_id)
        RETURNING id, content, user_id, blog_id, parent_comment_id, created_at, updated_at, status, likes_count
    """
    values = {
        "content": comment.content,
        "user_id": current_user.id,
        "blog_id": id,
        "parent_comment_id": comment.parent_comment_id,
    }
    new_comment = await database.fetch_one(query=query, values=values)
    return {**dict(new_comment), "user_name": current_user.display_name}


# ---------------------------------------------------------------------------
# Blog Stats (admin)
# ---------------------------------------------------------------------------

@router.get("/blogs/admin/stats")
async def blog_stats(current_user: UserResponse = Depends(require_admin)):
    """Overview stats for admin dashboard."""
    rows = await database.fetch_all(
        """SELECT
               COUNT(*) AS total,
               COUNT(*) FILTER (WHERE status = 'published') AS published,
               COUNT(*) FILTER (WHERE status = 'draft') AS drafts,
               COALESCE(SUM(view_count), 0) AS total_views
           FROM blogs"""
    )
    r = dict(rows[0]) if rows else {"total": 0, "published": 0, "drafts": 0, "total_views": 0}

    comments_row = await database.fetch_one("SELECT COUNT(*) AS n FROM comments")
    r["total_comments"] = comments_row["n"] if comments_row else 0

    top_posts = await database.fetch_all(
        """SELECT id, title, slug, view_count
           FROM blogs WHERE is_published = TRUE
           ORDER BY view_count DESC LIMIT 5"""
    )
    r["top_posts"] = [dict(p) for p in top_posts]
    return r
