import logging
import os
import uuid as _uuid
from datetime import datetime
from typing import List

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from database import database
from auth import get_current_user
from models import UserResponse, MediaResponse
from r2_storage import r2_storage

router = APIRouter()
logger = logging.getLogger("MediaRouter")

# Media assets live in a dedicated publicly-accessible R2 bucket so social
# crawlers (Twitter / LinkedIn / Facebook) can fetch og:image URLs.
# Falls back to the shared scripts bucket if not configured.
MEDIA_BUCKET_NAME = os.getenv("R2_MEDIA_BUCKET_NAME") or (r2_storage.bucket_name if r2_storage else None)
MEDIA_PUBLIC_URL_BASE = os.getenv("R2_MEDIA_PUBLIC_URL_BASE") or (r2_storage.public_url_base if r2_storage else None)

ALLOWED_MIME = {
    "image/jpeg", "image/png", "image/gif", "image/webp", "image/svg+xml",
    "video/mp4", "application/pdf",
}
MAX_SIZE = 10 * 1024 * 1024  # 10 MB


@router.get("/blog/media", response_model=List[MediaResponse])
async def list_media(
    limit: int = 50,
    offset: int = 0,
    current_user: UserResponse = Depends(get_current_user),
):
    query = """
        SELECT * FROM media_assets
        WHERE uploaded_by = :uid
        ORDER BY created_at DESC
        LIMIT :limit OFFSET :offset
    """
    return await database.fetch_all(query=query, values={
        "uid": current_user.id, "limit": limit, "offset": offset,
    })


@router.post("/blog/media", response_model=MediaResponse)
async def upload_media(
    file: UploadFile = File(...),
    current_user: UserResponse = Depends(get_current_user),
):
    """Upload a media file to R2 and record in database."""
    if file.content_type not in ALLOWED_MIME:
        raise HTTPException(status_code=400, detail=f"Unsupported file type: {file.content_type}")

    data = await file.read()
    if len(data) > MAX_SIZE:
        raise HTTPException(status_code=400, detail="File too large (max 10 MB)")

    now = datetime.utcnow()
    ext = (file.filename or "file").rsplit(".", 1)[-1] if file.filename and "." in file.filename else "bin"
    file_id = _uuid.uuid4()
    r2_key = f"blog-media/{current_user.id}/{now.year}/{now.month:02d}/{file_id}.{ext}"

    if not r2_storage or not r2_storage.client:
        raise HTTPException(status_code=503, detail="Storage not configured")

    try:
        r2_storage.client.put_object(
            Bucket=MEDIA_BUCKET_NAME,
            Key=r2_key,
            Body=data,
            ContentType=file.content_type,
        )
    except Exception as e:
        logger.error("R2 upload failed: %s", e)
        raise HTTPException(status_code=500, detail="Upload failed")

    r2_url = f"{MEDIA_PUBLIC_URL_BASE}/{r2_key}" if MEDIA_PUBLIC_URL_BASE else r2_key

    query = """
        INSERT INTO media_assets (id, filename, r2_key, r2_url, mime_type, file_size_bytes, uploaded_by)
        VALUES (:id, :filename, :r2_key, :r2_url, :mime_type, :size, :uid)
        RETURNING *
    """
    row = await database.fetch_one(query=query, values={
        "id": file_id,
        "filename": file.filename or "unnamed",
        "r2_key": r2_key,
        "r2_url": r2_url,
        "mime_type": file.content_type,
        "size": len(data),
        "uid": current_user.id,
    })
    return row


@router.delete("/blog/media/{media_id}")
async def delete_media(
    media_id: _uuid.UUID,
    current_user: UserResponse = Depends(get_current_user),
):
    row = await database.fetch_one(
        "SELECT * FROM media_assets WHERE id = :id AND uploaded_by = :uid",
        {"id": media_id, "uid": current_user.id},
    )
    if not row:
        raise HTTPException(status_code=404, detail="Media not found")

    # Delete from R2 (media bucket)
    if r2_storage and r2_storage.client:
        try:
            r2_storage.client.delete_object(Bucket=MEDIA_BUCKET_NAME, Key=row["r2_key"])
        except Exception as e:
            logger.warning("R2 delete failed: %s", e)

    await database.execute("DELETE FROM media_assets WHERE id = :id", {"id": media_id})
    return {"status": "success"}
