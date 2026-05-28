from fastapi import APIRouter, Depends, HTTPException, Query
from typing import List, Optional
from uuid import UUID
from datetime import datetime

from database import database
from auth import get_current_user, get_optional_user, require_admin
from models import (
    UserResponse,
    DocumentCreate, DocumentUpdate, DocumentResponse
)

router = APIRouter()

@router.get("/documents", response_model=List[DocumentResponse])
async def list_documents(
    limit: int = 10, 
    offset: int = 0,
    include_unpublished: bool = False,
    current_user: Optional[UserResponse] = Depends(get_optional_user)
):
    """
    List documents.
    """
    show_unpublished = False
    if include_unpublished:
        if current_user and current_user.role in ["SUPER_ADMIN", "CONTENT_ADMIN"]:
            show_unpublished = True
            
    query = """
        SELECT d.*, u.display_name as owner_name
        FROM documents d
        JOIN users u ON d.owner_id = u.id
    """
    
    if not show_unpublished:
        query += " WHERE d.is_published = TRUE"
        
    query += " ORDER BY d.created_at DESC LIMIT :limit OFFSET :offset"
    
    return await database.fetch_all(query=query, values={"limit": limit, "offset": offset})

@router.get("/documents/{id}", response_model=DocumentResponse)
async def get_document(id: UUID):
    """
    Get document details.
    """
    query = """
        SELECT d.*, u.display_name as owner_name
        FROM documents d
        JOIN users u ON d.owner_id = u.id
        WHERE d.id = :id
    """
    doc = await database.fetch_one(query=query, values={"id": id})
    
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")
        
    return doc

@router.post("/documents", response_model=DocumentResponse)
async def create_document(
    doc: DocumentCreate,
    current_user: UserResponse = Depends(require_admin)
):
    """
    Create a document (Admin only).
    """
    published_at = datetime.now() if doc.is_published else None
    
    query = """
        INSERT INTO documents (title, description, content, owner_id, is_published, published_at)
        VALUES (:title, :description, :content, :owner_id, :is_published, :published_at)
        RETURNING id, title, description, content, owner_id, is_published, published_at, created_at, updated_at
    """
    values = {
        "title": doc.title,
        "description": doc.description,
        "content": doc.content,
        "owner_id": current_user.id,
        "is_published": doc.is_published,
        "published_at": published_at
    }
    
    try:
        new_doc = await database.fetch_one(query=query, values=values)
        return {**new_doc, "owner_name": current_user.display_name}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.put("/documents/{id}", response_model=DocumentResponse)
async def update_document(
    id: UUID,
    doc_update: DocumentUpdate,
    current_user: UserResponse = Depends(require_admin)
):
    """
    Update a document (Admin only).
    """
    check_query = "SELECT * FROM documents WHERE id = :id"
    existing_doc = await database.fetch_one(query=check_query, values={"id": id})
    if not existing_doc:
        raise HTTPException(status_code=404, detail="Document not found")
        
    update_fields = []
    values = {"id": id}
    
    if doc_update.title is not None:
        update_fields.append("title = :title")
        values["title"] = doc_update.title
    if doc_update.description is not None:
        update_fields.append("description = :description")
        values["description"] = doc_update.description
    if doc_update.content is not None:
        update_fields.append("content = :content")
        values["content"] = doc_update.content
    if doc_update.is_published is not None:
        update_fields.append("is_published = :is_published")
        values["is_published"] = doc_update.is_published
        
        if doc_update.is_published and not existing_doc["is_published"]:
             update_fields.append("published_at = NOW()")
        elif doc_update.is_published is False:
             update_fields.append("published_at = NULL")
             
    if not update_fields:
        return {**existing_doc, "owner_name": current_user.display_name} # Assuming owner didn't change
        
    query = f"""
        UPDATE documents 
        SET {", ".join(update_fields)}
        WHERE id = :id
        RETURNING id, title, description, content, owner_id, is_published, published_at, created_at, updated_at
    """
    
    updated_doc = await database.fetch_one(query=query, values=values)
    
    owner_query = "SELECT display_name FROM users WHERE id = :id"
    owner = await database.fetch_one(query=owner_query, values={"id": updated_doc["owner_id"]})
    
    return {**updated_doc, "owner_name": owner["display_name"] if owner else None}

@router.delete("/documents/{id}")
async def delete_document(
    id: UUID,
    current_user: UserResponse = Depends(require_admin)
):
    """
    Delete a document (Admin only).
    """
    check = await database.fetch_one("SELECT id FROM documents WHERE id = :id", {"id": id})
    if not check:
        raise HTTPException(status_code=404, detail="Document not found")
        
    await database.execute("DELETE FROM documents WHERE id = :id", {"id": id})
    return {"status": "success", "message": "Document deleted"}
