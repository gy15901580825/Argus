import logging
from typing import List
from uuid import UUID
from fastapi import APIRouter, HTTPException, Depends
from database import database
from models import ScriptCreate, ScriptUpdate, ScriptResponse, UserResponse
from auth import get_current_user

router = APIRouter()
logger = logging.getLogger("ScriptsRouter")

@router.post("/scripts", response_model=ScriptResponse)
async def create_script(
    script: ScriptCreate,
    current_user: UserResponse = Depends(get_current_user)
):
    """
    Create a new script record.
    """
    query = """
        INSERT INTO scripts (name, script_address, description, owner_id, version)
        VALUES (:name, :script_address, :description, :owner_id, :version)
        RETURNING id, name, script_address, description, owner_id, version, created_at, updated_at
    """
    
    try:
        result = await database.fetch_one(
            query=query,
            values={
                "name": script.name,
                "script_address": script.script_address,
                "description": script.description,
                "owner_id": current_user.id,
                "version": script.version
            }
        )
        
        return ScriptResponse(
            id=result["id"],
            name=result["name"],
            script_address=result["script_address"],
            description=result["description"],
            owner_id=result["owner_id"],
            version=result["version"],
            created_at=result["created_at"],
            updated_at=result["updated_at"],
            owner_name=current_user.username
        )
    except Exception as e:
        logger.error(f"Error creating script: {e}")
        raise HTTPException(status_code=500, detail="Failed to create script")


@router.get("/scripts", response_model=List[ScriptResponse])
async def list_scripts(
    current_user: UserResponse = Depends(get_current_user)
):
    """
    List all scripts for the current user.
    """
    query = """
        SELECT 
            s.id, s.name, s.script_address, s.description, s.owner_id, s.version, 
            s.created_at, s.updated_at,
            u.username as owner_name
        FROM scripts s
        LEFT JOIN users u ON s.owner_id = u.id
        WHERE s.owner_id = :user_id
        ORDER BY s.created_at DESC
    """
    
    try:
        results = await database.fetch_all(
            query=query,
            values={"user_id": current_user.id}
        )
        
        return [
            ScriptResponse(
                id=row["id"],
                name=row["name"],
                script_address=row["script_address"],
                description=row["description"],
                owner_id=row["owner_id"],
                version=row["version"],
                created_at=row["created_at"],
                updated_at=row["updated_at"],
                owner_name=row["owner_name"]
            )
            for row in results
        ]
    except Exception as e:
        logger.error(f"Error listing scripts: {e}")
        raise HTTPException(status_code=500, detail="Failed to list scripts")


@router.get("/scripts/{script_id}", response_model=ScriptResponse)
async def get_script(
    script_id: UUID,
    current_user: UserResponse = Depends(get_current_user)
):
    """
    Get a specific script by ID.
    """
    query = """
        SELECT 
            s.id, s.name, s.script_address, s.description, s.owner_id, s.version,
            s.created_at, s.updated_at,
            u.username as owner_name
        FROM scripts s
        LEFT JOIN users u ON s.owner_id = u.id
        WHERE s.id = :script_id AND s.owner_id = :user_id
    """
    
    try:
        result = await database.fetch_one(
            query=query,
            values={"script_id": script_id, "user_id": current_user.id}
        )
        
        if not result:
            raise HTTPException(status_code=404, detail="Script not found")
        
        return ScriptResponse(
            id=result["id"],
            name=result["name"],
            script_address=result["script_address"],
            description=result["description"],
            owner_id=result["owner_id"],
            version=result["version"],
            created_at=result["created_at"],
            updated_at=result["updated_at"],
            owner_name=result["owner_name"]
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting script: {e}")
        raise HTTPException(status_code=500, detail="Failed to get script")


@router.put("/scripts/{script_id}", response_model=ScriptResponse)
async def update_script(
    script_id: UUID,
    script_update: ScriptUpdate,
    current_user: UserResponse = Depends(get_current_user)
):
    """
    Update a script.
    """
    # Check ownership
    check_query = "SELECT id FROM scripts WHERE id = :script_id AND owner_id = :user_id"
    existing = await database.fetch_one(
        query=check_query,
        values={"script_id": script_id, "user_id": current_user.id}
    )
    
    if not existing:
        raise HTTPException(status_code=404, detail="Script not found")
    
    # Build update query dynamically
    update_fields = []
    values = {"script_id": script_id, "user_id": current_user.id}
    
    if script_update.name is not None:
        update_fields.append("name = :name")
        values["name"] = script_update.name
    if script_update.script_address is not None:
        update_fields.append("script_address = :script_address")
        values["script_address"] = script_update.script_address
    if script_update.description is not None:
        update_fields.append("description = :description")
        values["description"] = script_update.description
    if script_update.version is not None:
        update_fields.append("version = :version")
        values["version"] = script_update.version
    
    if not update_fields:
        raise HTTPException(status_code=400, detail="No fields to update")
    
    query = f"""
        UPDATE scripts
        SET {", ".join(update_fields)}
        WHERE id = :script_id AND owner_id = :user_id
        RETURNING id, name, script_address, description, owner_id, version, created_at, updated_at
    """
    
    try:
        result = await database.fetch_one(query=query, values=values)
        
        return ScriptResponse(
            id=result["id"],
            name=result["name"],
            script_address=result["script_address"],
            description=result["description"],
            owner_id=result["owner_id"],
            version=result["version"],
            created_at=result["created_at"],
            updated_at=result["updated_at"],
            owner_name=current_user.username
        )
    except Exception as e:
        logger.error(f"Error updating script: {e}")
        raise HTTPException(status_code=500, detail="Failed to update script")


@router.delete("/scripts/{script_id}")
async def delete_script(
    script_id: UUID,
    current_user: UserResponse = Depends(get_current_user)
):
    """
    Delete a script.
    """
    query = "DELETE FROM scripts WHERE id = :script_id AND owner_id = :user_id RETURNING id"
    
    try:
        result = await database.fetch_one(
            query=query,
            values={"script_id": script_id, "user_id": current_user.id}
        )
        
        if not result:
            raise HTTPException(status_code=404, detail="Script not found")
        
        return {"message": "Script deleted successfully", "id": str(result["id"])}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting script: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete script")

