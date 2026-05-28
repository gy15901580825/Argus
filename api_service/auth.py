import logging
from fastapi import Header, HTTPException, Depends
from typing import Optional
from database import database
from models import UserRole, UserResponse
from b2c_auth import verify_b2c_jwt, is_jwt_token, check_scope, get_user_info_from_token
from uuid import UUID
from datetime import datetime

logger = logging.getLogger("Auth")

async def get_current_user(
    authorization: Optional[str] = Header(None, alias="Authorization"),
    x_api_token: Optional[str] = Header(None, alias="x-api-token")
) -> UserResponse:
    """
    Authenticate user via Bearer Token or x-api-token header.
    Returns the user object if authenticated.
    Raises 401 if no token provided.
    """
    token = None
    
    # 1. Try x-api-token header
    if x_api_token:
        token = x_api_token
    # 2. Try Authorization: Bearer <token>
    elif authorization:
        parts = authorization.split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            token = parts[1]
    
    if not token:
        raise HTTPException(status_code=401, detail="Missing authentication token")

    query = """
        SELECT id, username, email, display_name, avatar, role, is_active, created_at, updated_at
        FROM users 
        WHERE api_token = :token
    """
    try:
        user = await database.fetch_one(query=query, values={"token": token})
        
        if not user:
             raise HTTPException(status_code=401, detail="Invalid token")
             
        if not user["is_active"]:
            raise HTTPException(status_code=403, detail="User account is inactive")
            
        return UserResponse(**user)
        
    except Exception as e:
        logger.error(f"Auth error: {e}")
        # If it's already an HTTP exception, re-raise it
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=500, detail="Authentication failed")

async def get_optional_user(
    authorization: Optional[str] = Header(None, alias="Authorization"),
    x_api_token: Optional[str] = Header(None, alias="x-api-token")
) -> Optional[UserResponse]:
    """
    Optionally authenticate user via Bearer Token or x-api-token header.
    Returns the user object if authenticated, None if no token provided.
    This allows public access to certain endpoints while still supporting authenticated access.
    """
    token = None
    
    # 1. Try x-api-token header
    if x_api_token:
        token = x_api_token
    # 2. Try Authorization: Bearer <token>
    elif authorization:
        parts = authorization.split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            token = parts[1]
    
    if not token:
        return None

    query = """
        SELECT id, username, email, display_name, avatar, role, is_active, created_at, updated_at
        FROM users 
        WHERE api_token = :token
    """
    try:
        user = await database.fetch_one(query=query, values={"token": token})
        
        if not user:
            return None
             
        if not user["is_active"]:
            return None
            
        return UserResponse(**user)
        
    except Exception as e:
        logger.error(f"Auth error: {e}")
        return None

async def require_admin(current_user: UserResponse = Depends(get_current_user)) -> UserResponse:
    """
    Dependency to ensure the user has admin privileges.
    """
    if current_user.role not in [UserRole.SUPER_ADMIN, UserRole.CONTENT_ADMIN]:
        raise HTTPException(status_code=403, detail="Admin privileges required")
    return current_user

async def require_trial_create_permission(current_user: UserResponse = Depends(get_current_user)) -> UserResponse:
    """
    Dependency to ensure the user has permission to create trial tokens.
    Allowed: Admins, 'tester', 'w.lee'
    """
    allowed_users = ["tester", "w.lee"]
    
    # Check if admin
    if current_user.role in [UserRole.SUPER_ADMIN, UserRole.CONTENT_ADMIN]:
        return current_user
        
    # Check if allowed specifically by username
    if current_user.username in allowed_users:
        return current_user
        
    raise HTTPException(status_code=403, detail="Permission denied for trial token creation")

async def get_current_user_dual_auth(
    authorization: Optional[str] = Header(None, alias="Authorization"),
    x_api_token: Optional[str] = Header(None, alias="x-api-token"),
    x_internal_call: Optional[str] = Header(None, alias="x-internal-call"),
    x_user_id: Optional[str] = Header(None, alias="x-user-id"),
) -> tuple[UserResponse, Optional[dict]]:
    """
    Authenticate user via JWT Bearer Token or traditional x-api-token header.
    Supports dual authentication: both JWT from Azure AD B2C and API tokens.
    
    Returns:
        tuple: (UserResponse, Optional[token_payload])
        - UserResponse: The authenticated user
        - Optional[dict]: JWT payload if JWT was used, None if API token was used
    """
    # Internal service call: orchestrator passes x-internal-call + x-user-id
    if x_internal_call and x_internal_call.lower() == "true" and x_user_id:
        query = """
            SELECT id, username, email, display_name, avatar, role, is_active, created_at, updated_at
            FROM users WHERE id = :user_id
        """
        try:
            user = await database.fetch_one(query=query, values={"user_id": x_user_id})
            if user and user["is_active"]:
                logger.info("Internal call authenticated for user %s", x_user_id)
                return UserResponse(**user), None
        except Exception as e:
            logger.error("Internal call auth error: %s", e)
        raise HTTPException(status_code=401, detail="Internal call: user not found or inactive")

    token = None
    token_type = None

    # 1. Try x-api-token header first
    if x_api_token:
        token = x_api_token
        token_type = "api_token"
    # 2. Try Authorization: Bearer <token>
    elif authorization:
        parts = authorization.split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            token = parts[1]
            # Determine if it's a JWT or API token
            if is_jwt_token(token):
                token_type = "jwt"
            else:
                token_type = "api_token"
    
    if not token:
        raise HTTPException(status_code=401, detail="Missing authentication token")
    
    # Handle JWT authentication
    if token_type == "jwt":
        try:
            logger.info(f"Authenticating with JWT token (length: {len(token)}, starts with: {token[:20]}...)")
            jwt_payload = await verify_b2c_jwt(token)
            logger.info(f"JWT verification successful. Payload keys: {list(jwt_payload.keys())}")
            user_info = await get_user_info_from_token(jwt_payload)
            logger.info(f"Extracted user info: id={user_info.get('id')}, username={user_info.get('username')}, email={user_info.get('email')}")
            
            # Try to find user in database by sub (user_id from B2C)
            user_id = user_info.get("id")
            username = user_info.get("username")
            email = user_info.get("email")
            
            if not user_id:
                logger.error(f"JWT missing subject. Payload: {jwt_payload}")
                raise HTTPException(status_code=401, detail="Invalid JWT: missing subject")
            
            # Query user from database
            logger.info(f"Querying database for user: id={user_id}, username={username}, email={email}")
            query = """
                SELECT id, username, email, display_name, avatar, role, is_active, created_at, updated_at
                FROM users 
                WHERE id = :user_id OR username = :username OR email = :email
            """
            user = await database.fetch_one(
                query=query, 
                values={"user_id": user_id, "username": username, "email": email}
            )
            logger.info(f"Database query result: {'Found user' if user else 'User not found'}")
            
            if not user:
                # User doesn't exist in our database, create a minimal user record
                logger.info(f"User not found in database. Creating new user from JWT: {user_id}")
                create_query = """
                    INSERT INTO users (id, username, email, display_name, avatar, role, is_active, created_at, updated_at)
                    VALUES (:user_id, :username, :email, :display_name, :avatar, :role, true, NOW(), NOW())
                    RETURNING id, username, email, display_name, avatar, role, is_active, created_at, updated_at
                """
                try:
                    user = await database.fetch_one(
                        query=create_query,
                        values={
                            "user_id": user_id,
                            "username": username or f"user_{user_id}",
                            "email": email or f"{user_id}@argus.local",
                            "display_name": user_info.get("display_name"),
                            "avatar": user_info.get("avatar"),
                            "role": UserRole.ORDINARY_USER.value
                        }
                    )
                    logger.info(f"Successfully created new user: {user_id}")
                except Exception as db_error:
                    logger.error(f"Failed to create user in database: {db_error}")
                    raise HTTPException(status_code=500, detail=f"Failed to create user: {str(db_error)}")
            
            if not user["is_active"]:
                logger.warning(f"User {user_id} account is inactive")
                raise HTTPException(status_code=403, detail="User account is inactive")
            
            logger.info(f"JWT authentication successful for user: {user['username']} (ID: {user['id']})")
            return UserResponse(**user), jwt_payload
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"JWT authentication error: {type(e).__name__}: {str(e)}", exc_info=True)
            raise HTTPException(status_code=401, detail=f"JWT authentication failed: {str(e)}")
    
    # Handle traditional API token authentication
    else:
        logger.info("Authenticating with API token")
        query = """
            SELECT id, username, email, display_name, avatar, role, is_active, created_at, updated_at
            FROM users 
            WHERE api_token = :token
        """
        try:
            user = await database.fetch_one(query=query, values={"token": token})
            
            if not user:
                raise HTTPException(status_code=401, detail="Invalid API token")
                 
            if not user["is_active"]:
                raise HTTPException(status_code=403, detail="User account is inactive")
                
            return UserResponse(**user), None
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"API token authentication error: {e}")
            raise HTTPException(status_code=500, detail="Authentication failed")

def require_scope(*required_scopes: str):
    """
    Dependency factory to check if user has required scopes.
    For JWT tokens, checks the scopes in the token.
    For API tokens, assumes all permissions (for backward compatibility).
    
    Usage:
        @app.get("/protected")
        async def protected_endpoint(
            auth_data = Depends(require_scope("api:read", "api:write"))
        ):
            user, jwt_payload = auth_data
            ...
    """
    async def check_scopes_dependency(
        auth_data: tuple[UserResponse, Optional[dict]] = Depends(get_current_user_dual_auth)
    ) -> tuple[UserResponse, Optional[dict]]:
        user, jwt_payload = auth_data
        
        # If using API token, allow all operations (backward compatibility)
        if jwt_payload is None:
            logger.info(f"API token used, granting all permissions to user {user.id}")
            return auth_data
        
        # If using JWT, check scopes
        scope_str = jwt_payload.get("scope", "")
        token_scopes = scope_str.split() if isinstance(scope_str, str) else jwt_payload.get("scopes", [])
        
        missing_scopes = [scope for scope in required_scopes if scope not in token_scopes]
        
        if missing_scopes:
            logger.warning(f"User {user.id} missing required scopes: {missing_scopes}")
            raise HTTPException(
                status_code=403,
                detail=f"Missing required permissions: {', '.join(missing_scopes)}"
            )
        
        logger.info(f"User {user.id} has required scopes: {required_scopes}")
        return auth_data
    
    return check_scopes_dependency
