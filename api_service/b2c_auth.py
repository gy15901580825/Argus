import os
import logging
from typing import Optional, Dict, Any
import jwt
from jwt import PyJWKClient
from fastapi import HTTPException

logger = logging.getLogger("B2CAuth")

# Cache for JWKS client
_jwks_client: Optional[PyJWKClient] = None


def get_ciam_tenant_name() -> str:
    return os.getenv("CIAM_TENANT_NAME", "")


def get_ciam_tenant_id() -> str:
    return os.getenv("CIAM_TENANT_ID", "")


def get_jwks_client() -> PyJWKClient:
    global _jwks_client

    if _jwks_client is None:
        tenant = get_ciam_tenant_name()
        tenant_id = get_ciam_tenant_id()
        # Entra External ID (CIAM) JWKS endpoint
        jwks_url = f"https://{tenant}.ciamlogin.com/{tenant_id}/discovery/v2.0/keys"
        logger.info(f"Initializing JWKS client with URL: {jwks_url}")
        _jwks_client = PyJWKClient(jwks_url)

    return _jwks_client


async def verify_b2c_jwt(token: str) -> Dict[str, Any]:
    """
    Verify an Azure AD B2C JWT token and return its payload.

    Raises:
        HTTPException: If token verification fails
    """
    try:
        jwks_client = get_jwks_client()
        signing_key = jwks_client.get_signing_key_from_jwt(token)

        payload = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            options={
                "verify_signature": True,
                "verify_exp": True,
                "verify_iat": True,
                "verify_aud": False,  # B2C aud varies by app registration
            },
        )

        logger.info(f"Successfully verified JWT for subject: {payload.get('sub')}")
        return payload

    except jwt.ExpiredSignatureError:
        logger.error("JWT token has expired")
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError as e:
        logger.error(f"Invalid JWT token: {e}")
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")
    except Exception as e:
        logger.error(f"JWT verification failed: {e}")
        raise HTTPException(status_code=401, detail=f"Token verification failed: {str(e)}")


def check_scope(required_scope: str, token_payload: Dict[str, Any]) -> bool:
    """Check if token payload contains the required scope."""
    scope_str = token_payload.get("scope", "") or token_payload.get("scp", "")
    scopes = scope_str.split() if isinstance(scope_str, str) else []

    if not scopes and "scopes" in token_payload:
        scopes = token_payload["scopes"]

    return required_scope in scopes


def check_scopes(required_scopes: list[str], token_payload: Dict[str, Any]) -> bool:
    """Check if token payload contains all required scopes."""
    return all(check_scope(scope, token_payload) for scope in required_scopes)


async def get_user_info_from_token(token_payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract user information from B2C JWT token payload.

    B2C claims format:
    - emails: array (not string) -> use emails[0]
    - sub/oid: user identifier
    - name / given_name / family_name: display name
    - No owner/organization fields
    """
    # B2C uses "emails" (array) instead of "email" (string)
    emails = token_payload.get("emails", [])
    email = emails[0] if emails else token_payload.get("email")

    user_info = {
        "id": token_payload.get("sub") or token_payload.get("oid"),
        "username": token_payload.get("name") or token_payload.get("preferred_username") or token_payload.get("sub"),
        "email": email,
        "display_name": token_payload.get("name"),
        "avatar": None,  # B2C doesn't provide avatar in standard claims
        "scopes": (token_payload.get("scope", "") or token_payload.get("scp", "")).split() if isinstance(token_payload.get("scope", token_payload.get("scp")), str) else [],
        "token_type": "jwt",
    }

    return user_info


def is_jwt_token(token: str) -> bool:
    """Check if a token string is a JWT token (has 3 parts separated by dots)."""
    return token.count('.') == 2
