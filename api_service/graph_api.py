"""Microsoft Graph API helper for CIAM user management."""

import os
import logging
import httpx
from typing import Optional

logger = logging.getLogger("GraphAPI")

CIAM_TENANT_ID = os.getenv("CIAM_TENANT_ID", "")
CIAM_BACKEND_CLIENT_ID = os.getenv("CIAM_BACKEND_CLIENT_ID", "")
CIAM_BACKEND_CLIENT_SECRET = os.getenv("CIAM_BACKEND_CLIENT_SECRET", "")

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
TOKEN_URL = f"https://login.microsoftonline.com/{CIAM_TENANT_ID}/oauth2/v2.0/token"

_cached_token: Optional[str] = None
_token_expires_at: float = 0


async def _get_access_token() -> str:
    """Get a Graph API access token using client credentials flow, with simple caching."""
    global _cached_token, _token_expires_at
    import time

    if _cached_token and time.time() < _token_expires_at - 60:
        return _cached_token

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            TOKEN_URL,
            data={
                "grant_type": "client_credentials",
                "client_id": CIAM_BACKEND_CLIENT_ID,
                "client_secret": CIAM_BACKEND_CLIENT_SECRET,
                "scope": "https://graph.microsoft.com/.default",
            },
        )
        resp.raise_for_status()
        data = resp.json()
        _cached_token = data["access_token"]
        _token_expires_at = time.time() + data.get("expires_in", 3600)
        return _cached_token


async def _graph_request(method: str, path: str, json: dict = None) -> httpx.Response:
    """Make an authenticated request to the Graph API."""
    token = await _get_access_token()
    async with httpx.AsyncClient() as client:
        resp = await client.request(
            method,
            f"{GRAPH_BASE}{path}",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json=json,
        )
        return resp


async def get_ciam_user(user_id: str) -> Optional[dict]:
    """Get a CIAM user by ID."""
    resp = await _graph_request("GET", f"/users/{user_id}?$select=id,displayName,mail,accountEnabled")
    if resp.status_code == 200:
        return resp.json()
    if resp.status_code == 404:
        return None
    logger.warning(f"Graph GET user {user_id} failed: {resp.status_code} {resp.text[:200]}")
    return None


async def create_ciam_user(
    display_name: str,
    email: str,
    password: Optional[str] = None,
) -> Optional[dict]:
    """Create a new user in CIAM. Returns the created user dict or None on failure."""
    import secrets

    if not password:
        password = secrets.token_urlsafe(16) + "!A1"  # Meet complexity requirements

    body = {
        "displayName": display_name,
        "identities": [
            {
                "signInType": "emailAddress",
                "issuer": f"{os.getenv('CIAM_TENANT_NAME', 'yourtenant')}.onmicrosoft.com",
                "issuerAssignedId": email,
            }
        ],
        "passwordProfile": {
            "password": password,
            "forceChangePasswordNextSignIn": True,
        },
        "accountEnabled": True,
    }
    resp = await _graph_request("POST", "/users", json=body)
    if resp.status_code == 201:
        user = resp.json()
        logger.info(f"Created CIAM user: {user['id']} ({display_name})")
        return user
    logger.error(f"Graph create user failed: {resp.status_code} {resp.text[:300]}")
    return None


async def update_ciam_user(user_id: str, updates: dict) -> bool:
    """Update a CIAM user. Supported fields: displayName, accountEnabled, mail."""
    body = {}
    if "display_name" in updates:
        body["displayName"] = updates["display_name"]
    if "is_active" in updates:
        body["accountEnabled"] = updates["is_active"]

    if not body:
        return True

    resp = await _graph_request("PATCH", f"/users/{user_id}", json=body)
    if resp.status_code == 204:
        logger.info(f"Updated CIAM user {user_id}: {list(body.keys())}")
        return True
    logger.warning(f"Graph update user {user_id} failed: {resp.status_code} {resp.text[:200]}")
    return False


async def delete_ciam_user(user_id: str) -> bool:
    """Delete a user from CIAM."""
    resp = await _graph_request("DELETE", f"/users/{user_id}")
    if resp.status_code == 204:
        logger.info(f"Deleted CIAM user {user_id}")
        return True
    if resp.status_code == 404:
        logger.info(f"CIAM user {user_id} not found (already deleted)")
        return True
    logger.warning(f"Graph delete user {user_id} failed: {resp.status_code} {resp.text[:200]}")
    return False


async def disable_ciam_user(user_id: str) -> bool:
    """Disable a CIAM user account."""
    return await update_ciam_user(user_id, {"is_active": False})


async def enable_ciam_user(user_id: str) -> bool:
    """Enable a CIAM user account."""
    return await update_ciam_user(user_id, {"is_active": True})
