import asyncio
import json
import logging
import argparse
import sys
import os
import httpx
import websockets
from typing import Optional
from datetime import datetime, timedelta

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("ClientAgent")

# --- OAuth Client Logic ---

class OAuthClient:
    """
    OAuth client that authenticates via API Service proxy.
    Only requires username and password - client_secret stays secure on server.
    """
    def __init__(self, api_service_url: str, username: str, password: str):
        self.api_service_url = api_service_url
        self.username = username
        self.password = password
        self.access_token: Optional[str] = None
        self.refresh_token: Optional[str] = None
        self.token_expires_at: Optional[datetime] = None
        self.refresh_buffer_seconds = 300  # Refresh token 5 minutes before expiry
        
    async def get_access_token(self) -> str:
        """
        Get a valid access token. Requests a new one if expired or doesn't exist.
        """
        # Check if we have a valid token
        if self.access_token and self.token_expires_at:
            # Add buffer time to prevent using expired tokens
            if datetime.now() < (self.token_expires_at - timedelta(seconds=self.refresh_buffer_seconds)):
                logger.debug("Using cached access token")
                return self.access_token
            else:
                logger.info("Access token expired or expiring soon, requesting new token")
        
        # Request new token
        await self.request_token()
        return self.access_token
    
    async def request_token(self) -> dict:
        """
        Request a new access token via API Service proxy.
        API Service handles the OAuth flow, keeping client_secret secure.
        """
        # Ensure api_service_url ends with /api/v1 or /api/v1/
        base_url = self.api_service_url.rstrip('/')
        if not base_url.endswith('/api/v1'):
            base_url = f"{base_url}/api/v1"
        login_url = f"{base_url}/auth/login"
        
        payload = {
            "username": self.username,
            "password": self.password
        }
        
        logger.info(f"Requesting access token via API Service (username: {self.username})")
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                response = await client.post(
                    login_url,
                    json=payload,
                    headers={"Content-Type": "application/json"}
                )
                response.raise_for_status()
                token_data = response.json()
                
                # Extract token and expiry
                self.access_token = token_data.get("access_token")
                self.refresh_token = token_data.get("refresh_token")
                expires_in = token_data.get("expires_in", 3600)  # Default 1 hour
                
                if not self.access_token:
                    raise Exception("No access_token in response")
                
                # Calculate expiry time
                self.token_expires_at = datetime.now() + timedelta(seconds=expires_in)
                
                logger.info(f"Successfully obtained access token (expires in {expires_in}s)")
                return token_data
                
            except httpx.HTTPStatusError as e:
                logger.error(f"HTTP error requesting token: {e.response.status_code} - {e.response.text}")
                raise Exception(f"Failed to obtain access token: {e.response.status_code}")
            except Exception as e:
                logger.error(f"Error requesting token: {e}")
                raise
    
    def get_seconds_until_expiry(self) -> Optional[float]:
        """
        Get the number of seconds until the token expires.
        Returns None if no token or expiry time is set.
        """
        if not self.token_expires_at:
            return None
        delta = self.token_expires_at - datetime.now()
        return max(0, delta.total_seconds())

# --- Agent Logic ---

class ClientAgent:
    def __init__(self, orchestrator_url: str, api_service_url: Optional[str] = None,
                 agent_name: str = "default-client-agent",
                 username: Optional[str] = None,
                 password: Optional[str] = None,
                 api_token: Optional[str] = None,
                 agent_secret: Optional[str] = None):
        """
        Initialize Client Agent with either username/password or API token.
        
        SECURE: Client credentials (client_id/client_secret) are kept on API Service.
        Client Agent only needs username and password.
        
        Args:
            orchestrator_url: WebSocket URL of the orchestrator
            api_service_url: HTTP URL of a server to register with first. None means
                direct mode: connect to the orchestrator with agent_name as the agent id.
            agent_name: Unique name for this agent
            username: username (user credential)
            password: password (user credential)
            api_token: Traditional API token (fallback if OAuth not configured)
            agent_secret: Shared secret sent as x-agent-secret when the orchestrator
                sets AGENT_CONNECT_SECRET
        """
        self.orchestrator_url = orchestrator_url
        self.api_service_url = api_service_url
        self.agent_name = agent_name
        self.agent_id: Optional[str] = None
        self.agent_secret = agent_secret
        self.running = False
        
        # OAuth client (preferred) - authenticates via API Service proxy
        self.oauth_client: Optional[OAuthClient] = None
        self.api_token: Optional[str] = None
        if api_service_url is None:
            # Direct mode: no server to register with, so no credentials are used.
            return
        self.api_token = api_token
        if username and password:
            logger.info(f"Initializing with authentication via API Service (user: {username})")
            self.oauth_client = OAuthClient(
                api_service_url,
                username,
                password
            )
        
        if not self.oauth_client and not self.api_token:
            raise ValueError("Either credentials (username/password) or API token must be provided")

    async def register(self):
        """Register agent with API Service"""
        logger.info(f"Registering agent {self.agent_name} with API Service at {self.api_service_url}...")
        
        # Prepare headers
        headers = {}
        
        # Use OAuth token if available, otherwise fall back to API token
        if self.oauth_client:
            try:
                jwt_token = await self.oauth_client.get_access_token()
                headers["Authorization"] = f"Bearer {jwt_token}"
                logger.info(f"Using OAuth JWT token for registration (token starts with: {jwt_token[:20]}...)")
            except Exception as e:
                logger.error(f"Failed to get OAuth token: {e}")
                if not self.api_token:
                    raise
                logger.warning("Falling back to API token")
                headers["x-api-token"] = self.api_token
        elif self.api_token:
            headers["x-api-token"] = self.api_token
            logger.info("Using API token for registration")
        
        # Ensure api_service_url ends with /api/v1 or /api/v1/
        base_url = self.api_service_url.rstrip('/')
        if not base_url.endswith('/api/v1'):
            base_url = f"{base_url}/api/v1"
        register_url = f"{base_url}/agent/register"
        
        logger.info(f"Registration URL: {register_url}")
        logger.info(f"Request headers: {list(headers.keys())}")
        
        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(
                    register_url,
                    headers=headers,
                    json={
                        "agent_name": self.agent_name,
                        "agent_type": "web_fetcher",
                        "status": "active",
                        "description": "Client agent for fetching web content"
                    }
                )
                response.raise_for_status()
                data = response.json()
                self.agent_id = data.get("agent_id")
                logger.info(f"Registered successfully. Agent ID: {self.agent_id}")
            except httpx.HTTPStatusError as e:
                error_detail = "Unknown error"
                try:
                    error_response = e.response.json()
                    error_detail = error_response.get("detail", e.response.text)
                except:
                    error_detail = e.response.text
                
                logger.error(f"Registration failed with {e.response.status_code}")
                logger.error(f"Error detail: {error_detail}")
                logger.error(f"Response headers: {dict(e.response.headers)}")
                raise Exception(f"Registration failed ({e.response.status_code}): {error_detail}")
            except Exception as e:
                logger.error(f"Registration failed: {e}")
                raise

    def connect_headers(self) -> dict:
        """Headers for /agent/connect: the agent id, plus the shared secret when set."""
        headers = {"x-agent-id": self.agent_id or "unknown"}
        if self.agent_secret:
            headers["x-agent-secret"] = self.agent_secret
        return headers

    async def connect_orchestrator(self):
        """Connect to Orchestrator WebSocket and handle messages"""
        # Ensure orchestrator_url doesn't have trailing slash
        base_url = self.orchestrator_url.rstrip('/')
        uri = f"{base_url}/agent/connect"
        headers = self.connect_headers()
        
        while self.running:
            try:
                logger.info(f"Connecting to Orchestrator at {uri}...")
                async with websockets.connect(
                    uri,
                    additional_headers=headers,
                    ping_interval=None,  # use application-level keepalive instead
                    ping_timeout=None,
                ) as websocket:
                    logger.info("Connected to Orchestrator")

                    async def _keepalive():
                        """Send a JSON-RPC ping every 30 s to keep the connection
                        alive through load-balancers and NAT tables while
                        a red-team browser probe is running."""
                        ka_id = 0
                        while True:
                            await asyncio.sleep(30)
                            ka_id += 1
                            try:
                                await websocket.send(json.dumps({
                                    "jsonrpc": "2.0",
                                    "method": "ping",
                                    "id": f"ka-{ka_id}",
                                }))
                                logger.debug("Keepalive ping sent (%d)", ka_id)
                            except Exception:
                                break  # websocket closed — stop quietly

                    keepalive_task = asyncio.create_task(_keepalive())
                    try:
                        async for message in websocket:
                            try:
                                data = json.loads(message)
                                logger.info("=" * 80)
                                logger.info("📥 RECEIVED REQUEST FROM ORCHESTRATOR")
                                logger.info(f"Full message: {json.dumps(data, indent=2)}")
                                logger.info("=" * 80)

                                # Handle JSON-RPC Request
                                if "method" in data:
                                    method = data["method"]
                                    params = data.get("params", {})
                                    msg_id = data.get("id")

                                    logger.info(f"🔧 Processing method: {method}")
                                    logger.info(f"📦 Parameters: {json.dumps(params, indent=2)}")

                                    if method == "redteam_browser_probe":
                                        from redteam_runner.browser_probe import BrowserProbe
                                        result = await BrowserProbe().run(params)
                                    elif method == "ping":
                                        result = "pong"
                                    else:
                                        logger.warning(f"⚠️  Unknown method: {method}")
                                        result = {"error": f"Unknown method: {method}"}

                                    # Send Response
                                    response = {
                                        "jsonrpc": "2.0",
                                        "result": result,
                                        "id": msg_id
                                    }
                                    logger.info("=" * 80)
                                    logger.info("📤 SENDING RESPONSE TO ORCHESTRATOR")
                                    logger.info(f"Full response: {json.dumps(response, indent=2)}")
                                    logger.info("=" * 80)
                                    await websocket.send(json.dumps(response))

                                elif "result" in data:
                                    # Response to our keepalive ping — ignore
                                    pass

                            except json.JSONDecodeError:
                                logger.error("Failed to decode JSON message")
                            except Exception as e:
                                logger.error(f"Error processing message: {e}")
                    finally:
                        keepalive_task.cancel()

            except Exception as e:
                logger.error(f"Connection lost or failed: {e}")
                logger.info("Reconnecting in 5 seconds...")
                await asyncio.sleep(5)

    async def token_refresh_task(self):
        """
        Background task to refresh OAuth token before it expires.
        Only runs if OAuth is enabled.
        """
        if not self.oauth_client:
            return
        
        logger.info("Starting token refresh background task")
        
        while self.running:
            try:
                # Get current token (this will refresh if needed)
                await self.oauth_client.get_access_token()

                # Calculate when to refresh next
                # Refresh at 80% of token lifetime or at least every 5 minutes
                seconds_until_expiry = self.oauth_client.get_seconds_until_expiry()
                if seconds_until_expiry:
                    # Refresh at 80% of lifetime, but at least check every 5 minutes
                    refresh_interval = min(
                        max(seconds_until_expiry * 0.8, 60),  # At least 1 minute
                        300  # At most 5 minutes
                    )
                else:
                    # Default to checking every 5 minutes if we don't know expiry
                    refresh_interval = 300
                
                logger.info(f"Token valid, next refresh check in {refresh_interval:.0f} seconds")
                await asyncio.sleep(refresh_interval)
                
            except Exception as e:
                logger.error(f"Token refresh failed: {e}")
                # Retry after 30 seconds on error
                await asyncio.sleep(30)
    
    async def run(self):
        self.running = True
        if self.api_service_url:
            await self.register()
        else:
            self.agent_id = self.agent_name

        # Start token refresh task in background if using OAuth
        refresh_task = None
        if self.oauth_client:
            refresh_task = asyncio.create_task(self.token_refresh_task())
        
        try:
            await self.connect_orchestrator()
        finally:
            # Cancel refresh task when done
            if refresh_task:
                refresh_task.cancel()
                try:
                    await refresh_task
                except asyncio.CancelledError:
                    pass

def build_agent(argv: Optional[list] = None) -> "ClientAgent":
    parser = argparse.ArgumentParser(description="Argus Client Agent - Secure Public Client")
    parser.add_argument("--orchestrator-url", required=True, help="Orchestrator WebSocket URL, e.g. ws://localhost:8080")
    parser.add_argument("--api-service-url", default=None,
                        help="Server to register with before connecting. Omit to connect directly, "
                             "using --agent-name as the agent id.")
    parser.add_argument("--agent-name", default="default-client-agent", help="Unique name for this agent")
    parser.add_argument("--agent-secret", default=os.getenv("AGENT_CONNECT_SECRET"),
                        help="Shared secret matching the orchestrator's AGENT_CONNECT_SECRET. "
                             "Prefer the AGENT_CONNECT_SECRET env var: argv is visible in ps.")

    # authentication (SECURE: only username/password, client_secret stays on server)
    parser.add_argument("--username", help="username (with --api-service-url)")
    parser.add_argument("--password", default=os.getenv("AGENT_PASSWORD"),
                        help="password (with --api-service-url). Prefer env AGENT_PASSWORD: argv is visible in ps.")

    # API token authentication (fallback)
    parser.add_argument("--api-token", default=os.getenv("AGENT_API_TOKEN"),
                        help="API Token for authentication (with --api-service-url). "
                             "Prefer env AGENT_API_TOKEN: argv is visible in ps.")

    args = parser.parse_args(argv)

    has_credentials = args.username and args.password
    if args.api_service_url and not has_credentials and not args.api_token:
        parser.error("--api-service-url needs credentials (--username/--password) or --api-token")
    ignored = [f for f, v in (("--username", args.username), ("--password", args.password),
                              ("--api-token", args.api_token)) if v]
    if not args.api_service_url and ignored:
        print(f"warning: {', '.join(ignored)} ignored without --api-service-url", file=sys.stderr)

    return ClientAgent(
        orchestrator_url=args.orchestrator_url,
        api_service_url=args.api_service_url,
        agent_name=args.agent_name,
        username=args.username,
        password=args.password,
        api_token=args.api_token,
        agent_secret=args.agent_secret,
    )


if __name__ == "__main__":
    agent = build_agent()

    try:
        asyncio.run(agent.run())
    except KeyboardInterrupt:
        logger.info("Agent stopped by user")
