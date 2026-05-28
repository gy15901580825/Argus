import asyncio
import json
import logging
import argparse
import sys
import os
import httpx
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import websockets
from typing import Dict, Any, Optional
from datetime import datetime, timedelta

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("ClientAgent")

# ---------------------------------------------------------------------------
# Optional Web UI testing support (requires browser-use + playwright)
# ---------------------------------------------------------------------------
_WEB_UI_ENABLED = False
try:
    import web_ui_runner  # local module
    _WEB_UI_ENABLED = True
    logger.info("Web UI testing support enabled (browser-use + playwright available)")
except ImportError:
    logger.info("Web UI testing support not available (install browser-use + playwright to enable)")

# --- Web Fetch Logic (Copied/Adapted from testing_web_fetch_service) ---

async def _probe_openapi(client: httpx.AsyncClient, base_url: str, extracted_links: list[str]) -> dict | None:
    """
    Attempt to discover and fetch OpenAPI/Swagger specification.
    """
    common_paths = [
        "/v2/swagger.json",
        "/v3/api-docs",
        "/api/docs",
        "/swagger/v1/swagger.json",
        "/openapi.json",
        "/api/v3/openapi.json",
        "/swagger.json"
    ]
    
    candidate_urls = []
    
    # Check extracted links for API spec patterns
    for link in extracted_links:
        path = urlparse(link).path
        if path.endswith(('.json', '.yaml', '.yml')) and ('swagger' in path or 'api' in path or 'openapi' in path):
            candidate_urls.append(link)
            
    # Add common paths
    for path in common_paths:
        candidate_urls.append(urljoin(base_url, path))
        
    candidate_urls = list(set(candidate_urls))
    
    # Try fetching each candidate URL
    for url in candidate_urls:
        try:
            response = await client.get(url, timeout=5.0)
            if response.status_code == 200:
                try:
                    data = response.json()
                    if "openapi" in data or "swagger" in data:
                        return {"url": url, "spec": data}
                except json.JSONDecodeError:
                    continue
        except Exception:
            continue
            
    return None

async def fetch_url_impl(url: str, cookie: Optional[str] = None, token: Optional[str] = None) -> str:
    """
    Fetch and analyze web page structure.
    """
    headers = {
        "User-Agent": "AT-Helper-Client-Agent/1.0"
    }
    
    # Add cookie if provided
    if cookie:
        headers["Cookie"] = cookie
        logger.info("🍪 Using provided cookie for authentication")
        
    # Add token if provided
    if token:
        headers["Authorization"] = f"Bearer {token}"
        logger.info("🔑 Using provided token for authentication")
    
    result = {
        "text": "",
        "links": [],
        "scripts": [],
        "api_spec": None,
        "metadata": {}
    }

    async with httpx.AsyncClient(verify=False, follow_redirects=True) as client:
        try:
            response = await client.get(url, headers=headers, timeout=30.0)
            result["metadata"]["status_code"] = response.status_code
            result["metadata"]["url"] = str(response.url)
            
            if response.status_code >= 400:
                return json.dumps(result, ensure_ascii=False)

            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract metadata
            if soup.title:
                result["metadata"]["title"] = soup.title.string
            
            # Extract links
            links = set()
            for a in soup.find_all('a', href=True):
                full_url = urljoin(str(response.url), a['href'])
                links.add(full_url)
            result["links"] = list(links)
            
            # Extract scripts
            scripts = set()
            for script in soup.find_all('script', src=True):
                full_url = urljoin(str(response.url), script['src'])
                scripts.add(full_url)
            result["scripts"] = list(scripts)
            
            # Clean text content
            for tag in soup(["script", "style"]):
                tag.decompose()
            
            text = soup.get_text()
            lines = (line.strip() for line in text.splitlines())
            chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
            result["text"] = '\n'.join(chunk for chunk in chunks if chunk)
            
            # Probe for OpenAPI spec
            try:
                data = response.json()
                if isinstance(data, dict) and ("openapi" in data or "swagger" in data):
                    result["api_spec"] = {"url": str(response.url), "spec": data}
                    result["text"] = "Fetched content is a JSON API Specification."
            except json.JSONDecodeError:
                # If not JSON, try to find linked spec
                spec_found = await _probe_openapi(client, str(response.url), result["links"])
                if spec_found:
                    result["api_spec"] = spec_found

        except Exception as e:
            result["error"] = str(e)
            
    return json.dumps(result, ensure_ascii=False, indent=2)

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
        
        async with httpx.AsyncClient(verify=False, timeout=30.0) as client:
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
    def __init__(self, orchestrator_url: str, api_service_url: str, agent_name: str,
                 username: Optional[str] = None,
                 password: Optional[str] = None,
                 api_token: Optional[str] = None):
        """
        Initialize Client Agent with either username/password or API token.
        
        SECURE: Client credentials (client_id/client_secret) are kept on API Service.
        Client Agent only needs username and password.
        
        Args:
            orchestrator_url: WebSocket URL of the orchestrator
            api_service_url: HTTP URL of the API service
            agent_name: Unique name for this agent
            username: username (user credential)
            password: password (user credential)
            api_token: Traditional API token (fallback if OAuth not configured)
        """
        self.orchestrator_url = orchestrator_url
        self.api_service_url = api_service_url
        self.agent_name = agent_name
        self.agent_id: Optional[str] = None
        self.running = False
        
        # OAuth client (preferred) - authenticates via API Service proxy
        self.oauth_client: Optional[OAuthClient] = None
        if username and password:
            logger.info(f"Initializing with authentication via API Service (user: {username})")
            self.oauth_client = OAuthClient(
                api_service_url,
                username,
                password
            )
        
        # Fallback API token
        self.api_token = api_token
        
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
                if _WEB_UI_ENABLED:
                    web_ui_runner.set_api_credentials(self.api_service_url, jwt_token)
            except Exception as e:
                logger.error(f"Failed to get OAuth token: {e}")
                if not self.api_token:
                    raise
                logger.warning("Falling back to API token")
                headers["x-api-token"] = self.api_token
        elif self.api_token:
            headers["x-api-token"] = self.api_token
            logger.info("Using API token for registration")
            if _WEB_UI_ENABLED:
                web_ui_runner.set_api_credentials(self.api_service_url, self.api_token)
        
        # Ensure api_service_url ends with /api/v1 or /api/v1/
        base_url = self.api_service_url.rstrip('/')
        if not base_url.endswith('/api/v1'):
            base_url = f"{base_url}/api/v1"
        register_url = f"{base_url}/agent/register"
        
        logger.info(f"Registration URL: {register_url}")
        logger.info(f"Request headers: {list(headers.keys())}")
        
        async with httpx.AsyncClient(verify=False) as client:
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

    async def handle_tool_call(self, name: str, arguments: Dict[str, Any]) -> Any:
        logger.info(f"⚙️  Executing tool: {name}")
        logger.info(f"📥 Input arguments: {json.dumps(arguments, indent=2)}")

        # ----------------------------------------------------------------
        # fetch_url — existing web crawl tool
        # ----------------------------------------------------------------
        if name == "fetch_url":
            url = arguments.get("url")
            if not url:
                error_result = {"error": "Missing url argument"}
                logger.error(f"❌ Tool execution failed: {error_result}")
                return error_result

            cookie = arguments.get("cookie") or arguments.get("cookies")
            token = arguments.get("token")

            logger.info(f"🌐 Fetching URL: {url}")
            result = await fetch_url_impl(url, cookie, token)
            logger.info(f"✅ Tool execution completed, result size: {len(str(result))} chars")
            return result

        # ----------------------------------------------------------------
        # Web UI testing tools (only available when browser-use is installed)
        # ----------------------------------------------------------------
        elif name == "start_web_ui_test":
            if not _WEB_UI_ENABLED:
                return {"error": "Web UI testing not available on this agent (browser-use not installed)"}

            url = arguments.get("url")
            if not url:
                return {"error": "Missing 'url' argument"}

            result = web_ui_runner.start_web_ui_test(
                url=url,
                cdp_url=arguments.get("cdp_url"),
                max_steps=int(arguments.get("max_steps", 100)),
                llm_model=arguments.get("llm_model"),
                script_model=arguments.get("script_model"),
                credentials=arguments.get("credentials"),
                business_context=arguments.get("business_context"),
                user_persona=arguments.get("user_persona", "new_user"),
            )
            logger.info(f"🚀 Web UI test started: task_id={result.get('task_id')}")
            return result

        elif name == "get_web_ui_test_status":
            if not _WEB_UI_ENABLED:
                return {"error": "Web UI testing not available on this agent"}
            task_id = arguments.get("task_id")
            if not task_id:
                return {"error": "Missing 'task_id' argument"}
            return web_ui_runner.get_web_ui_test_status(task_id)

        elif name == "get_web_ui_test_result":
            if not _WEB_UI_ENABLED:
                return {"error": "Web UI testing not available on this agent"}
            task_id = arguments.get("task_id")
            if not task_id:
                return {"error": "Missing 'task_id' argument"}
            result = web_ui_runner.get_web_ui_test_result(task_id)
            logger.info(
                f"📦 Returning web UI result for task {task_id}, "
                f"script size: {len(result.get('test_script') or '')} chars"
            )
            return result

        elif name == "cancel_web_ui_test":
            if not _WEB_UI_ENABLED:
                return {"error": "Web UI testing not available on this agent"}
            task_id = arguments.get("task_id")
            if not task_id:
                return {"error": "Missing 'task_id' argument"}
            result = web_ui_runner.cancel_web_ui_test(task_id)
            logger.info(f"🛑 Cancel requested for task {task_id}: {result}")
            return result

        else:
            error_result = {"error": f"Unknown tool: {name}"}
            logger.error(f"❌ Unknown tool requested: {name}")
            return error_result

    async def handle_tools_list(self, params: dict) -> list:
        """Return list of available tools, including web UI tools when enabled."""
        tools = [
            {
                "name": "fetch_url",
                "description": (
                    "Fetch and analyze content from ANY URL including private network addresses "
                    "(192.168.x.x, 10.x.x.x, localhost). Runs in the user's local environment "
                    "and can access private/internal URLs that cloud services cannot reach."
                ),
                "parameters": {
                    "url": {"type": "string", "description": "The URL to fetch", "required": True},
                    "cookie": {"type": "string", "description": "Optional cookie string", "required": False},
                    "token": {"type": "string", "description": "Optional Bearer token", "required": False},
                },
            }
        ]

        if _WEB_UI_ENABLED:
            tools += [
                {
                    "name": "start_web_ui_test",
                    "description": (
                        "Start a browser-based web UI exploration and test generation task on the "
                        "user's local machine. Connects to a Chrome instance via CDP for intranet "
                        "access. Returns immediately with a task_id — poll status with "
                        "get_web_ui_test_status."
                    ),
                    "parameters": {
                        "url": {"type": "string", "description": "Target URL to explore", "required": True},
                        "cdp_url": {
                            "type": "string",
                            "description": (
                                "Chrome DevTools Protocol URL, e.g. 'http://host.docker.internal:9222'. "
                                "Defaults to CDP_URL env var. If omitted, launches a new headless browser."
                            ),
                            "required": False,
                        },
                        "max_steps": {"type": "integer", "description": "Max exploration steps (default 100)", "required": False},
                        "llm_model": {"type": "string", "description": "LLM model for exploration (default gpt-5.4-mini)", "required": False},
                        "credentials": {
                            "type": "object",
                            "description": "Optional login credentials: {username, password}",
                            "required": False,
                        },
                        "business_context": {"type": "string", "description": "Optional business context hint", "required": False},
                        "user_persona": {
                            "type": "string",
                            "description": "Exploration persona: new_user | returning_user | power_user | admin",
                            "required": False,
                        },
                    },
                },
                {
                    "name": "get_web_ui_test_status",
                    "description": "Poll the status of a web UI test task (no test script in response, use get_web_ui_test_result when completed).",
                    "parameters": {
                        "task_id": {"type": "string", "description": "Task ID from start_web_ui_test", "required": True},
                    },
                },
                {
                    "name": "get_web_ui_test_result",
                    "description": "Get the full result of a completed web UI test, including the generated pytest script and bug report.",
                    "parameters": {
                        "task_id": {"type": "string", "description": "Task ID from start_web_ui_test", "required": True},
                    },
                },
                {
                    "name": "cancel_web_ui_test",
                    "description": "Cancel a running web UI test task.",
                    "parameters": {
                        "task_id": {"type": "string", "description": "Task ID from start_web_ui_test", "required": True},
                    },
                },
            ]

        return tools

    async def connect_orchestrator(self):
        """Connect to Orchestrator WebSocket and handle messages"""
        # Ensure orchestrator_url doesn't have trailing slash
        base_url = self.orchestrator_url.rstrip('/')
        uri = f"{base_url}/agent/connect"
        headers = {
            "x-agent-id": self.agent_id or "unknown" 
            # Note: Orchestrator expects agent_id. 
            # If orchestrator validates against DB, it should use the ID returned by register.
            # If orchestrator just uses it as session key, it's fine.
            # We use the ID returned by API service.
        }
        
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
                        browser-use is running in a background thread."""
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

                                    if method == "tools/call":
                                        tool_name = params.get("name")
                                        arguments = params.get("arguments", {})
                                        logger.info(f"🛠️  Calling tool: {tool_name}")
                                        logger.info(f"📋 Tool arguments: {json.dumps(arguments, indent=2)}")
                                        result = await self.handle_tool_call(tool_name, arguments)
                                        logger.info(f"✅ Tool result: {json.dumps(result, indent=2)}")
                                    elif method == "tools/list":
                                        logger.info("📝 Listing available tools")
                                        result = await self.handle_tools_list(params)
                                        logger.info(f"✅ Available tools: {json.dumps(result, indent=2)}")
                                    elif method == "redteam_browser_probe":
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
                if _WEB_UI_ENABLED and self.oauth_client.access_token:
                    web_ui_runner.set_api_credentials(
                        self.api_service_url, self.oauth_client.access_token
                    )

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
        await self.register()

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

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Argus Client Agent - Secure Public Client")
    parser.add_argument("--orchestrator-url", default="wss://www.example.com", help="Orchestrator WebSocket URL")
    parser.add_argument("--api-service-url", default="https://www.example.com", help="API Service URL")
    parser.add_argument("--agent-name", default="default-client-agent", help="Unique name for this agent")
    
    # authentication (SECURE: only username/password, client_secret stays on server)
    parser.add_argument("--username", help="username")
    parser.add_argument("--password", help="password")
    
    # API token authentication (fallback)
    parser.add_argument("--api-token", help="API Token for authentication (fallback)")
    
    args = parser.parse_args()
    
    # Validate that we have either credentials or API token
    has_credentials = args.username and args.password
    if not has_credentials and not args.api_token:
        parser.error("Either credentials (--username/password) or --api-token must be provided")
    
    agent = ClientAgent(
        orchestrator_url=args.orchestrator_url,
        api_service_url=args.api_service_url,
        agent_name=args.agent_name,
        username=args.username,
        password=args.password,
        api_token=args.api_token
    )
    
    try:
        asyncio.run(agent.run())
    except KeyboardInterrupt:
        logger.info("Agent stopped by user")
