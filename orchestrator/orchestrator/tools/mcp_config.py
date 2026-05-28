"""
MCP Server Configuration for Learning Content System
"""

import json
import os
import sys
import logging
import asyncio
from typing import Optional, Dict, Any, List, TYPE_CHECKING
from google.adk.tools.mcp_tool.mcp_toolset import McpToolset, StdioServerParameters
from google.adk.tools.mcp_tool.mcp_session_manager import StdioConnectionParams
from google.adk.tools.base_tool import BaseTool
from google.adk.tools.base_toolset import BaseToolset
from google.adk.tools.tool_context import ToolContext

if TYPE_CHECKING:
    from google.adk.agents.readonly_context import ReadonlyContext

logger = logging.getLogger(__name__)


# MCP Server Configurations
def get_huggingface_mcp_toolset():
    """
    Hugging Face MCP Server for model, dataset, and paper search
    """
    # Fallback to a simpler configuration or comment out if not available
    # For now, let's try to use the generic tools server as a placeholder to avoid crashing
    return SafeMCPToolset(
        connection_params=StdioConnectionParams(
            server_params=StdioServerParameters(
                command="node_modules/.bin/mcp-server-filesystem",
                args=["."], # Using a standard server that usually exists
            )
        )
         # We have to remove the tool filter since this server doesn't support those tools
        # tool_filter=["search-models", "search-datasets",
        #              "get-model-info", "search-papers"]
    )


def get_tts_mcp_toolset():
    """
    Text-to-Speech MCP Server using Dia-1.6B
    """
    return SafeMCPToolset(
        connection_params=StdioConnectionParams(
            server_params=StdioServerParameters(
                command="npx",
                args=["-y", "-q", "mcp-remote", "https://ysharma-dia-1-6b.hf.space/gradio_api/mcp/sse",
                      "--transport", "sse-only"],
            ),
            timeout=60.0
        ),
        tool_filter=["generate_speech"]
    )


class DummyToolset(BaseToolset):
    """
    A dummy toolset that provides no-op tools.
    Used for global instances to avoid spawning processes/sessions at import time.
    """
    def __init__(self, tool_names: List[str]):
        super().__init__()
        self._tool_names = tool_names
        
    async def get_tools(self, readonly_context: Optional['ReadonlyContext'] = None) -> list[BaseTool]:
        tools = []
        for name in self._tool_names:
            # Create a simple BaseTool subclass closure
            class DummyTool(BaseTool):
                def __init__(self, n):
                    super().__init__(name=n, description=f"Placeholder for {n}", is_long_running=False)
                async def run_async(self, *, args: dict[str, Any], tool_context: ToolContext) -> Any:
                    return f"Tool {self.name} is a placeholder and not active."
                async def process_llm_request(self, *, tool_context: ToolContext, llm_request) -> None:
                    pass

            tools.append(DummyTool(name))
        return tools

    async def get_tools_with_prefix(self, readonly_context: Optional['ReadonlyContext'] = None) -> list[BaseTool]:
        return await self.get_tools(readonly_context)

    async def process_llm_request(self, *, tool_context: ToolContext, llm_request) -> None:
        pass

    async def close(self) -> None:
        pass


class SafeMCPToolset(McpToolset):
    """
    An McpToolset that safely handles cleanup errors and avoids asyncio busy-wait bugs.

    The parent McpToolset.close() has a cancel scope bug in Google ADK that can cause
    the Python asyncio event loop to spin at 100% CPU. This implementation bypasses
    the problematic cleanup entirely.
    """
    async def close(self) -> None:
        import signal
        import os
        
        logger.info("SafeMCPToolset.close() called - using safe cleanup")
        
        # Step 1: Try to terminate any subprocess directly WITHOUT calling parent close()
        # This avoids the cancel scope bug entirely
        try:
            # Look for subprocess in various possible locations
            process = None
            
            # Try _session_manager
            if hasattr(self, '_session_manager') and self._session_manager:
                sm = self._session_manager
                for attr in ['_process', 'process', '_subprocess', '_stdio_process']:
                    if hasattr(sm, attr):
                        process = getattr(sm, attr, None)
                        if process:
                            break
                
                # Also check for nested _session in session_manager
                if not process and hasattr(sm, '_session'):
                    session = sm._session
                    for attr in ['_process', 'process', '_subprocess']:
                        if hasattr(session, attr):
                            process = getattr(session, attr, None)
                            if process:
                                break
                
                # Check for _stdio_context
                if not process and hasattr(sm, '_stdio_context'):
                    ctx = sm._stdio_context
                    for attr in ['process', '_process']:
                        if hasattr(ctx, attr):
                            process = getattr(ctx, attr, None)
                            if process:
                                break
            
            # Terminate the process if found
            if process:
                logger.info(f"Found MCP subprocess: {process}")
                try:
                    if hasattr(process, 'terminate'):
                        process.terminate()
                    if hasattr(process, 'kill'):
                        process.kill()
                    logger.info("MCP subprocess terminated")
                except Exception as e:
                    logger.debug(f"Error terminating process: {e}")
        except Exception as e:
            logger.debug(f"Error finding subprocess: {e}")
        
        # Step 2: Kill any orphaned node/npx processes by scanning /proc
        try:
            for proc_dir in os.listdir('/proc'):
                if proc_dir.isdigit():
                    pid = int(proc_dir)
                    if pid <= 1:
                        continue
                    try:
                        cmdline_path = f'/proc/{proc_dir}/cmdline'
                        if os.path.exists(cmdline_path):
                            with open(cmdline_path, 'r') as f:
                                cmdline = f.read()
                                # Kill any mcp-remote or node processes related to MCP
                                if 'mcp-remote' in cmdline or 'mcp_remote' in cmdline:
                                    os.kill(pid, signal.SIGKILL)
                                    logger.info(f"Killed orphaned MCP process PID {pid}")
                    except (IOError, ProcessLookupError, PermissionError, ValueError):
                        pass
        except Exception as e:
            logger.debug(f"Error during /proc scan: {e}")
        
        # Step 3: Clear internal state to prevent any callbacks
        try:
            if hasattr(self, '_session_manager'):
                self._session_manager = None
            if hasattr(self, '_tools'):
                self._tools = []
            if hasattr(self, '_initialized'):
                self._initialized = False
        except Exception:
            pass
        
        # Step 4: Do NOT call parent close() because it triggers the infinite loop bug
        # The manual cleanup above (terminating process) is sufficient.
        # logger.info("Calling parent close() to clean up tasks...")
        # await asyncio.wait_for(super().close(), timeout=2.0)
        
        logger.info("SafeMCPToolset cleanup completed (bypassed parent close)")



def get_general_tools_mcp_toolset():
    """
    General MCP Tools for various utilities
    """
    # Use DummyToolset to avoid global stdio session
    return DummyToolset(["search-models", "search-datasets"])


def get_api_testing_mcp_toolset():
    """
    API Testing MCP Server (Real Service via SSE)
    """
    # Connect to the running SSE server
    # We use npx mcp-remote to bridge the SSE connection to Stdio
    # Use localhost instead of 0.0.0.0 to avoid HTTPS requirement error
    url = os.getenv("MCP_API_TESTING_URL", "http://localhost:8000/sse")
    # Use SafeMCPToolset to avoid crash on cleanup
    return SafeMCPToolset(
        connection_params=StdioConnectionParams(
            server_params=StdioServerParameters(
                command="npx",
                args=["-y", "-q", "mcp-remote", url, "--transport", "sse-only", "--allow-http"],
            ),
            timeout=60.0
        ),
        tool_filter=["run_api_test"]
    )


def get_internal_web_fetch_mcp_toolset():
    """
    Internal Web Fetch MCP Server (Real Service via SSE)
    """
    # Connect to the running SSE server
    # We use npx mcp-remote to bridge the SSE connection to Stdio
    url = os.getenv("MCP_WEB_FETCH_URL", "http://argus-testing-web-fetch-service.default.svc.cluster.local:8001/sse")
    return SafeMCPToolset(
        connection_params=StdioConnectionParams(
            server_params=StdioServerParameters(
                command="npx",
                args=["-y", "-q", "mcp-remote", url, "--transport", "sse-only", "--allow-http"],
            ),
            timeout=900.0
        ),
        tool_filter=["fetch_internal_page"]
    )


def get_browser_mcp_toolset():
    """
    Browser Tools MCP Server for web content analysis
    """
    return SafeMCPToolset(
        connection_params=StdioConnectionParams(
            server_params=StdioServerParameters(
                command="npx",
                args=["-y", "-q", "@agentdeskai/browser-tools-mcp@latest"],
            )
        )
    )


def read_url_mcp_toolset():
    """
    URL Reader MCP Server for fetching and summarizing web pages.
    Returns dummy implementation for global instances.
    For dynamic client agent selection, use get_read_url_toolset_with_context() with context.
    """
    # Use DummyToolset to avoid global stdio session
    return DummyToolset(["fetch_url"])


class ClientAgentTool(BaseTool):
    """
    A proxy tool that forwards calls to a client agent via WebSocket.
    Inherits from BaseTool to work with Google ADK.
    """
    def __init__(
        self, 
        name: str,
        description: str,
        toolset: 'ClientAgentMCPToolset',
        parameters_schema: Optional[Dict[str, Any]] = None
    ):
        # Store references
        self.toolset_ref = toolset
        self.tool_name = name
        self.params_schema = parameters_schema or {}
        
        # Initialize BaseTool
        super().__init__(
            name=name,
            description=description,
            is_long_running=False
        )
        
        # EXPERIMENTAL: Try to expose parameters to BaseTool / ADK
        # Since we don't know the exact attribute name, we set a few common ones
        self.parameters = self.params_schema
        self._parameters = self.params_schema
        self.input_schema = self.params_schema
        self.args_schema = self.params_schema # LangChain style
        
        # Log BaseTool attributes for debugging
        if not hasattr(ClientAgentTool, '_debug_logged'):
            ClientAgentTool._debug_logged = True
            try:
                logger.info(f"🔍 BaseTool attributes: {dir(BaseTool)}")
                logger.info(f"🔍 BaseTool instance attributes: {dir(self)}")
            except Exception as e:
                logger.error(f"Failed to inspect BaseTool: {e}")

        logger.info(f"🔧 ClientAgentTool created: {name}")
        logger.info(f"   Description: {description}")
        logger.info(f"   Parameters Schema Keys: {list(self.params_schema.keys())}")
    
    async def run_async(self, *, args: dict[str, Any], tool_context: ToolContext) -> Any:
        """Execute the tool by proxying to client agent"""
        logger.info(f"🔨 ClientAgentTool.run_async called for: {self.tool_name}")
        logger.info(f"📥 Input args: {json.dumps(args, indent=2)}")
        
        result = await self.toolset_ref.call_tool(self.tool_name, args)
        
        logger.info(f"📤 ClientAgentTool.run_async result: {str(result)[:200]}")
        return result
    
    async def process_llm_request(self, *, tool_context: ToolContext, llm_request) -> None:
        """Process LLM request (required by BaseTool)"""
        pass


class ClientAgentMCPToolset(BaseToolset):
    """
    A custom toolset that proxies tool calls to a connected client agent via WebSocket.
    Inherits from BaseToolset for compatibility with ADK agents.
    """
    def __init__(self, user_id: str, connection_manager, get_user_agent_id_func, auth_token: Optional[str] = None, cookie: Optional[str] = None, token: Optional[str] = None):
        """
        Initialize the client agent toolset.
        
        Args:
            user_id: The user ID to lookup the agent for
            connection_manager: The global connection manager instance from server.py
            get_user_agent_id_func: Function to query agent_id from user_id
            auth_token: Optional OAuth bearer token for authentication
            cookie: Optional cookie string for authenticated requests
            token: Optional token string for Authorization header
        """
        super().__init__()  # Initialize BaseToolset
        self.user_id = user_id
        self.agent_id: Optional[str] = None
        self.connection_manager = connection_manager
        self.get_user_agent_id_func = get_user_agent_id_func
        self.auth_token = auth_token
        self.cookie = cookie
        self.token = token
        self._tools: List[ClientAgentTool] = []
        self._initialized = False
        logger.info(f"ClientAgentMCPToolset initialized for user {user_id}, cookie: {bool(cookie)}, token: {bool(token)}")
        
    async def initialize(self):
        """Fetch agent_id and discover available tools"""
        if self._initialized:
            return
            
        if not self.agent_id:
            logger.info("=" * 80)
            logger.info("🚀 INITIALIZING CLIENT AGENT TOOLSET")
            logger.info(f"User ID: {self.user_id}")
            logger.info(f"Has OAuth Token: {bool(self.auth_token)}")
            logger.info("Note: OAuth token is used for API authentication, not for matching agent records")
            logger.info("=" * 80)
            
            # Query agent by user_id only
            # auth_token is passed for HTTP authentication, not for matching agent records
            self.agent_id = await self.get_user_agent_id_func(self.user_id, self.auth_token)
            
            if not self.agent_id:
                error_msg = (
                    f"No active client agent found for user {self.user_id}.\n"
                    f"Please ensure:\n"
                    f"1. Client Agent application is running\n"
                    f"2. Client Agent has successfully registered with API service\n"
                    f"3. Client Agent status is 'active'\n"
                    f"4. User ID in Client Agent matches OAuth user: {self.user_id}"
                )
                logger.error(f"❌ {error_msg}")
                logger.info("=" * 80)
                raise Exception(error_msg)
            
            logger.info(f"✅ Found agent ID: {self.agent_id}")
        
        # Log connection status for debugging
        active_agents = list(self.connection_manager.active_connections.keys())
        logger.info(f"📡 Active WebSocket connections: {active_agents}")
        logger.info(f"🔍 Looking for agent_id: {self.agent_id}")
        
        if self.agent_id not in active_agents:
            logger.warning(f"⚠️ Agent {self.agent_id} not connected via WebSocket!")
            logger.info("💡 The agent is registered but not connected")
            logger.info("   Please check:")
            logger.info("   1. Client Agent WebSocket connection status")
            logger.info("   2. Network connectivity between Client Agent and Orchestrator")
            logger.info("   3. Client Agent logs for connection errors")
        
        # Discover tools from client agent
        try:
            logger.info(f"🔧 Discovering tools from agent {self.agent_id}...")
            tools_info = await self.connection_manager.send_command(
                self.agent_id,
                "tools/list",
                {}
            )
            
            logger.info(f"📦 Received {len(tools_info)} tools from agent")
            
            # Create dynamic functions with correct signatures for each discovered tool
            # This ensures ADK can inspect the signature and generate correct tool declarations
            self._tools = []
            
            # Type mapping from JSON schema to Python types
            type_mapping = {
                "string": "str",
                "integer": "int",
                "number": "float",
                "boolean": "bool",
                "array": "list",
                "object": "dict"
            }
            
            for tool_info in tools_info:
                tool_name = tool_info['name']
                tool_desc = tool_info.get('description', '')
                tool_params = tool_info.get('parameters', {})
                
                # 1. Build parameter signature string
                # e.g. "url: str, limit: int"
                param_parts = []
                for p_name, p_info in tool_params.items():
                    p_type_str = type_mapping.get(p_info.get('type'), 'Any')
                    # Sanitize parameter name if needed (though usually they are valid identifiers)
                    p_name_clean = p_name.replace('-', '_')
                    param_parts.append(f"{p_name_clean}: {p_type_str}")
                
                sig_str = ", ".join(param_parts)
                
                # 2. Define function code dynamically
                # We use a closure to access 'self'
                # Sanitize function name for Python syntax
                func_name = tool_name.replace('-', '_').replace(' ', '_')
                
                # Clean description to be safe for docstring
                safe_desc = tool_desc.replace("'''", "").replace('"""', "")
                
                code = f"""
async def {func_name}({sig_str}) -> Any:
    '''{safe_desc}'''
    # Capture arguments
    args = locals().copy()
    return await toolset.call_tool('{tool_name}', args)
"""
                
                # 3. Execute to create function
                # Prepare scope with required types and self reference
                scope = {
                    'toolset': self,
                    'Any': Any,
                    'str': str,
                    'int': int,
                    'float': float,
                    'bool': bool,
                    'list': list,
                    'dict': dict
                }
                
                try:
                    exec(code, scope)
                    tool_func = scope[func_name]
                    
                    # Attach metadata just in case
                    tool_func._tool_name = tool_name
                    
                    self._tools.append(tool_func)
                    
                    logger.info(f"📦 Created dynamic tool function: {tool_name}")
                    logger.info(f"   Signature: {func_name}({sig_str})")
                    
                except Exception as e:
                    logger.error(f"Failed to create dynamic function for {tool_name}: {e}")
                    logger.error(f"Code was:\n{code}")
            
            self._initialized = True
            logger.info(f"✅ Successfully initialized with {len(self._tools)} tool functions from client agent {self.agent_id}")
            logger.info("=" * 80)
        except Exception as e:
            logger.error(f"❌ Failed to discover tools from client agent: {e}")
            logger.exception(e)
            logger.info("=" * 80)
            # Fallback: create a default fetch_url function
            async def fetch_url(url: str):
                """Fetch and analyze content from ANY URL including private network addresses.
                
                Args:
                    url (str): The URL to fetch (can be public or private network address)
                
                Returns:
                    The content retrieved from the URL
                """
                return await self.call_tool("fetch_url", {"url": url})
            
            self._tools = [fetch_url]
            logger.info("⚠️ Using default fetch_url tool function as fallback")
            self._initialized = True
    
    async def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Any:
        """
        Call a tool on the client agent via WebSocket.
        """
        if not self.agent_id:
            await self.initialize()
        
        logger.info("=" * 80)
        logger.info("🔧 CALLING CLIENT AGENT TOOL")
        logger.info(f"Agent ID: {self.agent_id}")
        logger.info(f"Tool Name: {tool_name}")
        logger.info(f"Arguments: {json.dumps(arguments, indent=2)}")
        logger.info("=" * 80)
        
        # Use the connection_manager to send command
        try:
            # Inject cookie if available and not present in arguments
            final_args = arguments.copy()
            if self.cookie:
                # Check for common cookie parameter names
                has_cookie_param = any(k in final_args for k in ['cookie', 'cookies'])
                if not has_cookie_param:
                    # Inject cookie directly
                    final_args['cookie'] = self.cookie
                    logger.info(f"🍪 Injected cookie into tool {tool_name}")
            
            # Inject token if available and not present in arguments
            if self.token:
                has_token_param = 'token' in final_args
                if not has_token_param:
                    final_args['token'] = self.token
                    logger.info(f"🔑 Injected token into tool {tool_name}")

            result = await self.connection_manager.send_command(
                self.agent_id,
                "tools/call",
                {"name": tool_name, "arguments": final_args}
            )
            logger.info("=" * 80)
            logger.info("✅ CLIENT AGENT TOOL RESULT")
            logger.info(f"Tool Name: {tool_name}")
            logger.info(f"Result: {json.dumps(result, indent=2) if isinstance(result, dict) else str(result)[:500]}")
            logger.info("=" * 80)
            return result
        except Exception as e:
            logger.error("=" * 80)
            logger.error("❌ CLIENT AGENT TOOL ERROR")
            logger.error(f"Tool Name: {tool_name}")
            logger.error(f"Error: {str(e)}")
            logger.error("=" * 80)
            raise
    
    async def get_tools(self, readonly_context: Optional['ReadonlyContext'] = None) -> list[BaseTool]:
        """Return list of available tools (required by BaseToolset)"""
        if not self._initialized:
            logger.warning("get_tools called before initialization")
            return []
        return self._tools
    
    async def get_tools_with_prefix(self, readonly_context: Optional['ReadonlyContext'] = None) -> list[BaseTool]:
        """Return tools with name prefix (required by BaseToolset)"""
        return await self.get_tools(readonly_context)
    
    async def process_llm_request(self, *, tool_context: ToolContext, llm_request) -> None:
        """Process LLM request (required by BaseToolset)"""
        pass
    
    async def close(self) -> None:
        """Cleanup resources (required by BaseToolset)"""
        try:
            self._tools = []
            self._initialized = False
            logger.info(f"ClientAgentMCPToolset closed for user {self.user_id}")
        except Exception as e:
            # Suppress cancel scope warnings during cleanup
            logger.debug(f"Exception during ClientAgentMCPToolset cleanup: {e}")


def get_read_url_toolset_with_context(context: Optional[Dict[str, Any]] = None):
    """
    Factory function to create appropriate URL reading toolset based on context.
    
    If context contains local_test_enabled=True and user_id:
      - Returns a ClientAgentMCPToolset that proxies to the user's client agent
    Otherwise:
      - Returns the default filesystem mock
    
    Args:
        context: Dictionary containing local_test_enabled, user_id, auth_token, etc.
    
    Returns:
        MCPToolset or ClientAgentMCPToolset instance
    """
    if context is None:
        context = {}
    else:
        if not isinstance(context, dict):
            context = dict(context)
    
    local_test_enabled = context.get("local_test_enabled", False)
    user_id = context.get("user_id")
    auth_token = context.get("auth_token")
    
    # Enable local test with properly implemented ClientAgentMCPToolset
    if local_test_enabled and user_id:
        logger.info(f"Local test enabled for user {user_id}, using client agent")
        # Import here to avoid circular dependency
        try:
            # Import from separate module to avoid circular imports
            from connection_manager import connection_manager
            from server import get_user_agent_id
            
            # Extract cookie from context if available
            # Check for both "cookie" and "cookies" keys
            cookie = context.get("cookie") or context.get("cookies")
            token = context.get("token")
            
            return ClientAgentMCPToolset(
                user_id=user_id,
                connection_manager=connection_manager,
                get_user_agent_id_func=get_user_agent_id,
                auth_token=auth_token,
                cookie=cookie,
                token=token
            )
        except ImportError as e:
            logger.error(f"Failed to import server components: {e}, falling back to mock")
            return read_url_mcp_toolset()
    else:
        # Default: internal web fetch service
        logger.info("Using internal web fetch service for URL reading")
        return get_internal_web_fetch_mcp_toolset()


# All available MCP toolsets
AVAILABLE_MCP_TOOLSETS = {
    "api_testing": get_api_testing_mcp_toolset,
    "huggingface": get_huggingface_mcp_toolset,
    "tts": get_tts_mcp_toolset,
    "general_tools": get_general_tools_mcp_toolset,
    # "browser": get_browser_mcp_toolset
    "read_url": read_url_mcp_toolset,
}
