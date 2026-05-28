import asyncio
import json
import logging
import os
import websockets
import sys
from tools_impl import fetch_internal_page_impl

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("TunnelClient")

GATEWAY_URL = os.getenv("GATEWAY_URL", "ws://localhost:8081/agent/connect")
AGENT_ID = os.getenv("AGENT_ID", "web-fetch-agent")
AUTH_TOKEN = os.getenv("AUTH_TOKEN", "Bearer my-secret-token")

async def execute_tool(name: str, arguments: dict) -> dict:
    logger.info(f"Executing tool: {name} with args: {arguments}")
    
    if name == "fetch_internal_page":
        try:
            url = arguments.get("url")
            if not url:
                return {"error": "Missing 'url' argument"}
            
            result_json_str = await fetch_internal_page_impl(url)
            # The tool implementation returns a JSON string, we should parse it 
            # so we return a structured object to the orchestrator, or keep it as string?
            # JSON-RPC result can be any type. Let's return the parsed object for flexibility.
            return json.loads(result_json_str)
        except Exception as e:
            logger.error(f"Error executing fetch_internal_page: {e}")
            return {"error": str(e)}
    else:
        return {"error": f"Unknown tool: {name}"}

async def connect():
    while True:
        try:
            logger.info(f"Connecting to {GATEWAY_URL}...")
            extra_headers = {
                "x-agent-id": AGENT_ID,
                "Authorization": AUTH_TOKEN
            }
            
            async with websockets.connect(GATEWAY_URL, additional_headers=extra_headers) as websocket:
                logger.info("Connected to Orchestrator Gateway")
                
                # Ping/Keepalive loop could be here, but websockets lib handles ping/pong automatically mostly.
                # We mainly listen for messages.
                
                async for message in websocket:
                    data = json.loads(message)
                    logger.info(f"Received message: {data}")
                    
                    if data.get("jsonrpc") == "2.0":
                        msg_id = data.get("id")
                        method = data.get("method")
                        
                        if method == "tools/call":
                            params = data.get("params", {})
                            tool_name = params.get("name")
                            arguments = params.get("arguments", {})
                            
                            # Execute tool
                            result = await execute_tool(tool_name, arguments)
                            
                            # Send response
                            response = {
                                "jsonrpc": "2.0",
                                "id": msg_id,
                                "result": result
                            }
                            await websocket.send(json.dumps(response))
                        
                        elif method == "ping":
                            # Reply pong
                            await websocket.send(json.dumps({"jsonrpc": "2.0", "result": "pong", "id": msg_id}))

        except Exception as e:
            logger.error(f"Connection error: {e}")
            logger.info("Reconnecting in 5 seconds...")
            await asyncio.sleep(5)

if __name__ == "__main__":
    try:
        asyncio.run(connect())
    except KeyboardInterrupt:
        logger.info("Client stopped by user")
