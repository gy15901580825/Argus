from mcp.server.fastmcp import FastMCP
import os
import argparse
from tools_impl import fetch_internal_page_impl
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import json as json_lib
import uuid
from typing import Dict, Any
import datetime

# Server configuration with environment and CLI override support
default_port = 8001
default_host = "0.0.0.0"

port = int(os.getenv("PORT", default_port))
host = os.getenv("HOST", default_host)

# Parse CLI arguments for port and host
if __name__ == "__main__":
    try:
        parser = argparse.ArgumentParser(add_help=False)
        parser.add_argument("--port", type=int)
        parser.add_argument("--host", type=str)
        args, _ = parser.parse_known_args()
        
        if args.port:
            port = args.port
        if args.host:
            host = args.host
    except Exception:
        pass

mcp = FastMCP("Internal-Fetch", port=port, host=host)

# --- Result Cache Implementation ---
app = FastAPI()
RESULT_CACHE: Dict[str, Any] = {}

@mcp.tool()
async def fetch_internal_page(url: str, cookie: str = None, token: str = None) -> str:
    """
    Fetch and analyze web page structure.
    
    Returns a JSON containing a 'result_id'.
    The full detailed content (thousands of links, raw logs) is cached on the server
    to avoid overwhelming the LLM context.
    """
    # 1. Execute the heavy implementation
    raw_result_str = await fetch_internal_page_impl(url, cookie, token)
    
    try:
        result_data = json_lib.loads(raw_result_str)
    except json_lib.JSONDecodeError:
        return raw_result_str # Fallback

    # 2. Generate Result ID and Cache
    result_id = str(uuid.uuid4())
    RESULT_CACHE[result_id] = {
        "timestamp": datetime.datetime.now().isoformat(),
        "data": result_data
    }
    
    # 3. Create a summary for the LLM
    metadata = result_data.get("metadata", {})
    
    summary_response = {
        "result_id": result_id,
        "status": "success",
        "url": url,
        "summary": {
            "title": metadata.get("title", ""),
            "status_code": metadata.get("status_code"),
            "api_spec_found": bool(result_data.get("api_spec")),
            "crawled_apis_count": len(result_data.get("crawled_apis", [])),
            "links_count": len(result_data.get("links", [])),
        },
        # Provide text context for analysis, but truncate if massive
        "text": result_data.get("text", "")[:10000] 
    }
    
    return json_lib.dumps(summary_response, ensure_ascii=False)

@app.get("/result/{result_id}")
async def get_cached_result(result_id: str):
    """Retrieve full cached result by ID"""
    if result_id not in RESULT_CACHE:
        raise HTTPException(status_code=404, detail="Result ID not found or expired")
    return RESULT_CACHE[result_id]["data"]

# Mount FastAPI app to MCP server (FastMCP underlying STARLETTE app)
# Accessing private _app is a hack but standard for extending FastMCP
if hasattr(mcp, "_app"):
    mcp._app.mount("/api", app)
else:
    print("WARNING: Could not mount API endpoints - mcp._app not found")

if __name__ == "__main__":
    mcp.run()
