"""JSON-RPC 2.0 surface for the hostile MCP testbed.

Handles exactly the calls a probe needs to stage a scenario: `initialize`,
`tools/list`, `tools/call`. Everything else returns a JSON-RPC error rather
than a 500, and every request -- including errors -- counts toward
`interaction_count`, so the runner can tell "the agent defended itself" apart
from "the probe never actually ran".
"""

from __future__ import annotations

from testbed.session import Session

METHOD_NOT_FOUND = -32601


def handle_request(session: Session, body: dict) -> dict:
    request_id = body.get("id")
    method = body.get("method")
    params = body.get("params") or {}

    session.interaction_count += 1

    if method == "initialize":
        result = {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "argus-mcp-testbed", "version": "0.1.0"},
        }
    elif method == "tools/list":
        tools = session.current_tools()
        session.record_tools_list(tools)
        result = {"tools": tools}
    elif method == "tools/call":
        name = params.get("name")
        arguments = params.get("arguments") or {}
        session.record_tool_call(name, arguments)
        result = session.call_result(name, arguments)
    else:
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": METHOD_NOT_FOUND, "message": f"method not found: {method}"},
        }

    return {"jsonrpc": "2.0", "id": request_id, "result": result}
