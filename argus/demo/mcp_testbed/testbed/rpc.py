from __future__ import annotations

from .session import Session

METHOD_NOT_FOUND = -32601


def handle_request(session: Session, body: dict, server: str = "primary") -> dict:
    request_id = body.get("id")
    method = body.get("method")
    params = body.get("params") or {}

    session.interaction_count += 1
    counts = session.interaction_count_by_session.setdefault(str(session.conversation), {"requests": 0, "tool_calls": 0})
    counts["requests"] += 1

    if server == "second":
        if method == "initialize":
            result = {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "team-utilities", "version": "0.1.0"},
            }
        elif method == "tools/list":
            result = {"tools": session.world.second_server_tools(
                seq=session.interaction_count, conversation=session.conversation
            )}
        elif method == "tools/call":
            counts["tool_calls"] += 1
            name = params.get("name")
            arguments = params.get("arguments") or {}
            session.record_tool_call(name, arguments, server="second")
            result = session.world.call_second_server(name, arguments)
        else:
            return {
                "jsonrpc": "2.0", "id": request_id,
                "error": {"code": METHOD_NOT_FOUND, "message": f"method not found: {method}"},
            }
        return {"jsonrpc": "2.0", "id": request_id, "result": result}

    if method == "initialize":
        result = {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "argus-mcp-testbed", "version": "0.1.0"},
        }
        if session.world is not None:
            instructions = session.world.server_instructions(
                seq=session.interaction_count, conversation=session.conversation
            )
            if instructions is not None:
                result["instructions"] = instructions
            if session.world.spec.list_resources is not None:
                result["capabilities"]["resources"] = {}
    elif method == "tools/list":
        tools = session.current_tools()
        session.record_tools_list(tools)
        result = {"tools": tools}
    elif method == "resources/list" and session.world is not None and session.world.spec.list_resources is not None:
        result = {"resources": session.world.list_resources()}
    elif method == "resources/read" and session.world is not None and session.world.spec.read_resource is not None:
        uri = params.get("uri")
        result = session.world.read_resource(
            uri, seq=session.interaction_count, conversation=session.conversation
        )
        if result is None:
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32002, "message": f"resource not found: {uri}"},
            }
    elif method == "tools/call":
        counts["tool_calls"] += 1
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
