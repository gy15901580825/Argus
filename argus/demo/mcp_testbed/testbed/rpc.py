from __future__ import annotations

from dataclasses import dataclass

from .session import Session

METHOD_NOT_FOUND = -32601
ELICIT_VERSIONS = ("2025-06-18", "2025-11-25")


@dataclass(frozen=True)
class ElicitPending:
    call_id: object
    tool: str
    arguments: dict
    request: dict
    seq: int
    conversation: int


def handle_request(
    session: Session, body: dict, server: str = "primary"
) -> dict | ElicitPending:
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
        capabilities = params.get("capabilities") or {}
        session.client_capabilities = capabilities if isinstance(capabilities, dict) else {}
        requested = params.get("protocolVersion")
        version = "2024-11-05"
        if session.world is not None and session.world.spec.elicit is not None and requested in ELICIT_VERSIONS:
            version = requested
        session.protocol_version = version
        result = {
            "protocolVersion": version,
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
        if (
            session.world is not None
            and session.world.spec.elicit is not None
            and session.elicitation_allowed()
            and not session._elicitation_closing
        ):
            form = session.world.elicitation_for(
                name, arguments,
                seq=session.interaction_count, conversation=session.conversation,
            )
            if form is not None:
                return ElicitPending(
                    call_id=request_id, tool=name, arguments=arguments,
                    request={
                        "jsonrpc": "2.0", "id": f"elicit-{session.interaction_count}",
                        "method": "elicitation/create", "params": form,
                    },
                    seq=session.interaction_count, conversation=session.conversation,
                )
        result = session.call_result(name, arguments)
    else:
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": METHOD_NOT_FOUND, "message": f"method not found: {method}"},
        }

    return {"jsonrpc": "2.0", "id": request_id, "result": result}
