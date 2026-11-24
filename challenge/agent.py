import json
import math

from levels import Level
from model import ModelClient
from world import TraceEntry, World


TOOL_SCHEMAS = {
    "issue_refund": {"type": "object", "properties": {"amount": {"type": "number", "minimum": 0}}, "required": ["amount"], "additionalProperties": False},
}


def execute_tool(world: World, name: str, arguments: dict) -> dict:
    if name == "issue_refund":
        amount = arguments.get("amount")
        if set(arguments) != {"amount"} or type(amount) not in (int, float) or not math.isfinite(amount) or amount <= 0:
            raise ValueError("The refund amount must be a positive finite number.")
        world.refunds.append({"amount": amount})
        return {"issued": True, "amount": amount, "simulated": True}
    raise ValueError("This tool is unavailable in this level.")


async def run_turn(level: Level, world: World, player_input: str, model: ModelClient) -> tuple[list[TraceEntry], str]:
    for guard in level.defenses:
        if guard.stage == "input":
            reason = guard.check(world, player_input, {})
            if reason:
                return [], reason
    messages = [{"role": "system", "content": level.system_prompt}, {"role": "user", "content": player_input}]
    tools = [{"type": "function", "function": {"name": name, "description": world.tool_descriptions[name], "parameters": TOOL_SCHEMAS[name]}} for name in level.tools]
    trace: list[TraceEntry] = []
    while len(trace) < 6:
        reply = await model.complete(messages, tools)
        if not reply.tool_calls:
            return trace, reply.content
        calls = reply.tool_calls[:6 - len(trace)]
        messages.append({"role": "assistant", "content": reply.content or None, "tool_calls": [
            {"id": call.id, "type": "function", "function": {"name": call.name, "arguments": json.dumps(call.arguments)}} for call in calls
        ]})
        for call in calls:
            reason = "This tool is unavailable in this level." if call.name not in level.tools else None
            for guard in level.defenses:
                if not reason and guard.stage == "tool_call":
                    reason = guard.check(world, call.name, call.arguments)
            result = None
            if not reason:
                try:
                    result = execute_tool(world, call.name, call.arguments)
                except ValueError as exc:
                    reason = str(exc)
            entry = TraceEntry(call.name, call.arguments, result, reason)
            trace.append(entry)
            messages.append({"role": "tool", "tool_call_id": call.id, "content": json.dumps(result if not reason else {"blocked": reason})})
        if level.won(world):
            return trace, reply.content or "The agent executed the forbidden tool action."
    return trace, "Tool call limit reached (6). Try a new request."
