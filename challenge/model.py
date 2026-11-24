from dataclasses import dataclass, field
from collections import deque
from copy import deepcopy
import json
import re
from typing import Any, Protocol

import httpx


@dataclass(frozen=True)
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0


@dataclass(frozen=True)
class ToolCall:
    name: str
    arguments: dict[str, Any]
    id: str = "call-1"


@dataclass(frozen=True)
class ModelReply:
    content: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    usage: Usage = field(default_factory=Usage)


class ModelClient(Protocol):
    async def complete(self, messages: list[dict], tools: list[dict]) -> ModelReply: ...


class ScriptedModelClient:
    def __init__(self, replies=()):
        self.calls: list[dict] = []
        self.replies = deque(replies)

    async def complete(self, messages, tools) -> ModelReply:
        self.calls.append(deepcopy({"messages": messages, "tools": tools}))
        return self.replies.popleft() if self.replies else ModelReply(content="I can help with your company order.")


class DevScriptedModelClient:
    async def complete(self, messages, tools) -> ModelReply:
        if messages[-1]["role"] == "tool":
            return ModelReply(content="The simulated order adjustment is complete.")
        text = messages[-1]["content"]
        match = re.search(r"\b(\d{1,6})\b", text)
        amount = int(match.group(1)) if match else 150 if "one hundred fifty" in text.casefold() else None
        if amount is not None:
            return ModelReply(tool_calls=[ToolCall("issue_refund", {"amount": amount})])
        return ModelReply(content="Dev mode: include an amount in an order request to see a simulated tool call.")


class ModelError(Exception):
    pass


class ProxyModelClient:
    def __init__(self, base: str, client: httpx.AsyncClient | None = None, model: str = "gpt-6-luna"):
        if not base.startswith(("http://", "https://")):
            raise ValueError("CHALLENGE_MODEL_BASE must be an http(s) proxy URL")
        self.url = base.rstrip("/") + "/openai/v1/chat/completions"
        self.client = client
        self.model = model

    def payload(self, messages, tools) -> dict:
        return {
            "model": self.model, "reasoning_effort": "none", "max_completion_tokens": 300,
            "messages": messages, "tools": tools,
        }

    async def complete(self, messages, tools) -> ModelReply:
        try:
            if self.client is None:
                async with httpx.AsyncClient(timeout=30, trust_env=False) as client:
                    response = await client.post(self.url, json=self.payload(messages, tools))
            else:
                response = await self.client.post(self.url, json=self.payload(messages, tools))
            response.raise_for_status()
            data = response.json()
            message = data["choices"][0]["message"]
            usage = data["usage"]
            counts = [usage["prompt_tokens"], usage["completion_tokens"]]
            if any(type(n) is not int or n < 0 for n in counts):
                raise ValueError("Invalid usage")
            calls = []
            for raw in message.get("tool_calls") or []:
                arguments = json.loads(raw["function"]["arguments"])
                if not isinstance(arguments, dict):
                    raise ValueError("Invalid tool arguments")
                calls.append(ToolCall(raw["function"]["name"], arguments, raw["id"]))
            content = message.get("content") or ""
            if not isinstance(content, str):
                raise ValueError("Invalid model content")
            return ModelReply(content, calls, Usage(*counts))
        except (httpx.HTTPError, ValueError, KeyError, IndexError, TypeError) as exc:
            raise ModelError("The agent is temporarily unavailable. Please try again later.") from exc
