from typing import AsyncGenerator, Optional, Dict, Any
from typing_extensions import override
import json
import httpx
import logging

from google.adk.agents.base_agent import BaseAgent, BaseAgentConfig
from google.adk.events.event import Event
from google.adk.agents.invocation_context import InvocationContext
from google.genai import types

logger = logging.getLogger(__name__)

class RemoteAgentConfig(BaseAgentConfig):
    service_url: str

class RemoteAgent(BaseAgent):
    """
    An agent that delegates execution to a remote service via HTTP.
    """
    config_type = RemoteAgentConfig
    # Pydantic V2: Declare fields with defaults to make them optional
    service_url: str = ""
    payload_extras: Dict[str, Any] = {}

    def __init__(
        self,
        name: str,
        service_url: str,
        description: str = "",
        config: Optional[RemoteAgentConfig] = None,
        payload_extras: Optional[Dict[str, Any]] = None
    ):
        if config:
            service_url = config.service_url
        # Pass service_url and payload_extras to Pydantic's model_construct
        super().__init__(
            name=name, 
            description=description, 
            service_url=service_url,
            payload_extras=payload_extras or {}
        )

    @override
    async def _run_async_impl(
        self, ctx: InvocationContext
    ) -> AsyncGenerator[Event, None]:
        
        # Prepare payload
        payload = {
            "session_state": ctx.session.state,
            "invocation_id": ctx.invocation_id,
            "user_id": ctx.session.user_id,
            "app_name": ctx.session.app_name,
            # "events": [] # Optionally pass history if we needed to serialize it
        }
        
        # Merge extra payload fields (e.g., model_provider)
        if self.payload_extras:
            payload.update(self.payload_extras)

        async with httpx.AsyncClient() as client:
            try:
                # Use stream to handle Server-Sent Events (NDJSON)
                async with client.stream(
                    "POST", 
                    self.service_url, 
                    json=payload,
                    timeout=300.0 # Long timeout for agent execution
                ) as response:
                    response.raise_for_status()
                    async for line in response.aiter_lines():
                        if not line.strip():
                            continue
                        try:
                            # Parse JSON line
                            data = json.loads(line)
                            
                            # Check for error in response
                            if "error" in data and isinstance(data["error"], str):
                                logger.error(f"Remote agent reported error: {data['error']}")
                                # We could yield an error event here if Event supports it
                                continue

                            # Reconstruct Event object
                            try:
                                event = Event.model_validate(data)
                                yield event
                            except Exception:
                                # Fallback: If it's not a standard Event, wrap it
                                # This handles cases where the remote service returns raw data (like artifacts)
                                # instead of a full Event object.
                                content_text = json.dumps(data, indent=2)
                                yield Event(
                                    invocation_id=ctx.invocation_id,
                                    author=self.name,
                                    content=types.Content(parts=[types.Part(text=f"Remote Agent Output:\n{content_text}")])
                                )
                        except json.JSONDecodeError:
                            logger.error(f"Failed to parse event JSON: {line}")
                        except Exception as e:
                            logger.error(f"Error reconstructing event: {e}")
                            
            except httpx.HTTPError as e:
                logger.error(f"Remote agent call failed to {self.service_url}: {e}")
                # Yield an error event instead of raising
                error_message = f"Failed to connect to remote service at {self.service_url}. Error: {str(e)}"
                yield Event(
                    invocation_id=ctx.invocation_id,
                    author=self.name,
                    content=types.Content(parts=[types.Part(text=f"⚠️ Remote Agent Error:\n{error_message}\n\nNote: This agent requires an external service that is currently unavailable.")])
                )

