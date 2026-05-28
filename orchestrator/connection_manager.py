"""
WebSocket Connection Manager for Agent Communication

This module provides a centralized ConnectionManager for handling WebSocket
connections with agents. It's in a separate module to avoid circular imports.
"""
import asyncio
import logging
import os
import uuid
import httpx
from typing import Dict, Optional, Any
from fastapi import WebSocket, HTTPException

logger = logging.getLogger("ConnectionManager")

API_SERVICE_URL = os.getenv("API_SERVICE_URL", "http://argus-api-service.default.svc.cluster.local:8881")
ORCHESTRATOR_SECRET = os.getenv("ORCHESTRATOR_SECRET", "default_secret_change_me")

class ConnectionManager:
    """Manages WebSocket connections for agents"""
    
    def __init__(self):
        # Store active connections: agent_id -> WebSocket
        self.active_connections: Dict[str, WebSocket] = {}
        # Store pending command futures: command_id -> Future
        self.pending_commands: Dict[str, asyncio.Future] = {}
        logger.info(f"ConnectionManager initialized, instance id: {id(self)}")

    async def connect(self, websocket: WebSocket, agent_id: str):
        await websocket.accept()
        self.active_connections[agent_id] = websocket
        logger.info(f"Agent connected: {agent_id}, ConnectionManager id: {id(self)}, total connections: {len(self.active_connections)}")
        
        # Notify API Service to update status to active
        try:
            async with httpx.AsyncClient() as client:
                await client.post(
                    f"{API_SERVICE_URL}/api/v1/internal/agent/status",
                    json={"agent_id": agent_id, "status": "active"},
                    headers={"x-orchestrator-secret": ORCHESTRATOR_SECRET},
                    timeout=5.0
                )
            logger.info(f"Updated agent {agent_id} status to active")
        except Exception as e:
            logger.error(f"Failed to update agent status to active: {e}")

    async def disconnect(self, agent_id: str):
        if agent_id in self.active_connections:
            del self.active_connections[agent_id]
            logger.info(f"Agent disconnected: {agent_id}, total connections: {len(self.active_connections)}")
            
            # Notify API Service to update status to offline
            try:
                async with httpx.AsyncClient() as client:
                    await client.post(
                        f"{API_SERVICE_URL}/api/v1/internal/agent/status",
                        json={"agent_id": agent_id, "status": "offline"},
                        headers={"x-orchestrator-secret": ORCHESTRATOR_SECRET},
                        timeout=5.0
                    )
                logger.info(f"Updated agent {agent_id} status to offline")
            except Exception as e:
                logger.error(f"Failed to update agent status to offline: {e}")

    async def send_command(self, agent_id: str, method: str, params: Dict[str, Any]) -> Any:
        if agent_id not in self.active_connections:
            raise HTTPException(status_code=404, detail=f"Agent {agent_id} not connected")
        
        connection = self.active_connections[agent_id]
        command_id = f"cmd-{asyncio.get_running_loop().time()}"
        
        message = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": command_id
        }
        
        # Create a future to wait for the result
        loop = asyncio.get_running_loop()
        future = loop.create_future()
        self.pending_commands[command_id] = future
        
        try:
            await connection.send_json(message)
            # Wait for response with timeout
            result = await asyncio.wait_for(future, timeout=30.0)
            return result
        except asyncio.TimeoutError:
            self.pending_commands.pop(command_id, None)
            raise HTTPException(status_code=504, detail="Agent command timed out")
        except BaseException:
            # BaseException catches CancelledError (Python 3.8+) in addition to
            # regular exceptions, preventing pending_commands from leaking when
            # the caller coroutine is externally cancelled.
            self.pending_commands.pop(command_id, None)
            if not future.done():
                future.cancel()
            raise

    def handle_response(self, response: Dict[str, Any]):
        command_id = response.get("id")
        if not command_id or command_id not in self.pending_commands:
            logger.warning(f"Received response for unknown command: {command_id}")
            return

        future = self.pending_commands[command_id]
        if "error" in response:
            future.set_exception(Exception(response["error"]))
        else:
            future.set_result(response.get("result"))

        del self.pending_commands[command_id]

    def first_active_agent_id(self) -> Optional[str]:
        """Returns any currently connected agent id, or None.

        Redteam runs are single-agent in v0; if multiple agents are connected,
        we pick the first iteration order (insertion-order on Python 3.7+).
        """
        return next(iter(self.active_connections), None)

    def get_redteam_bridge(self) -> "RedteamBridge":
        """Returns a bridge object for sending redteam_browser_probe messages."""
        return RedteamBridge(self)


class RedteamBridge:
    """Multiplexes redteam browser-probe requests over the existing client_agent WS.

    Each `send_and_wait` call generates a fresh UUIDv4 envelope id and waits
    for the matching reply via the manager's `pending_commands` future map.
    """

    METHOD = "redteam_browser_probe"

    def __init__(self, manager: ConnectionManager) -> None:
        self._mgr = manager

    async def send_and_wait(self, msg: Dict[str, Any], timeout_s: float = 60.0) -> Dict[str, Any]:
        agent_id = self._mgr.first_active_agent_id()
        if not agent_id:
            raise RuntimeError("No client_agent connected for redteam bridge")
        connection = self._mgr.active_connections[agent_id]
        command_id = str(uuid.uuid4())
        envelope = {
            "jsonrpc": "2.0",
            "method": self.METHOD,
            "params": msg,
            "id": command_id,
        }
        loop = asyncio.get_running_loop()
        future = loop.create_future()
        self._mgr.pending_commands[command_id] = future
        try:
            await connection.send_json(envelope)
            return await asyncio.wait_for(future, timeout=timeout_s)
        except asyncio.TimeoutError:
            self._mgr.pending_commands.pop(command_id, None)
            raise
        except BaseException:
            self._mgr.pending_commands.pop(command_id, None)
            if not future.done():
                future.cancel()
            raise


# Global connection manager instance
connection_manager = ConnectionManager()
