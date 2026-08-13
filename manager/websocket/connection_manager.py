import logging
import uuid
from typing import Dict, Set, Optional, Any
from fastapi import WebSocket

logger = logging.getLogger(__name__)

class ConnectionManager:
    """Manages active WebSocket connections for Agents and Dashboard Analyst sessions."""

    def __init__(self):
        # agent_id -> WebSocket
        self.active_agents: Dict[uuid.UUID, WebSocket] = {}
        # user_id -> Set[WebSocket] (user may open multiple tabs)
        self.active_dashboards: Dict[uuid.UUID, Set[WebSocket]] = {}

    async def connect_agent(self, agent_id: uuid.UUID, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active_agents[agent_id] = websocket
        logger.info(f"[WS] Agent connected: {agent_id}")

    def disconnect_agent(self, agent_id: uuid.UUID) -> None:
        if agent_id in self.active_agents:
            del self.active_agents[agent_id]
            logger.info(f"[WS] Agent disconnected: {agent_id}")

    async def connect_dashboard(self, user_id: uuid.UUID, websocket: WebSocket) -> None:
        await websocket.accept()
        if user_id not in self.active_dashboards:
            self.active_dashboards[user_id] = set()
        self.active_dashboards[user_id].add(websocket)
        logger.info(f"[WS] Dashboard user connected: {user_id}")

    def disconnect_dashboard(self, user_id: uuid.UUID, websocket: WebSocket) -> None:
        if user_id in self.active_dashboards:
            self.active_dashboards[user_id].discard(websocket)
            if not self.active_dashboards[user_id]:
                del self.active_dashboards[user_id]
            logger.info(f"[WS] Dashboard user disconnected: {user_id}")

    async def send_command_to_agent(self, agent_id: uuid.UUID, command_data: Dict[str, Any]) -> bool:
        """Sends a signed command to a connected agent. Returns True if pushed, False if offline."""
        websocket = self.active_agents.get(agent_id)
        if not websocket:
            logger.warning(f"[WS] Command delivery failed: Agent {agent_id} not connected via WebSocket")
            return False

        try:
            message = {
                "type": "command",
                "payload": command_data
            }
            await websocket.send_json(message)
            logger.info(f"[WS] Command {command_data.get('command_id')} pushed to agent {agent_id}")
            return True
        except Exception as exc:
            logger.error(f"[WS] Error pushing command to agent {agent_id}: {exc}")
            self.disconnect_agent(agent_id)
            return False

    async def broadcast_alert_to_dashboards(self, alert_payload: Dict[str, Any]) -> None:
        """Broadcasts security alerts to all connected dashboard analyst sessions."""
        message = {
            "type": "alert",
            "payload": alert_payload
        }
        for user_id, websockets in list(self.active_dashboards.items()):
            for ws in list(websockets):
                try:
                    await ws.send_json(message)
                except Exception as exc:
                    logger.error(f"[WS] Error broadcasting alert to user {user_id}: {exc}")
                    self.disconnect_dashboard(user_id, ws)

    async def broadcast_telemetry_update(self, agent_id: uuid.UUID, summary: Dict[str, Any]) -> None:
        """Broadcasts live telemetry updates to dashboard sessions."""
        message = {
            "type": "telemetry_summary",
            "payload": {
                "agent_id": str(agent_id),
                "summary": summary
            }
        }
        for user_id, websockets in list(self.active_dashboards.items()):
            for ws in list(websockets):
                try:
                    await ws.send_json(message)
                except Exception as exc:
                    logger.error(f"[WS] Error broadcasting telemetry to user {user_id}: {exc}")
                    self.disconnect_dashboard(user_id, ws)
