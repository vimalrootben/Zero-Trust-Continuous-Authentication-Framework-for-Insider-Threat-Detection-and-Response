import logging
import uuid
from datetime import datetime, timezone
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

    async def broadcast_agent_connected(self, agent_id: uuid.UUID, metadata: Optional[Dict[str, Any]] = None) -> None:
        """Broadcasts agent connection event to active dashboards."""
        now = datetime.now(timezone.utc).isoformat()
        message = {
            "type": "AGENT_CONNECTED",
            "event": "agent.connected",
            "agent_id": str(agent_id),
            "timestamp": now,
            "payload": {
                "agent_id": str(agent_id),
                "status": "ONLINE",
                "last_seen_at": now,
                "metadata": metadata or {}
            },
            "data": {
                "status": "ONLINE",
                "last_seen_at": now
            }
        }
        await self._broadcast_to_dashboards(message)

    async def broadcast_agent_disconnected(self, agent_id: uuid.UUID) -> None:
        """Broadcasts agent disconnection event to active dashboards."""
        now = datetime.now(timezone.utc).isoformat()
        message = {
            "type": "AGENT_DISCONNECTED",
            "event": "agent.disconnected",
            "agent_id": str(agent_id),
            "timestamp": now,
            "payload": {
                "agent_id": str(agent_id),
                "status": "OFFLINE",
                "last_seen_at": now
            },
            "data": {
                "status": "OFFLINE",
                "last_seen_at": now
            }
        }
        await self._broadcast_to_dashboards(message)

    async def broadcast_agent_status_change(self, agent_id: uuid.UUID, status: str, last_seen_at: Optional[str] = None) -> None:
        """Broadcasts agent status change to all active dashboard sessions."""
        now = datetime.now(timezone.utc).isoformat()
        message = {
            "type": "AGENT_STATUS_CHANGED",
            "event": "agent.status_changed",
            "agent_id": str(agent_id),
            "timestamp": now,
            "payload": {
                "agent_id": str(agent_id),
                "status": status,
                "last_seen_at": last_seen_at or now
            },
            "data": {
                "status": status,
                "last_seen_at": last_seen_at or now
            }
        }
        await self._broadcast_to_dashboards(message)

    async def broadcast_network_event(self, agent_id: uuid.UUID, event_type: str, event_data: Dict[str, Any]) -> None:
        """Broadcasts real-time network connection or port events to dashboard sessions."""
        now = datetime.now(timezone.utc).isoformat()
        message = {
            "type": "NETWORK_EVENT",
            "event": f"network.{event_type.lower()}",
            "agent_id": str(agent_id),
            "timestamp": now,
            "payload": {
                "agent_id": str(agent_id),
                "event_type": event_type,
                "data": event_data
            },
            "data": event_data
        }
        await self._broadcast_to_dashboards(message)

    async def broadcast_isolation_state(self, agent_id: uuid.UUID, isolation_status: str, details: Optional[Dict[str, Any]] = None) -> None:
        """Broadcasts network isolation state changes to dashboard sessions."""
        now = datetime.now(timezone.utc).isoformat()
        message = {
            "type": "ISOLATION_STATE_CHANGED",
            "event": f"network.{isolation_status.lower()}",
            "agent_id": str(agent_id),
            "timestamp": now,
            "payload": {
                "agent_id": str(agent_id),
                "isolation_status": isolation_status,
                "details": details or {}
            },
            "data": {
                "isolation_status": isolation_status,
                "details": details or {}
            }
        }
        await self._broadcast_to_dashboards(message)

    async def broadcast_heartbeat(self, agent_id: uuid.UUID, stats: Dict[str, Any]) -> None:
        """Broadcasts periodic heartbeat updates to dashboard sessions."""
        now = datetime.now(timezone.utc).isoformat()
        message = {
            "type": "AGENT_HEARTBEAT",
            "event": "agent.heartbeat",
            "agent_id": str(agent_id),
            "timestamp": now,
            "payload": {
                "agent_id": str(agent_id),
                "stats": stats
            },
            "data": stats
        }
        await self._broadcast_to_dashboards(message)

    async def _broadcast_to_dashboards(self, message: Dict[str, Any]) -> None:
        for user_id, websockets in list(self.active_dashboards.items()):
            for ws in list(websockets):
                try:
                    await ws.send_json(message)
                except Exception as exc:
                    logger.error(f"[WS] Error broadcasting to dashboard user {user_id}: {exc}")
                    self.disconnect_dashboard(user_id, ws)
