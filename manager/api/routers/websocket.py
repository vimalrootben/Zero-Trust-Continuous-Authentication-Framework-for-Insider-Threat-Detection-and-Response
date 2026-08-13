import uuid
import logging
from typing import Optional
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from manager.api.dependencies import get_db, jwt_handler
from manager.database.models.command import Command, CommandStatus
from manager.websocket.connection_manager import ConnectionManager
from manager.config import settings

logger = logging.getLogger(__name__)

ws_manager = ConnectionManager()

router = APIRouter(tags=["websocket"])

@router.websocket("/agent/ws")
async def agent_websocket_endpoint(
    websocket: WebSocket,
    agent_id: uuid.UUID = Query(...),
    db: AsyncSession = Depends(get_db)
):
    """
    WebSocket endpoint for Agent mTLS connection.
    On connection, flushes all pending commands for the agent immediately.
    """
    await ws_manager.connect_agent(agent_id, websocket)

    try:
        # Flush pending commands on connect
        stmt = select(Command).where(
            Command.agent_id == agent_id,
            Command.status == CommandStatus.PENDING
        ).order_by(Command.issued_at)

        result = await db.execute(stmt)
        pending_commands = list(result.scalars().all())

        for cmd in pending_commands:
            payload = {
                "command_id": str(cmd.id),
                "command_type": cmd.command_type,
                "agent_id": str(cmd.agent_id),
                "params": cmd.payload_json or {},
                "signature": cmd.signature,
                "issued_at": cmd.issued_at.isoformat()
            }
            pushed = await ws_manager.send_command_to_agent(agent_id, payload)
            if pushed:
                cmd.status = CommandStatus.SENT
        await db.commit()

        # Listen for messages (ack, result, ping)
        while True:
            data = await websocket.receive_json()
            msg_type = data.get("type")

            if msg_type == "ping":
                await websocket.send_json({"type": "pong"})
            elif msg_type == "ack":
                cmd_id = uuid.UUID(data.get("command_id"))
                cmd_row = await db.get(Command, cmd_id)
                if cmd_row:
                    cmd_row.status = CommandStatus.ACKNOWLEDGED
                    await db.commit()
            elif msg_type == "result":
                cmd_id = uuid.UUID(data.get("command_id"))
                cmd_row = await db.get(Command, cmd_id)
                if cmd_row:
                    cmd_row.status = CommandStatus.SUCCESS if data.get("status") == "success" else CommandStatus.FAILED
                    cmd_row.result_json = data.get("output")
                    await db.commit()

    except WebSocketDisconnect:
        ws_manager.disconnect_agent(agent_id)
    except Exception as exc:
        logger.error(f"[WS] Error in agent websocket loop for {agent_id}: {exc}")
        ws_manager.disconnect_agent(agent_id)

@router.websocket("/dashboard/ws")
async def dashboard_websocket_endpoint(
    websocket: WebSocket,
    token: str = Query(...)
):
    """
    WebSocket endpoint for Dashboard Analyst live telemetry & alert pushes.
    """
    try:
        payload = jwt_handler.decode_access_token(token)
        user_id = uuid.UUID(payload.sub)
    except Exception:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await ws_manager.connect_dashboard(user_id, websocket)

    try:
        while True:
            data = await websocket.receive_json()
            if data.get("type") == "ping":
                await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        ws_manager.disconnect_dashboard(user_id, websocket)
    except Exception as exc:
        logger.error(f"[WS] Error in dashboard websocket loop for user {user_id}: {exc}")
        ws_manager.disconnect_dashboard(user_id, websocket)
