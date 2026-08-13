import logging
import uuid
from typing import Dict, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from manager.database.models.command import Command, CommandStatus
from manager.websocket.connection_manager import ConnectionManager

logger = logging.getLogger(__name__)

class CommandDispatcher:
    """Dispatches signed commands to agents via WebSocket push with offline pending queue fallback."""

    def __init__(self, connection_manager: ConnectionManager, db_session: Optional[AsyncSession] = None):
        self.connection_manager = connection_manager
        self.db_session = db_session

    async def dispatch(self, command_id: uuid.UUID, command_payload: Dict[str, Any], db_session: Optional[AsyncSession] = None) -> bool:
        session = db_session or self.db_session
        if session is None:
            raise ValueError("Database session required to dispatch command")

        agent_id = uuid.UUID(str(command_payload["agent_id"]))

        # Attempt WebSocket Push
        pushed = await self.connection_manager.send_command_to_agent(agent_id, command_payload)

        if pushed:
            result = await session.execute(select(Command).where(Command.id == command_id))
            cmd_row = result.scalar_one_or_none()
            if cmd_row:
                cmd_row.status = CommandStatus.SENT
                await session.flush()
                logger.info(f"Command {command_id} status updated to SENT")

        return pushed
