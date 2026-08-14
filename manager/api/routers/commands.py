"""
FastAPI Router for Commands endpoints — Phase 12/15.
"""
import logging
import uuid
import hashlib
from datetime import datetime, timezone
from typing import List, Optional, Any, Dict

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from manager.database.session import get_db
from manager.database.models.command import Command, CommandStatus
from manager.database.models.agent import Agent
from manager.api.dependencies import get_current_user, require_permission
from manager.api.routers.websocket import ws_manager
from manager.websocket.command_dispatcher import CommandDispatcher
from manager.audit.audit_logger import AuditLogger

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/commands", tags=["commands"])

# ---------- Schemas ----------

class CommandCreate(BaseModel):
    agent_id: uuid.UUID = Field(..., description="Target Agent ID")
    command_type: str = Field(..., description="Action to run e.g. DISABLE_NETWORK, KILL_PROCESS, LOGOFF_USER")
    params: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Command parameters")


class CommandResponse(BaseModel):
    id: uuid.UUID
    agent_id: uuid.UUID
    command_type: str
    payload_json: Optional[Dict[str, Any]] = None
    status: str
    issued_at: str
    executed_at: Optional[str] = None
    result_json: Optional[Dict[str, Any]] = None


# ---------- Endpoints ----------

@router.post(
    "",
    response_model=CommandResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission("commands:execute"))]
)
async def issue_command(
    req: CommandCreate,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Issue a new remote response command to an agent.
    If the agent is online, pushes immediately via WebSocket.
    Otherwise, queues it as PENDING.
    """
    # Verify agent exists
    agent_result = await db.execute(select(Agent).where(Agent.id == req.agent_id))
    agent = agent_result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    cmd_id = uuid.uuid4()
    now = datetime.now(timezone.utc)

    # Generate signature based on payload hash
    payload_str = f"{cmd_id}:{req.command_type}:{req.agent_id}"
    signature = hashlib.sha256(payload_str.encode()).hexdigest()

    # Create command record
    cmd_row = Command(
        id=cmd_id,
        agent_id=req.agent_id,
        command_type=req.command_type,
        payload_json=req.params,
        issued_by=current_user.id if hasattr(current_user, "id") else None,
        signature=signature,
        status=CommandStatus.PENDING,
        issued_at=now
    )
    db.add(cmd_row)
    await db.flush()

    # Broadcast pending state for isolation actions
    if req.command_type in ("DISABLE_NETWORK", "ISOLATE_HOST"):
        await ws_manager.broadcast_isolation_state(req.agent_id, "ISOLATION_PENDING", {"command_id": str(cmd_id)})
    elif req.command_type in ("ENABLE_NETWORK", "UNISOLATE_HOST"):
        await ws_manager.broadcast_isolation_state(req.agent_id, "UNISOLATION_PENDING", {"command_id": str(cmd_id)})

    # Log to audit log
    audit_logger = AuditLogger(db)
    await audit_logger.log_action(
        actor_type="user",
        actor_id=current_user.id if hasattr(current_user, "id") else None,
        action=f"command.{req.command_type.lower()}",
        target_type="agent",
        target_id=req.agent_id,
        details_json={
            "command_id": str(cmd_id),
            "command_type": req.command_type,
            "params": req.params
        }
    )

    # Dispatch via websocket if connected
    dispatcher = CommandDispatcher(connection_manager=ws_manager, db_session=db)
    payload = {
        "command_id": str(cmd_id),
        "command_type": req.command_type,
        "agent_id": str(req.agent_id),
        "params": req.params or {},
        "signature": signature,
        "issued_at": now.isoformat()
    }
    
    pushed = await dispatcher.dispatch(cmd_id, payload, db_session=db)
    await db.commit()

    return CommandResponse(
        id=cmd_row.id,
        agent_id=cmd_row.agent_id,
        command_type=cmd_row.command_type,
        payload_json=cmd_row.payload_json,
        status=cmd_row.status.value,
        issued_at=cmd_row.issued_at.isoformat(),
        executed_at=cmd_row.executed_at.isoformat() if cmd_row.executed_at else None,
        result_json=cmd_row.result_json
    )


@router.get("/agent/{agent_id}", response_model=List[CommandResponse])
async def list_agent_commands(
    agent_id: uuid.UUID,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """List commands issued to a specific agent."""
    result = await db.execute(
        select(Command)
        .where(Command.agent_id == agent_id)
        .order_by(Command.issued_at.desc())
    )
    rows = result.scalars().all()
    return [
        CommandResponse(
            id=r.id,
            agent_id=r.agent_id,
            command_type=r.command_type,
            payload_json=r.payload_json,
            status=r.status.value,
            issued_at=r.issued_at.isoformat(),
            executed_at=r.executed_at.isoformat() if r.executed_at else None,
            result_json=r.result_json
        ) for r in rows
    ]
