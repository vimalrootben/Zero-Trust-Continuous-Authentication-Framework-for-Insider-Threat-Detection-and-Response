"""
Agents router — covers all manager-side endpoints for Phase 3:

  POST /api/v1/enrollment-tokens     — Admin generates a one-time token
  POST /agent/register               — Agent registers (unauthenticated, token-protected)
  GET  /api/v1/agents                — List agents (agents:read)
  GET  /api/v1/agents/{id}           — Single agent detail (agents:read)
  DELETE /api/v1/agents/{id}         — Decommission agent (agents:write)
  POST /agent/heartbeat              — Agent heartbeat (agent-facing, token-authenticated by cert)
  GET  /api/v1/agents/{id}/heartbeats — Heartbeat history (agents:read)
"""
import logging
import uuid
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status, Query
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from manager.config import settings
from manager.database.session import get_db
from manager.database.models.agent import Agent, AgentStatus, Heartbeat, EnrollmentToken
from manager.database.models.auth import User
from manager.api.dependencies import get_current_user, require_permission
from manager.api.schemas.agents import (
    EnrollmentTokenCreate,
    EnrollmentTokenResponse,
    RegistrationRequest,
    RegistrationResponse,
    HeartbeatPayload,
    HeartbeatResponse,
    AgentResponse,
)
from manager.agents.ca import CertificateAuthority
from manager.agents.token_service import EnrollmentTokenService
from manager.agents.registration_service import AgentRegistrationService
from manager.agents.heartbeat_service import HeartbeatService
from manager.agents.exceptions import (
    AgentException,
    TokenExpiredError,
    TokenExhaustedError,
    TokenNotFoundError,
    TokenRevokedError,
    DuplicateAgentError,
    InvalidCSRError,
    AgentNotFoundError,
)

logger = logging.getLogger(__name__)

# Router for /api/v1/* manager-facing endpoints
router = APIRouter(tags=["Agents"])

# Router for /agent/* agent-facing endpoints (no JWT — cert-protected in prod)
agent_router = APIRouter(tags=["Agent-Facing"])


def _get_ca() -> CertificateAuthority:
    """Dependency: load the CA singleton once."""
    return CertificateAuthority(
        ca_cert_path=settings.CA_CERT_PATH,
        ca_key_path=settings.CA_KEY_PATH,
    )


# ---------------------------------------------------------------------------
# ENROLLMENT TOKEN ENDPOINTS
# ---------------------------------------------------------------------------

@router.post(
    "/enrollment-tokens",
    response_model=EnrollmentTokenResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Generate a new agent enrollment token (Admin only)",
    dependencies=[Depends(require_permission("agents:write"))],
)
async def create_enrollment_token(
    body: EnrollmentTokenCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> EnrollmentTokenResponse:
    """
    Admin generates an enrollment token.
    The raw token is returned ONCE — only the hash is stored.
    """
    svc = EnrollmentTokenService(db)
    raw_token, token_obj = await svc.generate_token(
        created_by=current_user.id,
        expires_in_hours=body.expires_in_hours,
        max_uses=body.max_uses,
    )
    await db.commit()

    resp = EnrollmentTokenResponse.model_validate(token_obj)
    resp.token = raw_token  # Only shown here, never again
    return resp


@router.get(
    "/enrollment-tokens",
    response_model=list[EnrollmentTokenResponse],
    summary="List enrollment tokens (Admin only)",
    dependencies=[Depends(require_permission("agents:write"))],
)
async def list_enrollment_tokens(
    db: AsyncSession = Depends(get_db),
) -> list[EnrollmentTokenResponse]:
    result = await db.execute(select(EnrollmentToken).order_by(EnrollmentToken.created_at.desc()))
    return [EnrollmentTokenResponse.model_validate(t) for t in result.scalars().all()]


# ---------------------------------------------------------------------------
# AGENT REGISTRATION (unauthenticated — protected by enrollment token)
# ---------------------------------------------------------------------------

@agent_router.post(
    "/register",
    response_model=RegistrationResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new agent endpoint (enrollment-token protected)",
)
async def register_agent(
    payload: RegistrationRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    ca: CertificateAuthority = Depends(_get_ca),
) -> RegistrationResponse:
    """
    The one unauthenticated-by-cert endpoint. Protected by enrollment token + rate limiting.
    An already-registered agent restarting must NOT re-register — idempotent by fingerprint.
    """
    token_svc = EnrollmentTokenService(db)
    reg_svc = AgentRegistrationService(db=db, ca=ca, token_service=token_svc)

    try:
        result = await reg_svc.register_agent(payload)
        await db.commit()
        return result
    except (TokenExpiredError, TokenExhaustedError, TokenRevokedError, TokenNotFoundError) as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))
    except DuplicateAgentError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    except InvalidCSRError as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e))


# ---------------------------------------------------------------------------
# AGENT MANAGEMENT ENDPOINTS
# ---------------------------------------------------------------------------

@router.get(
    "/agents",
    response_model=list[AgentResponse],
    summary="List all agents",
    dependencies=[Depends(require_permission("agents:read"))],
)
async def list_agents(
    status_filter: Optional[str] = Query(None, alias="status"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
) -> list[AgentResponse]:
    query = select(Agent)
    if status_filter:
        try:
            query = query.where(Agent.status == AgentStatus(status_filter))
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid status filter: {status_filter}")

    query = query.order_by(Agent.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(query)
    return [AgentResponse.model_validate(a) for a in result.scalars().all()]


@router.get(
    "/agents/{agent_id}",
    response_model=AgentResponse,
    summary="Get agent details",
    dependencies=[Depends(require_permission("agents:read"))],
)
async def get_agent(
    agent_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> AgentResponse:
    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found.")
    return AgentResponse.model_validate(agent)


@router.delete(
    "/agents/{agent_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Decommission an agent (revokes certificate)",
    dependencies=[Depends(require_permission("agents:write"))],
)
async def decommission_agent(
    agent_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    ca: CertificateAuthority = Depends(_get_ca),
    current_user: User = Depends(get_current_user),
) -> None:
    token_svc = EnrollmentTokenService(db)
    reg_svc = AgentRegistrationService(db=db, ca=ca, token_service=token_svc)
    try:
        await reg_svc.decommission_agent(agent_id=agent_id, actor_id=current_user.id)
        await db.commit()
    except AgentNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))


# ---------------------------------------------------------------------------
# HEARTBEAT ENDPOINTS
# ---------------------------------------------------------------------------

@agent_router.post(
    "/heartbeat",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Agent heartbeat liveness report (agent-facing, mTLS in prod)",
)
async def receive_heartbeat(
    payload: HeartbeatPayload,
    db: AsyncSession = Depends(get_db),
) -> None:
    """
    In production, this endpoint is protected by mTLS — the TLS layer validates
    the agent's client certificate. In test/dev, we rely on the payload's agent_id.
    """
    from manager.api.routers.websocket import ws_manager
    svc = HeartbeatService(db, ws_manager=ws_manager)
    try:
        await svc.record_heartbeat(
            agent_id=payload.agent_id,
            cpu=payload.cpu_usage,
            memory=payload.memory_usage,
            disk=payload.disk_usage,
            status=payload.status,
            hostname=payload.hostname,
            os_version=payload.os_version,
            agent_version=payload.agent_version,
            ip_address=payload.ip_address,
            isolation_status=payload.isolation_status,
        )
        await db.commit()
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get(
    "/agents/{agent_id}/heartbeats",
    response_model=list[HeartbeatResponse],
    summary="Get heartbeat history for an agent",
    dependencies=[Depends(require_permission("agents:read"))],
)
async def get_heartbeat_history(
    agent_id: uuid.UUID,
    from_dt: Optional[datetime] = Query(None, alias="from"),
    to_dt: Optional[datetime] = Query(None, alias="to"),
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
) -> list[HeartbeatResponse]:
    query = select(Heartbeat).where(Heartbeat.agent_id == agent_id)
    if from_dt:
        query = query.where(Heartbeat.timestamp >= from_dt)
    if to_dt:
        query = query.where(Heartbeat.timestamp <= to_dt)

    query = query.order_by(Heartbeat.timestamp.asc()).offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(query)
    return [HeartbeatResponse.model_validate(h) for h in result.scalars().all()]
