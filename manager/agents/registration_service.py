"""
AgentRegistrationService — Orchestrates the full agent onboarding flow.

Flow:
  1. Validate & atomically consume the enrollment token.
  2. Reject duplicate hardware fingerprints (unless re-enrollment is explicit).
  3. Sign the agent's CSR with the CA.
  4. Persist the agents row with status='active'.
  5. Write an audit log entry.
  6. Return the signed certificate + agent metadata.
"""
import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from manager.database.models.agent import Agent, AgentStatus
from manager.database.models.audit import AuditLog, ActorType
from manager.agents.ca import CertificateAuthority
from manager.agents.token_service import EnrollmentTokenService
from manager.agents.exceptions import DuplicateAgentError, InvalidCSRError
from manager.api.schemas.agents import RegistrationRequest, RegistrationResponse

logger = logging.getLogger(__name__)


class AgentRegistrationService:
    def __init__(
        self,
        db: AsyncSession,
        ca: CertificateAuthority,
        token_service: EnrollmentTokenService,
    ) -> None:
        self.db = db
        self.ca = ca
        self.token_service = token_service

    async def register_agent(self, payload: RegistrationRequest) -> RegistrationResponse:
        """
        Full registration flow:

        1. validate_and_consume(enrollment_token)  — raises Token* errors on failure
        2. Check for duplicate hardware_fingerprint — raises DuplicateAgentError
        3. sign_csr(csr_pem, common_name=hostname)
        4. Create agents row with status='active'
        5. Audit log agent.registration.success
        6. Return RegistrationResponse
        """
        # Step 1: Validate and consume enrollment token
        token = await self.token_service.validate_and_consume(payload.enrollment_token)

        # Step 2: Reject duplicate fingerprint
        existing = await self.db.execute(
            select(Agent).where(
                Agent.device_fingerprint == payload.hardware_fingerprint,
                Agent.status != AgentStatus.DECOMMISSIONED,
            )
        )
        if existing.scalar_one_or_none():
            logger.warning(
                f"Duplicate hardware fingerprint rejected: {payload.hardware_fingerprint}"
            )
            raise DuplicateAgentError(
                f"An active agent with fingerprint '{payload.hardware_fingerprint}' already exists. "
                "Decommission the existing agent before re-registering."
            )

        # Step 3: Sign the CSR
        signed_cert_pem = self.ca.sign_csr(
            csr_pem=payload.public_key_csr,
            common_name=payload.hostname,
        )
        cert_fingerprint = self.ca.get_fingerprint(signed_cert_pem)
        ca_pem = self.ca.get_ca_pem()

        # Step 4: Create agent row
        agent = Agent(
            hostname=payload.hostname,
            device_fingerprint=payload.hardware_fingerprint,
            os_version=payload.os_version,
            agent_version=payload.agent_version,
            status=AgentStatus.ACTIVE,
            enrollment_token_id=token.id,
            cert_fingerprint=cert_fingerprint,
            last_seen_at=datetime.now(timezone.utc),
        )
        self.db.add(agent)
        await self.db.flush()

        # Step 5: Audit log
        audit = AuditLog(
            actor_type=ActorType.SYSTEM,
            actor_id=None,
            action="agent.registration.success",
            target_type="agent",
            target_id=agent.id,
            details_json={
                "hostname": payload.hostname,
                "os_version": payload.os_version,
                "agent_version": payload.agent_version,
                "device_fingerprint": payload.hardware_fingerprint,
                "cert_fingerprint": cert_fingerprint,
            },
            ip_address=None,
            timestamp=datetime.now(timezone.utc),
        )
        self.db.add(audit)
        await self.db.flush()

        logger.info(
            f"Agent registered: id={agent.id}, hostname={payload.hostname}, "
            f"fingerprint={payload.hardware_fingerprint}"
        )

        # Step 6: Return response
        return RegistrationResponse(
            agent_id=agent.id,
            signed_certificate=signed_cert_pem,
            ca_certificate=ca_pem,
            initial_policy_group=None,
            heartbeat_interval_seconds=30,
        )

    async def decommission_agent(self, agent_id: uuid.UUID, actor_id: uuid.UUID) -> None:
        """
        Decommission an agent:
        - Revoke its certificate (via CA CRL)
        - Set status='decommissioned'
        - Write audit log

        Raises:
            AgentNotFoundError if the agent doesn't exist.
        """
        from manager.agents.exceptions import AgentNotFoundError

        result = await self.db.execute(select(Agent).where(Agent.id == agent_id))
        agent = result.scalar_one_or_none()

        if not agent:
            raise AgentNotFoundError(f"Agent {agent_id} not found.")

        # Revoke certificate
        if agent.cert_fingerprint:
            self.ca.revoke_certificate(agent.cert_fingerprint)

        agent.status = AgentStatus.DECOMMISSIONED

        audit = AuditLog(
            actor_type=ActorType.USER,
            actor_id=actor_id,
            action="agent.decommissioned",
            target_type="agent",
            target_id=agent.id,
            details_json={
                "hostname": agent.hostname,
                "cert_fingerprint": agent.cert_fingerprint,
            },
            ip_address=None,
            timestamp=datetime.now(timezone.utc),
        )
        self.db.add(audit)
        await self.db.flush()

        logger.info(f"Agent decommissioned: id={agent_id}, by actor={actor_id}")
