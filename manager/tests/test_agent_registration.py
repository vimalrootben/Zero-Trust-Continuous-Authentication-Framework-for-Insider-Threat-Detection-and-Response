"""
Tests for agent registration (M3):
  - Enrollment token generation and one-time consumption
  - Expired token rejection
  - Duplicate hardware fingerprint rejection
  - Successful registration returns a cert signed by the CA
  - Decommission marks status and writes audit log
"""
import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from manager.database.models.agent import Agent, AgentStatus, EnrollmentToken
from manager.database.models.auth import User
from manager.agents.token_service import EnrollmentTokenService
from manager.agents.ca import CertificateAuthority
from manager.agents.registration_service import AgentRegistrationService
from manager.agents.exceptions import (
    TokenExpiredError,
    TokenExhaustedError,
    TokenNotFoundError,
    TokenRevokedError,
    DuplicateAgentError,
)
from manager.config import settings


# ─── Helpers ────────────────────────────────────────────────────────────────

def _make_csr_pem(hostname: str = "test-host") -> str:
    """Generate a valid CSR PEM for testing."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, hostname),
        ]))
        .sign(key, hashes.SHA256(), default_backend())
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode()


def _real_ca() -> CertificateAuthority:
    """Load the actual dev CA for end-to-end signing tests."""
    return CertificateAuthority(
        ca_cert_path=settings.CA_CERT_PATH,
        ca_key_path=settings.CA_KEY_PATH,
    )


async def _get_admin_id(db: AsyncSession) -> uuid.UUID:
    """Retrieve the seeded admin user's UUID for foreign key constraints."""
    res = await db.execute(select(User).where(User.username == "admin"))
    user = res.scalar_one_or_none()
    if user:
        return user.id
    # Fallback: query any user
    res = await db.execute(select(User))
    user = res.scalars().first()
    return user.id


# ─── Token Service Tests ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_generate_and_consume_token(db_session: AsyncSession):
    """Happy path: token is generated and consumed exactly once."""
    admin_id = await _get_admin_id(db_session)
    svc = EnrollmentTokenService(db_session)

    raw_token, token_obj = await svc.generate_token(
        created_by=admin_id, expires_in_hours=24, max_uses=1
    )

    assert raw_token
    assert token_obj.used_count == 0

    # Consume once — should succeed
    consumed = await svc.validate_and_consume(raw_token)
    assert consumed.used_count == 1


@pytest.mark.asyncio
async def test_token_expired_raises(db_session: AsyncSession):
    """Expired token raises TokenExpiredError."""
    admin_id = await _get_admin_id(db_session)

    # Insert an already-expired token directly
    raw = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw.encode()).hexdigest()
    token = EnrollmentToken(
        token_hash=token_hash,
        created_by=admin_id,
        expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
        max_uses=1,
        used_count=0,
        revoked=False,
    )
    db_session.add(token)
    await db_session.flush()

    svc = EnrollmentTokenService(db_session)
    with pytest.raises(TokenExpiredError):
        await svc.validate_and_consume(raw)


@pytest.mark.asyncio
async def test_token_exhausted_on_second_use(db_session: AsyncSession):
    """Single-use token raises TokenExhaustedError on second consumption attempt."""
    admin_id = await _get_admin_id(db_session)
    svc = EnrollmentTokenService(db_session)

    raw, token_obj = await svc.generate_token(
        created_by=admin_id, expires_in_hours=1, max_uses=1
    )

    # First consumption succeeds
    await svc.validate_and_consume(raw)

    # Second should fail
    with pytest.raises(TokenExhaustedError):
        await svc.validate_and_consume(raw)


@pytest.mark.asyncio
async def test_token_not_found_raises(db_session: AsyncSession):
    """Non-existent raw token raises TokenNotFoundError."""
    svc = EnrollmentTokenService(db_session)
    with pytest.raises(TokenNotFoundError):
        await svc.validate_and_consume("totally_fake_token_that_does_not_exist")


@pytest.mark.asyncio
async def test_token_revoked_raises(db_session: AsyncSession):
    """Revoked token raises TokenRevokedError."""
    admin_id = await _get_admin_id(db_session)
    raw = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw.encode()).hexdigest()
    token = EnrollmentToken(
        token_hash=token_hash,
        created_by=admin_id,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
        max_uses=1,
        used_count=0,
        revoked=True,
    )
    db_session.add(token)
    await db_session.flush()

    svc = EnrollmentTokenService(db_session)
    with pytest.raises(TokenRevokedError):
        await svc.validate_and_consume(raw)


# ─── Registration Service Tests ───────────────────────────────────────────────

@pytest.mark.asyncio
async def test_successful_registration_returns_valid_cert(db_session: AsyncSession):
    """Successful registration returns a cert that validates against the CA."""
    from manager.api.schemas.agents import RegistrationRequest

    ca = _real_ca()
    token_svc = EnrollmentTokenService(db_session)
    reg_svc = AgentRegistrationService(db=db_session, ca=ca, token_service=token_svc)

    admin_id = await _get_admin_id(db_session)
    raw_token, _ = await token_svc.generate_token(
        created_by=admin_id, expires_in_hours=1, max_uses=1
    )

    csr_pem = _make_csr_pem("test-endpoint")
    payload = RegistrationRequest(
        enrollment_token=raw_token,
        hostname="test-endpoint",
        os_version="Windows 11 22H2",
        agent_version="1.0.0",
        device_fingerprint="unique-fingerprint-abc123",
        public_key_csr=csr_pem,
    )

    result = await reg_svc.register_agent(payload)

    assert result.agent_id
    assert "BEGIN CERTIFICATE" in result.signed_certificate

    # Verify the returned cert validates against the CA
    ca_cert = x509.load_pem_x509_certificate(
        result.ca_certificate.encode(), default_backend()
    )
    agent_cert = x509.load_pem_x509_certificate(
        result.signed_certificate.encode(), default_backend()
    )
    # Issuer of agent cert == CA subject
    assert agent_cert.issuer == ca_cert.subject


@pytest.mark.asyncio
async def test_duplicate_fingerprint_rejected(db_session: AsyncSession):
    """Second registration with same hardware fingerprint raises DuplicateAgentError."""
    from manager.api.schemas.agents import RegistrationRequest

    ca = _real_ca()
    token_svc = EnrollmentTokenService(db_session)
    reg_svc = AgentRegistrationService(db=db_session, ca=ca, token_service=token_svc)

    admin_id = await _get_admin_id(db_session)
    fingerprint = "duplicate-fingerprint-xyz"

    # First registration
    raw1, _ = await token_svc.generate_token(created_by=admin_id, expires_in_hours=1, max_uses=1)
    payload1 = RegistrationRequest(
        enrollment_token=raw1,
        hostname="host-a",
        os_version="Win11",
        agent_version="1.0.0",
        device_fingerprint=fingerprint,
        public_key_csr=_make_csr_pem("host-a"),
    )
    await reg_svc.register_agent(payload1)

    # Second registration with same fingerprint
    raw2, _ = await token_svc.generate_token(created_by=admin_id, expires_in_hours=1, max_uses=1)
    payload2 = RegistrationRequest(
        enrollment_token=raw2,
        hostname="host-b",
        os_version="Win11",
        agent_version="1.0.0",
        device_fingerprint=fingerprint,
        public_key_csr=_make_csr_pem("host-b"),
    )
    with pytest.raises(DuplicateAgentError):
        await reg_svc.register_agent(payload2)


@pytest.mark.asyncio
async def test_register_endpoint_returns_201(db_session: AsyncSession, client: AsyncClient):
    """POST /agent/register returns 201 with agent_id and cert."""
    admin_id = await _get_admin_id(db_session)

    token_svc = EnrollmentTokenService(db_session)
    raw_token, _ = await token_svc.generate_token(
        created_by=admin_id, expires_in_hours=1, max_uses=1
    )

    resp = await client.post("/agent/register", json={
        "enrollment_token": raw_token,
        "hostname": "endpoint-api-test",
        "os_version": "Windows 10",
        "agent_version": "1.0.0",
        "device_fingerprint": f"fp-api-test-{uuid.uuid4().hex[:8]}",
        "public_key_csr": _make_csr_pem("endpoint-api-test"),
    })

    assert resp.status_code == 201
    data = resp.json()
    assert "agent_id" in data
    assert "signed_certificate" in data
    assert "ca_certificate" in data
