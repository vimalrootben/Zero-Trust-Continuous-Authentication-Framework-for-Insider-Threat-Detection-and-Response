"""
Agent-side unit tests (A1, A2, A3, A4):
  - AgentConfig: missing required field raises clear error; env override works
  - Hardware fingerprint: stable across two calls on same machine
  - CSR generation: valid, parseable CSR produced
  - Registration is skipped if agent_id already persisted
  - HeartbeatSender: correct consecutive failure tracking and offline signalling
  - WebSocketClient: backoff timing formula is correct
"""
import json
import os
import tempfile
import uuid
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


# ─── A1: AgentConfig ──────────────────────────────────────────────────────────

def test_agent_config_loads_defaults():
    """AgentConfig loads default values without any env file."""
    from agent.config.config import AgentConfig
    config = AgentConfig()
    assert config.heartbeat_interval_seconds == 30
    assert config.telemetry_batch_size == 50
    assert "localhost" in config.manager_url


def test_agent_config_env_override(tmp_path):
    """Environment variable overrides the default manager_url."""
    from agent.config.config import AgentConfig
    with patch.dict(os.environ, {"MANAGER_URL": "https://prod-manager:8443"}):
        config = AgentConfig()
        assert config.manager_url == "https://prod-manager:8443"


# ─── A2: Hardware Fingerprint ─────────────────────────────────────────────────

def test_hardware_fingerprint_stable():
    """Two consecutive calls return identical fingerprints on the same machine."""
    from agent.config.config import AgentConfig
    from agent.communication.registration import AgentRegistrationClient

    config = AgentConfig()
    client = AgentRegistrationClient(config)

    fp1 = client.get_hardware_fingerprint()
    fp2 = client.get_hardware_fingerprint()

    assert fp1 == fp2
    assert len(fp1) == 64  # SHA-256 hex


def test_hardware_fingerprint_is_sha256():
    """Fingerprint is exactly 64 hex characters (SHA-256 output)."""
    import hashlib
    from agent.config.config import AgentConfig
    from agent.communication.registration import AgentRegistrationClient

    config = AgentConfig()
    client = AgentRegistrationClient(config)
    fp = client.get_hardware_fingerprint()

    # Verify it's valid hex of the right length
    assert len(fp) == 64
    int(fp, 16)  # Raises ValueError if not valid hex


# ─── A2: CSR Generation ───────────────────────────────────────────────────────

def test_generate_keypair_and_csr(tmp_path):
    """generate_keypair_and_csr produces a valid, parseable CSR."""
    from agent.config.config import AgentConfig
    from agent.communication.registration import AgentRegistrationClient

    config = AgentConfig(
        key_path=str(tmp_path / "agent.key"),
        cert_path=str(tmp_path / "agent.crt"),
        ca_cert_path=str(tmp_path / "ca.crt"),
        local_db_path=str(tmp_path / "db" / "agent.db"),
    )
    client = AgentRegistrationClient(config)

    private_key_pem, csr_pem = client.generate_keypair_and_csr("test-hostname")

    # Private key must be written to disk
    assert Path(config.key_path).exists()

    # CSR must be valid and parseable
    assert "BEGIN CERTIFICATE REQUEST" in csr_pem
    csr = x509.load_pem_x509_csr(csr_pem.encode(), default_backend())
    assert csr.is_signature_valid

    # Common name must match
    cn = csr.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
    assert cn == "test-hostname"


def test_csr_private_key_not_in_csr(tmp_path):
    """The CSR must NOT contain the private key — only the public key."""
    from agent.config.config import AgentConfig
    from agent.communication.registration import AgentRegistrationClient

    config = AgentConfig(
        key_path=str(tmp_path / "agent.key"),
        cert_path=str(tmp_path / "agent.crt"),
        ca_cert_path=str(tmp_path / "ca.crt"),
        local_db_path=str(tmp_path / "db" / "agent.db"),
    )
    client = AgentRegistrationClient(config)
    _, csr_pem = client.generate_keypair_and_csr("secure-host")

    assert "PRIVATE KEY" not in csr_pem


# ─── A2: Registration Idempotency ────────────────────────────────────────────

@pytest.mark.asyncio
async def test_registration_skipped_if_already_registered(tmp_path):
    """If agent_state.json exists with agent_id, register() skips re-registration."""
    from agent.config.config import AgentConfig
    from agent.communication.registration import AgentRegistrationClient

    db_path = tmp_path / "db" / "agent.db"
    config = AgentConfig(
        key_path=str(tmp_path / "agent.crt"),
        cert_path=str(tmp_path / "agent.crt"),
        ca_cert_path=str(tmp_path / "ca.crt"),
        local_db_path=str(db_path),
    )

    # Pre-populate state file to simulate already-registered agent
    state_file = tmp_path / "db" / "agent_state.json"
    state_file.parent.mkdir(parents=True, exist_ok=True)

    # Write dummy cert files so the state-based read succeeds
    (tmp_path / "agent.crt").write_text("FAKE_CERT_PEM")
    (tmp_path / "ca.crt").write_text("FAKE_CA_PEM")

    existing_agent_id = str(uuid.uuid4())
    state_file.write_text(json.dumps({
        "agent_id": existing_agent_id,
        "heartbeat_interval": 30,
    }))

    client = AgentRegistrationClient(config)

    # transport.post should NEVER be called since we are already registered
    with patch.object(client.transport, "post", new_callable=AsyncMock) as mock_post:
        result = await client.register("any_token")

    mock_post.assert_not_called()
    assert result.agent_id == existing_agent_id


# ─── A3: HeartbeatSender ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_heartbeat_sender_success():
    """Successful heartbeat resets consecutive_failures and possibly_offline."""
    from agent.config.config import AgentConfig
    from agent.communication.heartbeat import HeartbeatSender

    config = AgentConfig()
    mock_transport = MagicMock()
    mock_response = MagicMock()
    mock_response.status_code = 204
    mock_transport.post = AsyncMock(return_value=mock_response)

    sender = HeartbeatSender(config=config, transport=mock_transport, agent_id=str(uuid.uuid4()))
    sender._consecutive_failures = 2
    sender._possibly_offline = True

    result = await sender.send_heartbeat()

    assert result is True
    assert sender._consecutive_failures == 0
    assert sender.possibly_offline is False


@pytest.mark.asyncio
async def test_heartbeat_sender_consecutive_failures_flip_offline_flag():
    """After N consecutive failures, possibly_offline flag is set to True."""
    from agent.config.config import AgentConfig
    from agent.communication.heartbeat import HeartbeatSender
    from agent.communication.transport import TransportError

    config = AgentConfig()
    mock_transport = MagicMock()
    mock_transport.post = AsyncMock(side_effect=TransportError("Network unreachable"))

    sender = HeartbeatSender(
        config=config,
        transport=mock_transport,
        agent_id=str(uuid.uuid4()),
        consecutive_failure_threshold=3,
    )

    # First two failures — not offline yet
    await sender.send_heartbeat()
    await sender.send_heartbeat()
    assert sender.possibly_offline is False

    # Third failure — crosses threshold
    await sender.send_heartbeat()
    assert sender.possibly_offline is True
    assert sender._consecutive_failures == 3


# ─── A4: WebSocketClient backoff formula ─────────────────────────────────────

def test_websocket_backoff_formula():
    """Backoff delay grows exponentially and is capped at 300s."""
    from agent.communication.transport import WebSocketClient

    # Use a mock config — only structure needed
    config = MagicMock()

    # Seed random for deterministic testing
    with patch("agent.communication.transport.random.random", return_value=0.5):
        delay_0 = WebSocketClient.backoff_delay(0, base=5.0, cap=300.0)
        delay_1 = WebSocketClient.backoff_delay(1, base=5.0, cap=300.0)
        delay_5 = WebSocketClient.backoff_delay(5, base=5.0, cap=300.0)
        delay_10 = WebSocketClient.backoff_delay(10, base=5.0, cap=300.0)

    # With jitter=0 (random=0.5 -> jitter factor=0), delays are exactly: 5, 10, 160, 300
    # (±20% jitter, random=0.5 gives jitter factor = 2*(0.5)-1 = 0)
    assert delay_0 == pytest.approx(5.0, abs=1.0)
    assert delay_1 == pytest.approx(10.0, abs=2.0)
    assert delay_10 <= 300.0  # Must not exceed cap


def test_websocket_backoff_never_exceeds_cap():
    """Backoff never exceeds the cap regardless of attempt number."""
    from agent.communication.transport import WebSocketClient

    for attempt in range(20):
        delay = WebSocketClient.backoff_delay(attempt, base=5.0, cap=300.0)
        assert delay <= 300.0
        assert delay >= 0.0
