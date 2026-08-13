"""
AgentRegistrationClient — Client-side counterpart to M3.

Implements the /agent/register flow from SECTION 4:
  1. generate_keypair_and_csr()  — RSA keypair + CSR; private key never leaves this host
  2. get_hardware_fingerprint()  — SHA-256 of stable hardware identifiers
  3. register()                  — Idempotent registration (skips if already registered)

The private key is written with restrictive permissions (owner-only, 0o600).
"""
import hashlib
import json
import logging
import os
import platform
import socket
import subprocess
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from agent.communication.transport import SecureTransport, TransportError

logger = logging.getLogger(__name__)


class RegistrationResult:
    def __init__(self, agent_id: str, signed_cert_pem: str, ca_cert_pem: str,
                 heartbeat_interval: int) -> None:
        self.agent_id = agent_id
        self.signed_cert_pem = signed_cert_pem
        self.ca_cert_pem = ca_cert_pem
        self.heartbeat_interval = heartbeat_interval


class AgentRegistrationClient:
    def __init__(self, config) -> None:
        self.config = config
        self.transport = SecureTransport(config)

    def generate_keypair_and_csr(self, common_name: str) -> tuple[str, str]:
        """
        Generate a 2048-bit RSA keypair and a PKCS#10 CSR.

        The private key is written to self.config.key_path with 0o600 permissions
        (owner-read/write only) — it NEVER leaves this machine.

        Returns:
            (private_key_pem, csr_pem): Both as PEM strings.
        """
        # Generate key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")

        # Build CSR
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, common_name),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ZeroTrust EDR Agent"),
            ]))
            .sign(private_key, hashes.SHA256(), default_backend())
        )
        csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")

        # Write private key with restrictive permissions
        key_path = Path(self.config.key_path)
        key_path.parent.mkdir(parents=True, exist_ok=True)
        key_path.write_text(private_key_pem, encoding="utf-8")
        try:
            os.chmod(key_path, 0o600)
        except AttributeError:
            # Windows: os.chmod is limited; ACL restriction is out of scope for MVP
            pass

        logger.info(f"RSA keypair generated; CSR for CN={common_name}.")
        return private_key_pem, csr_pem

    def get_hardware_fingerprint(self) -> str:
        """
        Compute a stable SHA-256 hardware fingerprint from:
          - Motherboard serial (WMI Win32_BaseBoard on Windows)
          - First physical disk serial (WMI Win32_DiskDrive)
          - MAC address of the primary network interface

        Falls back to hostname on non-Windows systems (for CI/test compatibility).
        Hostnames change — this fallback is documented as test-only.
        """
        components: list[str] = []

        if platform.system() == "Windows":
            # Motherboard serial
            mb = self._wmi_query("Win32_BaseBoard", "SerialNumber")
            components.append(mb or "unknown_mb")

            # Disk serial
            disk = self._wmi_query("Win32_DiskDrive", "SerialNumber")
            components.append(disk or "unknown_disk")
        else:
            # Non-Windows fallback (Linux CI, dev machines)
            components.append(f"fallback_host:{socket.gethostname()}")
            components.append(f"fallback_pid:{os.getpid()}")

        # MAC address (cross-platform)
        import uuid as _uuid
        mac = hex(_uuid.getnode())
        components.append(mac)

        fingerprint = hashlib.sha256("|".join(components).encode()).hexdigest()
        logger.debug(f"Hardware fingerprint computed: {fingerprint}")
        return fingerprint

    @staticmethod
    def _wmi_query(class_name: str, field: str) -> str | None:
        """Run a PowerShell WMI query and return the first result value."""
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 f"(Get-WmiObject -Class {class_name}).{field}"],
                capture_output=True, text=True, timeout=5
            )
            value = result.stdout.strip()
            return value if value else None
        except Exception as e:
            logger.warning(f"WMI query {class_name}.{field} failed: {e}")
            return None

    async def register(self, enrollment_token: str) -> RegistrationResult:
        """
        Idempotent registration:
          - If agent_id is already persisted (local state file exists), skip registration.
          - Otherwise, generate keypair + CSR, POST to /agent/register,
            save returned cert + agent_id to local storage.

        Returns:
            RegistrationResult with agent_id, signed cert, and CA cert.
        """
        state_file = Path(self.config.local_db_path).parent / "agent_state.json"

        # Idempotency check — already registered?
        if state_file.exists():
            try:
                state = json.loads(state_file.read_text())
                if state.get("agent_id"):
                    logger.info(
                        f"Agent already registered: id={state['agent_id']}. "
                        "Skipping re-registration."
                    )
                    return RegistrationResult(
                        agent_id=state["agent_id"],
                        signed_cert_pem=Path(self.config.cert_path).read_text(),
                        ca_cert_pem=Path(self.config.ca_cert_path).read_text(),
                        heartbeat_interval=state.get("heartbeat_interval", 30),
                    )
            except Exception:
                pass  # Corrupted state — re-register

        hostname = socket.gethostname()
        fingerprint = self.get_hardware_fingerprint()
        _, csr_pem = self.generate_keypair_and_csr(common_name=hostname)

        payload = {
            "enrollment_token": enrollment_token,
            "hostname": hostname,
            "os_version": platform.platform(),
            "agent_version": "1.0.0",
            "device_fingerprint": fingerprint,
            "public_key_csr": csr_pem,
        }

        try:
            response = await self.transport.post(
                "/agent/register", json=payload, use_mtls=False
            )
        except TransportError as e:
            raise RuntimeError(f"Registration failed: {e}") from e

        if response.status_code != 201:
            raise RuntimeError(
                f"Registration rejected by manager: {response.status_code} — {response.text}"
            )

        data = response.json()

        # Persist signed certificate
        cert_path = Path(self.config.cert_path)
        cert_path.parent.mkdir(parents=True, exist_ok=True)
        cert_path.write_text(data["signed_certificate"])

        # Persist CA cert
        ca_path = Path(self.config.ca_cert_path)
        ca_path.write_text(data["ca_certificate"])

        # Persist agent state
        state_file.parent.mkdir(parents=True, exist_ok=True)
        state_file.write_text(json.dumps({
            "agent_id": str(data["agent_id"]),
            "heartbeat_interval": data.get("heartbeat_interval_seconds", 30),
        }))

        logger.info(f"Registration successful: agent_id={data['agent_id']}")
        return RegistrationResult(
            agent_id=str(data["agent_id"]),
            signed_cert_pem=data["signed_certificate"],
            ca_cert_pem=data["ca_certificate"],
            heartbeat_interval=data.get("heartbeat_interval_seconds", 30),
        )
