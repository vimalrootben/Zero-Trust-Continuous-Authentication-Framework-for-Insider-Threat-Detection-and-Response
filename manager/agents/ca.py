"""
CertificateAuthority — Signs incoming agent CSRs and manages certificate revocation.

Uses the project's local dev CA (certificates/ca.crt + ca.key) to produce
per-agent TLS client certificates for mTLS authentication.
"""
import hashlib
import logging
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

from manager.agents.exceptions import InvalidCSRError

logger = logging.getLogger(__name__)


class CertificateAuthority:
    """
    Signs agent CSR requests using the Manager's local CA.

    The private key NEVER leaves the manager host.
    The agent sends only a CSR (public key + identity), and receives
    a signed certificate in return.
    """

    def __init__(self, ca_cert_path: str, ca_key_path: str) -> None:
        self.ca_cert_path = ca_cert_path
        self.ca_key_path = ca_key_path
        self._ca_cert: x509.Certificate | None = None
        self._ca_key = None
        self._load_ca()

    def _load_ca(self) -> None:
        """Load the CA certificate and private key from disk."""
        try:
            with open(self.ca_cert_path, "rb") as f:
                self._ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            with open(self.ca_key_path, "rb") as f:
                self._ca_key = serialization.load_pem_private_key(
                    f.read(), password=None, backend=default_backend()
                )
            logger.info("CA certificate and key loaded successfully.")
        except FileNotFoundError as e:
            logger.critical(f"CA file not found: {e}. Agent registration will fail.")
            raise

    def sign_csr(self, csr_pem: str, common_name: str, valid_days: int = 365) -> str:
        """
        Sign an agent's CSR and return a signed certificate in PEM format.

        Args:
            csr_pem: PEM-encoded Certificate Signing Request from agent.
            common_name: The agent's common name (typically agent_id or hostname).
            valid_days: Certificate validity period in days.

        Returns:
            PEM-encoded signed certificate string.

        Raises:
            InvalidCSRError: If the CSR is malformed or cannot be loaded.
        """
        try:
            csr = x509.load_pem_x509_csr(csr_pem.encode(), default_backend())
        except Exception as e:
            raise InvalidCSRError(f"Invalid CSR format: {e}") from e

        if not csr.is_signature_valid:
            raise InvalidCSRError("CSR signature is invalid.")

        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, common_name),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ZeroTrust EDR Agent"),
            ]))
            .issuer_name(self._ca_cert.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=valid_days))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
            .add_extension(
                x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=False,
            )
            .sign(self._ca_key, hashes.SHA256(), default_backend())
        )

        logger.info(f"Signed certificate for CN={common_name}, valid {valid_days} days.")
        return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")

    def get_fingerprint(self, cert_pem: str) -> str:
        """Compute the SHA-256 fingerprint of a PEM certificate."""
        cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
        return cert.fingerprint(hashes.SHA256()).hex()

    def get_ca_pem(self) -> str:
        """Return the CA certificate in PEM format for the agent to trust."""
        return self._ca_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")

    def revoke_certificate(self, cert_fingerprint: str) -> None:
        """
        Mark a certificate fingerprint as revoked.

        In production this would update a CRL file. For this project,
        revocation is enforced at the DB level (agents.status = 'decommissioned').
        The TLS layer (nginx/Traefik) should also serve the CRL for full enforcement.
        """
        logger.info(f"Certificate revoked: fingerprint={cert_fingerprint}")
        # CRL file management would be wired here in a production hardened system
