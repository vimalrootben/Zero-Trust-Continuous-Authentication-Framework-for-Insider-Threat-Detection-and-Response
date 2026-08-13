import os
import secrets
import hashlib
import hmac
import uuid
from datetime import datetime, timedelta, timezone
from typing import Tuple, Union
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from manager.auth.models import TokenPayload
from manager.auth.exceptions import ExpiredTokenError, InvalidTokenError

class JWTHandler:
    """Handles JWT generation, rotation, and validation.
    Supports both RS256 (asymmetric) and HS256 (symmetric) algorithms.
    If using RS256, it can dynamically load or generate keys from paths.
    """

    def __init__(
        self,
        secret_or_private_key: str,
        algorithm: str = "RS256",
        access_ttl_minutes: int = 15,
        refresh_ttl_days: int = 7,
        public_key_path: str = None
    ):
        self.algorithm = algorithm
        self.access_ttl_minutes = access_ttl_minutes
        self.refresh_ttl_days = refresh_ttl_days
        
        # Resolve keys
        self.private_key = None
        self.public_key = None

        if self.algorithm == "RS256":
            self._load_or_generate_rsa_keys(secret_or_private_key, public_key_path)
        else:
            # HS256 or other symmetric algorithm
            self.private_key = secret_or_private_key
            self.public_key = secret_or_private_key

    def _load_or_generate_rsa_keys(self, private_key_input: str, public_key_path: str = None):
        """Loads RSA keys from PEM string or file paths, generating them if missing."""
        # 1. Check if private_key_input is direct PEM content
        if private_key_input and ("-----BEGIN" in private_key_input or "-----BEGIN PRIVATE KEY-----" in private_key_input):
            self.private_key = private_key_input
            # Extract public key from private key
            pkey_obj = serialization.load_pem_private_key(private_key_input.encode(), password=None)
            pub_bytes = pkey_obj.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            self.public_key = pub_bytes.decode()
            return

        # 2. Otherwise treat private_key_input as a file path (or default path)
        private_key_path = private_key_input or "manager/certs/jwt_rs256.key"
        if not public_key_path:
            public_key_path = os.path.splitext(private_key_path)[0] + ".pub"

        # Check if the private key file exists
        if os.path.exists(private_key_path):
            with open(private_key_path, "r") as f:
                self.private_key = f.read()
            if os.path.exists(public_key_path):
                with open(public_key_path, "r") as f:
                    self.public_key = f.read()
            else:
                # Derive public key if file is missing
                pkey_obj = serialization.load_pem_private_key(self.private_key.encode(), password=None)
                pub_bytes = pkey_obj.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                self.public_key = pub_bytes.decode()
        else:
            # Generate a new key pair
            os.makedirs(os.path.dirname(os.path.abspath(private_key_path)), exist_ok=True)
            
            # Generate RSA key pair
            pkey_obj = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            
            # Serialize keys
            priv_bytes = pkey_obj.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            pub_bytes = pkey_obj.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            self.private_key = priv_bytes.decode()
            self.public_key = pub_bytes.decode()

            # Write keys to disk if a path is present
            try:
                with open(private_key_path, "w") as f:
                    f.write(self.private_key)
                with open(public_key_path, "w") as f:
                    f.write(self.public_key)
            except IOError:
                # Fail-safe: Keep keys in memory if directory is not writable during test setup
                pass

    def create_access_token(self, user_id: uuid.UUID, role: str, permissions: list[str]) -> str:
        """Creates a signed JWT access token."""
        now = datetime.now(timezone.utc)
        payload = {
            "jti": str(uuid.uuid4()),
            "sub": str(user_id),
            "role": role,
            "permissions": permissions,
            "exp": int((now + timedelta(minutes=self.access_ttl_minutes)).timestamp()),
            "iat": int(now.timestamp())
        }
        return jwt.encode(payload, self.private_key, algorithm=self.algorithm)

    def create_refresh_token(self) -> Tuple[str, str]:
        """Generates a secure random refresh token.
        Returns:
            Tuple[str, str]: (raw_token, sha256_hash_to_store)
        """
        raw_token = secrets.token_hex(32)
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        return raw_token, token_hash

    def decode_access_token(self, token: str) -> TokenPayload:
        """Decodes and validates a JWT access token.
        Raises:
            ExpiredTokenError: If the token is expired.
            InvalidTokenError: If the token signature or claims are invalid.
        """
        try:
            # pyjwt raises ExpiredSignatureError when the token has expired
            payload = jwt.decode(token, self.public_key, algorithms=[self.algorithm])
            
            # Build and validate TokenPayload
            return TokenPayload(
                sub=uuid.UUID(payload["sub"]),
                role=payload["role"],
                permissions=payload["permissions"],
                exp=payload["exp"]
            )
        except jwt.ExpiredSignatureError as e:
            raise ExpiredTokenError("Access token has expired") from e
        except (jwt.InvalidTokenError, KeyError, ValueError) as e:
            raise InvalidTokenError("Invalid access token") from e

    def verify_refresh_token(self, raw_token: str, stored_hash: str) -> bool:
        """Securely verifies a raw refresh token against its stored SHA-256 hash."""
        computed_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        return hmac.compare_digest(computed_hash, stored_hash)
