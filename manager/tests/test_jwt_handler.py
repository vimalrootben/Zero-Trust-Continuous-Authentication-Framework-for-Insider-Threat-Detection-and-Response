import uuid
import time
import pytest
from manager.auth.jwt_handler import JWTHandler
from manager.auth.exceptions import ExpiredTokenError, InvalidTokenError

def test_jwt_handler_symmetric():
    """Test JWTHandler with HS256 (symmetric) secret key."""
    handler = JWTHandler(secret_or_private_key="super_secret_symmetric_key", algorithm="HS256")
    user_id = uuid.uuid4()
    
    # Create token
    token = handler.create_access_token(user_id, "admin", ["users:write"])
    assert isinstance(token, str)

    # Decode token
    payload = handler.decode_access_token(token)
    assert payload.user_id == user_id
    assert payload.role == "admin"
    assert "users:write" in payload.permissions


def test_jwt_handler_asymmetric(tmp_path):
    """Test JWTHandler with RS256 (asymmetric) keypair."""
    # Write custom private/public paths to temp dir
    priv_path = str(tmp_path / "test_jwt.key")
    pub_path = str(tmp_path / "test_jwt.pub")

    handler = JWTHandler(
        secret_or_private_key=priv_path,
        algorithm="RS256",
        public_key_path=pub_path
    )
    user_id = uuid.uuid4()

    # Verify keys were generated and written
    assert handler.private_key.startswith("-----BEGIN PRIVATE KEY-----")
    assert handler.public_key.startswith("-----BEGIN PUBLIC KEY-----")

    # Create access token
    token = handler.create_access_token(user_id, "soc_analyst", ["agents:read"])
    assert isinstance(token, str)

    # Decode access token
    payload = handler.decode_access_token(token)
    assert payload.user_id == user_id
    assert payload.role == "soc_analyst"
    assert "agents:read" in payload.permissions


def test_jwt_handler_token_expiry():
    """Test token expiration handling."""
    # Initialize with 0 minute expiry (expired instantly)
    handler = JWTHandler(secret_or_private_key="secret", algorithm="HS256", access_ttl_minutes=-5)
    user_id = uuid.uuid4()
    
    token = handler.create_access_token(user_id, "viewer", [])
    
    with pytest.raises(ExpiredTokenError):
        handler.decode_access_token(token)


def test_jwt_handler_invalid_signature():
    """Test invalid signatures and token manipulations."""
    handler1 = JWTHandler(secret_or_private_key="secret1", algorithm="HS256")
    handler2 = JWTHandler(secret_or_private_key="secret2", algorithm="HS256")
    user_id = uuid.uuid4()
    
    token = handler1.create_access_token(user_id, "viewer", [])
    
    # Decoded with wrong key should fail
    with pytest.raises(InvalidTokenError):
        handler2.decode_access_token(token)


def test_refresh_token_generation_and_verification():
    handler = JWTHandler(secret_or_private_key="secret", algorithm="HS256")
    raw_token, token_hash = handler.create_refresh_token()

    assert len(raw_token) == 64
    assert len(token_hash) == 64  # SHA-256 is 64 hex characters

    # Verify correct match
    assert handler.verify_refresh_token(raw_token, token_hash) is True
    # Verify mismatch
    assert handler.verify_refresh_token("incorrect_token", token_hash) is False
