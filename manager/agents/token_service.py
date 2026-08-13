"""
EnrollmentTokenService — Generates, validates, and atomically consumes one-time enrollment tokens.

Tokens are never stored in plain text — only their SHA-256 hash is persisted.
Atomic consumption uses an UPDATE ... WHERE used_count < max_uses to prevent
race conditions under concurrent registration requests.
"""
import hashlib
import logging
import secrets
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from manager.database.models.agent import EnrollmentToken
from manager.agents.exceptions import (
    TokenExpiredError,
    TokenExhaustedError,
    TokenNotFoundError,
    TokenRevokedError,
)

logger = logging.getLogger(__name__)


def _hash_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode()).hexdigest()


class EnrollmentTokenService:
    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def generate_token(
        self,
        created_by: uuid.UUID,
        expires_in_hours: int = 24,
        max_uses: int = 1,
    ) -> tuple[str, EnrollmentToken]:
        """
        Create and persist a new enrollment token.

        Returns:
            (raw_token, EnrollmentToken): raw token shown ONCE to admin;
            only the hash is stored. The caller must return raw_token to the admin.
        """
        raw_token = secrets.token_urlsafe(32)
        token_hash = _hash_token(raw_token)
        expires_at = datetime.now(timezone.utc) + timedelta(hours=expires_in_hours)

        token_obj = EnrollmentToken(
            token_hash=token_hash,
            created_by=created_by,
            expires_at=expires_at,
            max_uses=max_uses,
            used_count=0,
            revoked=False,
        )
        self.db.add(token_obj)
        await self.db.flush()

        logger.info(
            f"Enrollment token created: id={token_obj.id}, "
            f"by={created_by}, expires={expires_at}, max_uses={max_uses}"
        )
        return raw_token, token_obj

    async def validate_and_consume(self, raw_token: str) -> EnrollmentToken:
        """
        Validate the token and atomically increment used_count.

        Uses a DB-level UPDATE ... WHERE used_count < max_uses to prevent
        race conditions under concurrent registration requests.

        Raises:
            TokenNotFoundError: Token hash not found in DB.
            TokenRevokedError: Token has been manually revoked.
            TokenExpiredError: Token expiry time has passed.
            TokenExhaustedError: Token has been fully consumed (used_count >= max_uses).
        """
        token_hash = _hash_token(raw_token)

        # Load the token record
        result = await self.db.execute(
            select(EnrollmentToken).where(EnrollmentToken.token_hash == token_hash)
        )
        token = result.scalar_one_or_none()

        if token is None:
            raise TokenNotFoundError("Enrollment token not found.")

        if token.revoked:
            raise TokenRevokedError("Enrollment token has been revoked.")

        now = datetime.now(timezone.utc)
        # Make expires_at timezone-aware if it isn't
        expires_at = token.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        if now > expires_at:
            raise TokenExpiredError("Enrollment token has expired.")

        if token.used_count >= token.max_uses:
            raise TokenExhaustedError("Enrollment token has been fully consumed.")

        # Atomic increment — only succeeds if used_count < max_uses
        result = await self.db.execute(
            update(EnrollmentToken)
            .where(
                EnrollmentToken.id == token.id,
                EnrollmentToken.used_count < EnrollmentToken.max_uses,
                EnrollmentToken.revoked == False,  # noqa: E712
            )
            .values(used_count=EnrollmentToken.used_count + 1)
            .returning(EnrollmentToken.used_count)
        )
        updated_count = result.scalar_one_or_none()

        if updated_count is None:
            # Another concurrent request consumed the last slot
            raise TokenExhaustedError("Enrollment token has been fully consumed (concurrent race).")

        # Refresh the in-session object
        await self.db.refresh(token)

        logger.info(
            f"Enrollment token consumed: id={token.id}, "
            f"used_count={token.used_count}/{token.max_uses}"
        )
        return token
