import uuid
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional
import pyotp
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from manager.database.models.auth import User, Session as UserSession
from manager.database.models.audit import AuditLog, ActorType
from manager.auth.password_handler import PasswordHandler
from manager.auth.jwt_handler import JWTHandler
from manager.auth.exceptions import (
    InvalidCredentialsError,
    AccountLockedError,
    AccountInactiveError,
    MFARequiredError,
    InvalidMFACodeError,
    InvalidRefreshTokenError,
)

class AuthService:
    """Orchestrates identity and authentication workflows including credentials checks,
    MFA, lockouts, refresh token rotation, and audit logging.
    """

    def __init__(
        self,
        db_session: AsyncSession,
        password_handler: PasswordHandler,
        jwt_handler: JWTHandler
    ):
        self.db = db_session
        self.password_handler = password_handler
        self.jwt_handler = jwt_handler

    async def _log_audit(
        self,
        actor_type: ActorType,
        actor_id: Optional[uuid.UUID],
        action: str,
        target_type: Optional[str],
        target_id: Optional[uuid.UUID],
        details_json: Optional[Dict[str, Any]],
        ip: str
    ) -> None:
        """Helper to create and persist an audit log entry."""
        audit = AuditLog(
            actor_type=actor_type,
            actor_id=actor_id,
            action=action,
            target_type=target_type,
            target_id=target_id,
            details_json=details_json,
            ip_address=ip,
            timestamp=datetime.now(timezone.utc)
        )
        self.db.add(audit)
        await self.db.flush()

    async def login(
        self,
        username: str,
        password: str,
        totp_code: Optional[str],
        ip: str,
        user_agent: str
    ) -> Dict[str, Any]:
        """Authenticates a user.
        Validates credentials, checks account status (inactive, locked), enforces TOTP MFA,
        tracks failed login attempts, updates locks, establishes a session, and issues tokens.
        """
        # Fetch user
        query = select(User).where(User.username == username)
        result = await self.db.execute(query)
        user = result.scalar_one_or_none()

        if not user:
            # Audit failed attempt for non-existing username
            await self._log_audit(
                actor_type=ActorType.USER,
                actor_id=None,
                action="auth.login.failed",
                target_type="user",
                target_id=None,
                details_json={"username": username, "reason": "user_not_found"},
                ip=ip
            )
            raise InvalidCredentialsError()

        # Check is_active
        if not user.is_active:
            await self._log_audit(
                actor_type=ActorType.USER,
                actor_id=user.id,
                action="auth.login.failed",
                target_type="user",
                target_id=user.id,
                details_json={"reason": "account_inactive"},
                ip=ip
            )
            raise AccountInactiveError()

        # Check account lockout status
        now = datetime.now(timezone.utc)
        if user.locked_until:
            # If locked_until is timezone-naive, make it timezone-aware or vice versa.
            # Our models use DateTime(timezone=True) so it is timezone-aware.
            locked_until = user.locked_until
            if locked_until.tzinfo is None:
                locked_until = locked_until.replace(tzinfo=timezone.utc)
            
            if locked_until > now:
                await self._log_audit(
                    actor_type=ActorType.USER,
                    actor_id=user.id,
                    action="auth.login.locked",
                    target_type="user",
                    target_id=user.id,
                    details_json={"reason": "account_locked"},
                    ip=ip
                )
                raise AccountLockedError()
            else:
                # Lock has expired, reset attempts
                user.locked_until = None
                user.failed_login_attempts = 0
                await self.db.flush()

        # Verify password
        if not self.password_handler.verify_password(password, user.password_hash):
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= 5:
                user.locked_until = now + timedelta(minutes=15)
                await self._log_audit(
                    actor_type=ActorType.USER,
                    actor_id=user.id,
                    action="auth.login.locked",
                    target_type="user",
                    target_id=user.id,
                    details_json={"reason": "lockout_triggered"},
                    ip=ip
                )
            else:
                await self._log_audit(
                    actor_type=ActorType.USER,
                    actor_id=user.id,
                    action="auth.login.failed",
                    target_type="user",
                    target_id=user.id,
                    details_json={"reason": "invalid_password", "failed_attempts": user.failed_login_attempts},
                    ip=ip
                )
            await self.db.flush()
            
            if user.failed_login_attempts >= 5:
                raise AccountLockedError()
            else:
                raise InvalidCredentialsError()

        # Verify TOTP MFA if enabled
        if user.mfa_enabled:
            if not totp_code:
                raise MFARequiredError(user_id=str(user.id))
            
            totp = pyotp.TOTP(user.mfa_secret)
            if not totp.verify(totp_code):
                await self._log_audit(
                    actor_type=ActorType.USER,
                    actor_id=user.id,
                    action="auth.login.failed",
                    target_type="user",
                    target_id=user.id,
                    details_json={"reason": "invalid_mfa_code"},
                    ip=ip
                )
                raise InvalidMFACodeError()

        # Reset failed login parameters
        user.failed_login_attempts = 0
        user.locked_until = None
        user.last_login_at = now
        await self.db.flush()

        # Generate refresh token
        raw_refresh, refresh_hash = self.jwt_handler.create_refresh_token()
        session_expires = now + timedelta(days=self.jwt_handler.refresh_ttl_days)

        # Create session row
        session = UserSession(
            user_id=user.id,
            refresh_token_hash=refresh_hash,
            issued_at=now,
            expires_at=session_expires,
            revoked=False,
            user_agent=user_agent,
            ip_address=ip
        )
        self.db.add(session)
        await self.db.flush()

        # Generate access token
        role_name = user.role.name if user.role else "viewer"
        permissions = [perm.code for perm in user.role.permissions] if user.role else []
        access_token = self.jwt_handler.create_access_token(user.id, role_name, permissions)

        await self._log_audit(
            actor_type=ActorType.USER,
            actor_id=user.id,
            action="auth.login.success",
            target_type="user",
            target_id=user.id,
            details_json={"session_id": str(session.id)},
            ip=ip
        )

        return {
            "access_token": access_token,
            "refresh_token": raw_refresh,
            "token_type": "bearer",
            "expires_in": self.jwt_handler.access_ttl_minutes * 60,
            "user": user
        }

    async def refresh(self, raw_refresh_token: str, ip: str = None, user_agent: str = None) -> Dict[str, Any]:
        """Rotates the refresh token (Refresh Token Rotation) and issues a new access token.
        Raises InvalidRefreshTokenError if the token is revoked, expired, or invalid.
        """
        token_hash = hashlib.sha256(raw_refresh_token.encode()).hexdigest()
        
        # Query active session
        query = select(UserSession).where(UserSession.refresh_token_hash == token_hash)
        result = await self.db.execute(query)
        session = result.scalar_one_or_none()

        now = datetime.now(timezone.utc)
        if not session or session.revoked or session.expires_at.replace(tzinfo=timezone.utc) < now:
            await self._log_audit(
                actor_type=ActorType.SYSTEM,
                actor_id=None,
                action="auth.token.invalid",
                target_type="session",
                target_id=None,
                details_json={"reason": "session_not_found_or_expired_or_revoked"},
                ip=ip or "0.0.0.0"
            )
            raise InvalidRefreshTokenError()

        # Fetch user details
        user_query = select(User).where(User.id == session.user_id)
        user_result = await self.db.execute(user_query)
        user = user_result.scalar_one_or_none()

        if not user or not user.is_active:
            raise InvalidRefreshTokenError()

        # Mark old session as revoked (Rotate)
        session.revoked = True
        await self.db.flush()

        # Generate a new session
        new_raw_refresh, new_refresh_hash = self.jwt_handler.create_refresh_token()
        new_session = UserSession(
            user_id=user.id,
            refresh_token_hash=new_refresh_hash,
            issued_at=now,
            expires_at=now + timedelta(days=self.jwt_handler.refresh_ttl_days),
            revoked=False,
            user_agent=user_agent or session.user_agent,
            ip_address=ip or session.ip_address
        )
        self.db.add(new_session)
        await self.db.flush()

        # Issue new access token
        role_name = user.role.name if user.role else "viewer"
        permissions = [perm.code for perm in user.role.permissions] if user.role else []
        new_access_token = self.jwt_handler.create_access_token(user.id, role_name, permissions)

        await self._log_audit(
            actor_type=ActorType.USER,
            actor_id=user.id,
            action="auth.token.refreshed",
            target_type="session",
            target_id=new_session.id,
            details_json={"old_session_id": str(session.id), "new_session_id": str(new_session.id)},
            ip=ip or "0.0.0.0"
        )

        return {
            "access_token": new_access_token,
            "refresh_token": new_raw_refresh,
            "token_type": "bearer",
            "expires_in": self.jwt_handler.access_ttl_minutes * 60,
            "user": user
        }

    async def logout(self, raw_refresh_token: str, ip: str = None) -> None:
        """Revokes a session via its raw refresh token."""
        token_hash = hashlib.sha256(raw_refresh_token.encode()).hexdigest()
        query = select(UserSession).where(UserSession.refresh_token_hash == token_hash)
        result = await self.db.execute(query)
        session = result.scalar_one_or_none()

        if session:
            session.revoked = True
            await self.db.flush()
            await self._log_audit(
                actor_type=ActorType.USER,
                actor_id=session.user_id,
                action="auth.logout",
                target_type="session",
                target_id=session.id,
                details_json=None,
                ip=ip or "0.0.0.0"
            )

    async def change_password(self, user_id: uuid.UUID, old_password: str, new_password: str) -> None:
        """Changes user password after validating complexity and checking the current password."""
        query = select(User).where(User.id == user_id)
        result = await self.db.execute(query)
        user = result.scalar_one_or_none()

        if not user:
            raise ValueError("User not found")

        # Verify old password
        if not self.password_handler.verify_password(old_password, user.password_hash):
            raise InvalidCredentialsError("Incorrect current password")

        # Hash and save new password
        user.password_hash = self.password_handler.hash_password(new_password)
        await self.db.flush()

        await self._log_audit(
            actor_type=ActorType.USER,
            actor_id=user.id,
            action="auth.password.changed",
            target_type="user",
            target_id=user.id,
            details_json=None,
            ip="0.0.0.0"
        )

    async def enable_mfa(self, user_id: uuid.UUID) -> Dict[str, str]:
        """Generates a new TOTP secret and provisioning URI for a user."""
        query = select(User).where(User.id == user_id)
        result = await self.db.execute(query)
        user = result.scalar_one_or_none()

        if not user:
            raise ValueError("User not found")

        # Generate TOTP secret
        secret = pyotp.random_base32()
        user.mfa_secret = secret
        await self.db.flush()

        totp = pyotp.totp.TOTP(secret)
        provisioning_uri = totp.provisioning_uri(name=user.email, issuer_name="ZeroTrustEDR")

        return {
            "secret": secret,
            "provisioning_uri": provisioning_uri
        }

    async def confirm_mfa(self, user_id: uuid.UUID, totp_code: str) -> None:
        """Confirms and enables MFA for the user after successfully verifying a TOTP code."""
        query = select(User).where(User.id == user_id)
        result = await self.db.execute(query)
        user = result.scalar_one_or_none()

        if not user or not user.mfa_secret:
            raise InvalidMFACodeError("MFA setup is not initialized")

        totp = pyotp.TOTP(user.mfa_secret)
        if not totp.verify(totp_code):
            raise InvalidMFACodeError("Invalid TOTP code")

        user.mfa_enabled = True
        await self.db.flush()

        await self._log_audit(
            actor_type=ActorType.USER,
            actor_id=user.id,
            action="auth.mfa.enabled",
            target_type="user",
            target_id=user.id,
            details_json=None,
            ip="0.0.0.0"
        )
