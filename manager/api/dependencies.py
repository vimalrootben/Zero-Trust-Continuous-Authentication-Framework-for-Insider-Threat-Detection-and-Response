import time
import uuid
from typing import Generator, List, Callable
from collections import defaultdict
from fastapi import Request, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from manager.config import settings
from manager.database.session import get_db
from manager.database.models.auth import User
from manager.auth.jwt_handler import JWTHandler
from manager.auth.rbac import RBACService
from manager.auth.exceptions import ExpiredTokenError, InvalidTokenError

# Initialize global JWTHandler using config values
jwt_handler = JWTHandler(
    secret_or_private_key=settings.JWT_SECRET_KEY_PATH,
    algorithm=settings.JWT_ALGORITHM,
    access_ttl_minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES,
    refresh_ttl_days=settings.REFRESH_TOKEN_EXPIRE_DAYS,
    public_key_path=settings.JWT_PUBLIC_KEY_PATH
)

# Authentication token scheme
security = HTTPBearer()

# In-memory store for rate limiting: IP -> list of timestamps
_login_attempts = defaultdict(list)


def rate_limit_login(request: Request) -> None:
    """FastAPI dependency to rate limit requests.
    Allows a maximum of 10 requests per minute per IP.
    """
    ip = request.client.host if request.client else "127.0.0.1"
    now = time.time()
    
    # Filter attempts in the last 60 seconds
    attempts = [t for t in _login_attempts[ip] if now - t < 60]
    
    if len(attempts) >= 10:
        _login_attempts[ip] = attempts
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Please try again after a minute."
        )
    
    attempts.append(now)
    _login_attempts[ip] = attempts


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db)
) -> User:
    """Decodes access token from auth header and fetches corresponding User object.
    Raises:
        HTTPException(401): If token is expired, invalid, or user does not exist.
        HTTPException(403): If user account is inactive.
    """
    token = credentials.credentials
    try:
        payload = jwt_handler.decode_access_token(token)
    except ExpiredTokenError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"}
        ) from e
    except InvalidTokenError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"}
        ) from e

    # Fetch User
    query = select(User).where(User.id == payload.user_id)
    result = await db.execute(query)
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"}
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive"
        )

    return user


def require_permission(permission_code: str) -> Callable:
    """Gating mechanism that requires the caller to possess a specific permission code.
    If settings.FORCE_DB_CHECK is False, claims embedded in the JWT are trusted.
    If True, the database is queried using RBACService to verify the user has the permission.
    """
    async def permission_dependency(
        credentials: HTTPAuthorizationCredentials = Depends(security),
        db: AsyncSession = Depends(get_db)
    ) -> None:
        token = credentials.credentials
        try:
            payload = jwt_handler.decode_access_token(token)
        except (ExpiredTokenError, InvalidTokenError) as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication failed",
                headers={"WWW-Authenticate": "Bearer"}
            ) from e

        # If admin role bypass is in place
        if payload.role == "admin":
            return

        # Gating logic
        if settings.FORCE_DB_CHECK:
            rbac = RBACService(db)
            has_perm = await rbac.user_has_permission(payload.user_id, permission_code)
            if not has_perm:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access denied: insufficient permissions"
                )
        else:
            # Check JWT claims permissions list
            if permission_code not in payload.permissions:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access denied: insufficient permissions"
                )

    return permission_dependency
