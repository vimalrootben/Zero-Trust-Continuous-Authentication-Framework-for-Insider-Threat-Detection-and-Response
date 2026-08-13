from fastapi import APIRouter, Depends, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession
from manager.api.dependencies import get_db, get_current_user, rate_limit_login, jwt_handler
from manager.api.schemas.auth import (
    LoginRequest,
    LoginResponse,
    RefreshRequest,
    RefreshResponse,
    ChangePasswordRequest,
    ConfirmMFARequest,
    MFAEnableResponse,
    UserPublic,
)
from manager.auth.password_handler import PasswordHandler
from manager.auth.services import AuthService
from manager.database.models.auth import User

router = APIRouter(prefix="/auth", tags=["Authentication"])


def get_auth_service(db: AsyncSession = Depends(get_db)) -> AuthService:
    """Dependency helper to instantiate the AuthService."""
    password_handler = PasswordHandler()
    return AuthService(db, password_handler, jwt_handler)


@router.post(
    "/login",
    response_model=LoginResponse,
    dependencies=[Depends(rate_limit_login)],
    summary="Authenticate user and issue access and refresh tokens."
)
async def login(
    request: Request,
    payload: LoginRequest,
    auth_service: AuthService = Depends(get_auth_service)
):
    ip = request.client.host if request.client else "127.0.0.1"
    user_agent = request.headers.get("user-agent", "")
    
    return await auth_service.login(
        username=payload.username,
        password=payload.password,
        totp_code=payload.totp_code,
        ip=ip,
        user_agent=user_agent
    )


@router.post(
    "/refresh",
    response_model=RefreshResponse,
    summary="Rotate refresh token and issue a new access token."
)
async def refresh(
    request: Request,
    payload: RefreshRequest,
    auth_service: AuthService = Depends(get_auth_service)
):
    ip = request.client.host if request.client else "127.0.0.1"
    user_agent = request.headers.get("user-agent", "")
    
    return await auth_service.refresh(
        raw_refresh_token=payload.refresh_token,
        ip=ip,
        user_agent=user_agent
    )


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke user session."
)
async def logout(
    request: Request,
    payload: RefreshRequest,
    auth_service: AuthService = Depends(get_auth_service)
):
    ip = request.client.host if request.client else "127.0.0.1"
    await auth_service.logout(raw_refresh_token=payload.refresh_token, ip=ip)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/change-password",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Change user password."
)
async def change_password(
    payload: ChangePasswordRequest,
    current_user: User = Depends(get_current_user),
    auth_service: AuthService = Depends(get_auth_service)
):
    await auth_service.change_password(
        user_id=current_user.id,
        old_password=payload.old_password,
        new_password=payload.new_password
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/mfa/enable",
    response_model=MFAEnableResponse,
    summary="Initialize TOTP multi-factor authentication."
)
async def enable_mfa(
    current_user: User = Depends(get_current_user),
    auth_service: AuthService = Depends(get_auth_service)
):
    return await auth_service.enable_mfa(user_id=current_user.id)


@router.post(
    "/mfa/confirm",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Confirm first TOTP code and enable MFA."
)
async def confirm_mfa(
    payload: ConfirmMFARequest,
    current_user: User = Depends(get_current_user),
    auth_service: AuthService = Depends(get_auth_service)
):
    await auth_service.confirm_mfa(user_id=current_user.id, totp_code=payload.totp_code)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get(
    "/me",
    response_model=UserPublic,
    summary="Get current user details."
)
async def get_me(current_user: User = Depends(get_current_user)):
    return current_user
