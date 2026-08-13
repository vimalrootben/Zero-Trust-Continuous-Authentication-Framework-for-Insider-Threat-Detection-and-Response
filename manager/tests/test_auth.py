import uuid
from datetime import datetime, timedelta, timezone
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from manager.database.models.auth import Permission, Role, User, Session as UserSession
from manager.database.models.audit import AuditLog
from manager.auth.password_handler import PasswordHandler
from manager.auth.services import AuthService
from manager.api.dependencies import jwt_handler

@pytest.mark.asyncio
async def test_auth_login_success(db_session: AsyncSession, client: AsyncClient):
    ph = PasswordHandler()
    
    # Retrieve existing seeded admin role
    role_res = await db_session.execute(select(Role).where(Role.name == "admin"))
    role = role_res.scalar_one()

    # Create test user linked to seeded admin role
    pw_hash = ph.hash_password("AdminSecure123!")
    user = User(
        username="admin_login_test",
        email="admin_test@zerotrust.local",
        password_hash=pw_hash,
        is_active=True,
        role_id=role.id
    )
    db_session.add(user)
    await db_session.flush()

    # Hit Login API
    response = await client.post(
        "/api/v1/auth/login",
        json={"username": "admin_login_test", "password": "AdminSecure123!"}
    )
    
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["user"]["username"] == "admin_login_test"
    assert data["user"]["role"] == "admin"


@pytest.mark.asyncio
async def test_auth_login_incorrect_password_lockout(db_session: AsyncSession, client: AsyncClient):
    ph = PasswordHandler()
    
    # Create user
    pw_hash = ph.hash_password("AdminSecure123!")
    user = User(
        username="lockout_test",
        email="lockout@test.local",
        password_hash=pw_hash,
        is_active=True
    )
    db_session.add(user)
    await db_session.flush()

    # Hit login with wrong password 4 times
    for _ in range(4):
        response = await client.post(
            "/api/v1/auth/login",
            json={"username": "lockout_test", "password": "WrongPassword123!"}
        )
        assert response.status_code == 401
        assert response.json()["error"]["code"] == "InvalidCredentialsError"

    # Refresh DB session state
    await db_session.refresh(user)
    assert user.failed_login_attempts == 4
    assert user.locked_until is None

    # 5th failed login attempt -> Lockout!
    response = await client.post(
        "/api/v1/auth/login",
        json={"username": "lockout_test", "password": "WrongPassword123!"}
    )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "AccountLockedError"

    # Refresh and verify locked_until is set
    await db_session.refresh(user)
    assert user.failed_login_attempts == 5
    assert user.locked_until is not None


@pytest.mark.asyncio
async def test_refresh_token_rotation(db_session: AsyncSession, client: AsyncClient):
    ph = PasswordHandler()
    
    # Create user
    pw_hash = ph.hash_password("AdminSecure123!")
    user = User(
        username="refresh_test",
        email="refresh@test.local",
        password_hash=pw_hash,
        is_active=True
    )
    db_session.add(user)
    await db_session.flush()

    # Initial Login
    login_res = await client.post(
        "/api/v1/auth/login",
        json={"username": "refresh_test", "password": "AdminSecure123!"}
    )
    assert login_res.status_code == 200
    tokens = login_res.json()
    first_refresh = tokens["refresh_token"]

    # Refresh tokens using first refresh token
    refresh_res = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": first_refresh}
    )
    assert refresh_res.status_code == 200
    new_tokens = refresh_res.json()
    assert new_tokens["access_token"] != tokens["access_token"]
    assert new_tokens["refresh_token"] != first_refresh

    # Try reusing the first refresh token (should be revoked and fail)
    reuse_res = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": first_refresh}
    )
    assert reuse_res.status_code == 401
    assert reuse_res.json()["error"]["code"] == "InvalidRefreshTokenError"


@pytest.mark.asyncio
async def test_rate_limiting_on_login(db_session: AsyncSession, client: AsyncClient):
    # Hit login endpoint 12 times quickly. 11th and 12th should trigger rate limit (429)
    # The default rate limit we set is 10/minute
    statuses = []
    for _ in range(12):
        res = await client.post(
            "/api/v1/auth/login",
            json={"username": "non_existent", "password": "password123"}
        )
        statuses.append(res.status_code)

    assert 429 in statuses


@pytest.mark.asyncio
async def test_rbac_permission_gating_api(db_session: AsyncSession, client: AsyncClient):
    ph = PasswordHandler()
    
    # Retrieve existing seeded analyst and viewer roles
    analyst_res = await db_session.execute(select(Role).where(Role.name == "soc_analyst"))
    role_analyst = analyst_res.scalar_one()

    viewer_res = await db_session.execute(select(Role).where(Role.name == "viewer"))
    role_viewer = viewer_res.scalar_one()

    # Create users
    user_analyst = User(
        username="analyst_api",
        email="analyst_api@test.local",
        password_hash=ph.hash_password("AdminSecure123!"),
        is_active=True,
        role_id=role_analyst.id
    )
    user_viewer = User(
        username="viewer_api",
        email="viewer_api@test.local",
        password_hash=ph.hash_password("AdminSecure123!"),
        is_active=True,
        role_id=role_viewer.id
    )
    db_session.add_all([user_analyst, user_viewer])
    await db_session.flush()

    # 1. Test analyst access to GET /roles (requires roles:read)
    token_analyst = jwt_handler.create_access_token(user_analyst.id, "soc_analyst", ["roles:read"])
    headers_analyst = {"Authorization": f"Bearer {token_analyst}"}
    
    res_roles = await client.get("/api/v1/roles", headers=headers_analyst)
    assert res_roles.status_code == 200

    # 2. Test analyst access to POST /roles (requires roles:write - analyst does not have this)
    res_post_role = await client.post(
        "/api/v1/roles",
        json={"name": "new_role", "description": "desc", "permission_codes": []},
        headers=headers_analyst
    )
    assert res_post_role.status_code == 403

    # 3. Test viewer access to GET /roles (no permission -> 403)
    token_viewer = jwt_handler.create_access_token(user_viewer.id, "viewer", [])
    headers_viewer = {"Authorization": f"Bearer {token_viewer}"}
    
    res_viewer_roles = await client.get("/api/v1/roles", headers=headers_viewer)
    assert res_viewer_roles.status_code == 403
