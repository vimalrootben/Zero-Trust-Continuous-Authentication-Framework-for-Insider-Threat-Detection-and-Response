import asyncio
import pytest
import pytest_asyncio
from typing import AsyncGenerator, Generator
from httpx import AsyncClient, ASGITransport
from sqlalchemy.pool import NullPool
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy import select
from manager.config import settings
from manager.database.base import Base
import manager.database.models  # Register all ORM models with Base.metadata
from manager.database.models.auth import Role, Permission, User
from manager.api.main import app

# Create a dedicated test database engine with NullPool to prevent connection caching across event loops.
test_engine = create_async_engine(settings.DATABASE_URL, pool_pre_ping=True, poolclass=NullPool)
test_session_maker = async_sessionmaker(bind=test_engine, class_=AsyncSession, expire_on_commit=False)


@pytest_asyncio.fixture(scope="session", autouse=True)
async def setup_test_database():
    """Create all database tables and seed default roles/users before tests."""
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Seed default roles, permissions, and admin user for test environment
    from scripts.seed_db import PERMISSIONS, ROLES_PERMISSIONS
    from manager.auth.password_handler import PasswordHandler
    ph = PasswordHandler()

    async with test_session_maker() as session:
        db_permissions = {}
        for perm_data in PERMISSIONS:
            res = await session.execute(select(Permission).where(Permission.code == perm_data["code"]))
            perm = res.scalar_one_or_none()
            if not perm:
                perm = Permission(code=perm_data["code"], description=perm_data["description"])
                session.add(perm)
            db_permissions[perm_data["code"]] = perm
        await session.flush()

        db_roles = {}
        for role_name, perm_codes in ROLES_PERMISSIONS.items():
            res = await session.execute(select(Role).where(Role.name == role_name))
            role = res.scalar_one_or_none()
            target_permissions = [db_permissions[code] for code in perm_codes if code in db_permissions]
            if not role:
                role = Role(name=role_name, description=f"Standard {role_name} role", permissions=target_permissions)
                session.add(role)
            else:
                role.permissions = target_permissions
            db_roles[role_name] = role
        await session.flush()

        res = await session.execute(select(User).where(User.username == "admin"))
        admin_user = res.scalar_one_or_none()
        admin_pw_hash = ph.hash_password("AdminSecure123!")
        if not admin_user:
            admin_user = User(
                username="admin",
                email="admin@zerotrust.local",
                password_hash=admin_pw_hash,
                full_name="Zero Trust Administrator",
                department="Security Operations",
                is_active=True,
                mfa_enabled=False,
                role_id=db_roles["admin"].id
            )
            session.add(admin_user)
        else:
            admin_user.password_hash = admin_pw_hash
            admin_user.role_id = db_roles["admin"].id
            admin_user.failed_login_attempts = 0
            admin_user.locked_until = None
            admin_user.is_active = True
        await session.commit()

    yield
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)



@pytest_asyncio.fixture(scope="function")
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    """Fixture to provide a database session for unit and API tests.

    Uses SQLAlchemy's implicit auto-begin (no explicit begin() context manager).
    This allows endpoints that call db.commit() mid-test to not close the
    session's transaction context, enabling multiple API calls per test function.

    Note: Because endpoint commits write to the real test DB, we issue a
    best-effort rollback at teardown — but committed data from endpoints
    intentionally persists within the same test (this is correct for
    integration tests that exercise real transactional semantics).
    """
    async with test_session_maker() as session:
        try:
            yield session
        finally:
            # Rollback any uncommitted data written directly by the test setup
            await session.rollback()


@pytest_asyncio.fixture(scope="function")
async def client(db_session: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    """Fixture to provide an AsyncClient for testing FastAPI HTTP endpoints.
    Overrides the get_db dependency to use the transactional db_session fixture.
    """
    from manager.database.session import get_db

    # Dependency override
    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    # Configure transport instead of using deprecated app parameter directly
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

    app.dependency_overrides.clear()
