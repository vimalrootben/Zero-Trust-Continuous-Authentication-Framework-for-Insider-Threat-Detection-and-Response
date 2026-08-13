import uuid
import pytest
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from manager.database.models.auth import Permission, Role, User
from manager.database.models.audit import AuditLog
from manager.auth.rbac import RBACService
from manager.auth.exceptions import RoleNotFoundError

@pytest.mark.asyncio
async def test_create_role_and_permissions(db_session: AsyncSession):
    rbac = RBACService(db_session)
    
    # Setup unique permissions
    perm1 = Permission(code="test_rbac:read", description="test read")
    perm2 = Permission(code="test_rbac:write", description="test write")
    db_session.add_all([perm1, perm2])
    await db_session.flush()

    # Create role
    role = await rbac.create_role(
        name="test_rbac_role",
        description="test role desc",
        permission_codes=["test_rbac:read", "test_rbac:write"]
    )
    assert role.name == "test_rbac_role"
    assert len(role.permissions) == 2
    assert "test_rbac:read" in [p.code for p in role.permissions]


@pytest.mark.asyncio
async def test_user_has_permission(db_session: AsyncSession):
    rbac = RBACService(db_session)
    
    # Create role and permissions with unique codes
    perm = Permission(code="test_user_has_perm:read", description="view test")
    role = Role(name="test_user_has_perm_role", description="analyst role", permissions=[perm])
    db_session.add_all([perm, role])
    await db_session.flush()

    # Create users
    user_analyst = User(
        username="test_user_has_perm_analyst",
        email="analyst_u_perm@test.local",
        password_hash="hash",
        is_active=True,
        role_id=role.id
    )
    
    # Use seeded admin role for admin check
    admin_role_res = await db_session.execute(select(Role).where(Role.name == "admin"))
    admin_role = admin_role_res.scalar_one()

    user_admin = User(
        username="test_user_has_perm_admin",
        email="admin_u_perm@test.local",
        password_hash="hash",
        is_active=True,
        role_id=admin_role.id
    )
    
    user_none = User(
        username="test_user_has_perm_none",
        email="none_u_perm@test.local",
        password_hash="hash",
        is_active=True,
        role_id=None
    )
    db_session.add_all([user_analyst, user_admin, user_none])
    await db_session.flush()

    # Check analyst permissions
    assert await rbac.user_has_permission(user_analyst.id, "test_user_has_perm:read") is True
    assert await rbac.user_has_permission(user_analyst.id, "test_user_has_perm:write") is False

    # Check admin bypass
    assert await rbac.user_has_permission(user_admin.id, "test_user_has_perm:read") is True
    assert await rbac.user_has_permission(user_admin.id, "test_user_has_perm:write") is True

    # Check user with no role
    assert await rbac.user_has_permission(user_none.id, "test_user_has_perm:read") is False


@pytest.mark.asyncio
async def test_assign_role_and_audit_log(db_session: AsyncSession):
    rbac = RBACService(db_session)
    actor_id = uuid.uuid4()

    # Setup roles with unique names
    role_viewer = Role(name="test_assign_viewer", description="viewer role")
    role_analyst = Role(name="test_assign_analyst", description="analyst role")
    db_session.add_all([role_viewer, role_analyst])
    await db_session.flush()

    # Create user
    user = User(
        username="test_assign_user",
        email="assign_user@test.local",
        password_hash="hash",
        is_active=True,
        role_id=role_viewer.id
    )
    db_session.add(user)
    await db_session.flush()

    # Assign new role
    await rbac.assign_role(user.id, role_analyst.id, actor_id=actor_id)
    assert user.role_id == role_analyst.id

    # Verify audit log entry
    query = select(AuditLog).where(AuditLog.action == "rbac.role.assigned")
    result = await db_session.execute(query)
    audit = result.scalar_one_or_none()
    
    assert audit is not None
    assert audit.actor_id == actor_id
    assert audit.target_id == user.id
    assert audit.details_json["old_role_id"] == str(role_viewer.id)
    assert audit.details_json["new_role_id"] == str(role_analyst.id)


@pytest.mark.asyncio
async def test_assign_non_existent_role_raises(db_session: AsyncSession):
    rbac = RBACService(db_session)
    user_id = uuid.uuid4()
    non_existent_role_id = uuid.uuid4()

    with pytest.raises(RoleNotFoundError):
        await rbac.assign_role(user_id, non_existent_role_id, actor_id=uuid.uuid4())
