import asyncio
import os
import sys
from datetime import datetime, timezone

# Ensure project root is in sys.path
_here = os.path.dirname(os.path.abspath(__file__))
_root = os.path.dirname(_here)
if _root not in sys.path:
    sys.path.insert(0, _root)

from sqlalchemy import select
from manager.database.session import async_session_maker, engine
from manager.database.base import Base
import manager.database.models  # noqa: F401 – registers all ORM models with Base.metadata
from manager.database.models.auth import Permission, Role, User
from manager.auth.password_handler import PasswordHandler

# Define default permissions list
PERMISSIONS = [
    # RBAC permissions
    {"code": "roles:read", "description": "View system roles and permissions"},
    {"code": "roles:write", "description": "Create and modify roles"},
    {"code": "users:write", "description": "Modify user assignments and roles"},
    # Core system permissions
    {"code": "agents:read", "description": "View enrolled host agents details"},
    {"code": "agents:write", "description": "Modify agents or enrollment tokens"},
    {"code": "alerts:read", "description": "View security alerts"},
    {"code": "alerts:write", "description": "Acknowledge or update alerts"},
    {"code": "incidents:read", "description": "View incident timelines and logs"},
    {"code": "incidents:write", "description": "Create or update incidents"},
    {"code": "commands:execute", "description": "Issue command payloads to agents"},
    {"code": "telemetry:read", "description": "Query gathered agent telemetry"},
    {"code": "policies:read", "description": "Read policies and policy groups"},
    {"code": "policies:write", "description": "Manage security policies"},
    {"code": "rules:read", "description": "Read detection rule configurations"},
    {"code": "rules:write", "description": "Manage detection rules"},
    {"code": "audit:read", "description": "View management audit logs"},
]

# Define default roles and their associated permission codes
ROLES_PERMISSIONS = {
    "admin": [p["code"] for p in PERMISSIONS],  # Gets all permissions
    "soc_analyst": [
        "agents:read", "alerts:read", "alerts:write", "incidents:read",
        "incidents:write", "commands:execute", "telemetry:read",
        "policies:read", "rules:read"
    ],
    "viewer": [
        "agents:read", "alerts:read", "incidents:read", "telemetry:read",
        "policies:read", "rules:read"
    ],
}


async def seed():
    print("Starting database seeding...")
    ph = PasswordHandler()

    # Ensure all tables exist (works with SQLite dev DB; no-op if already created)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    async with async_session_maker() as session:
        # 1. Seed Permissions
        print("Seeding permissions...")
        db_permissions = {}
        for perm_data in PERMISSIONS:
            query = select(Permission).where(Permission.code == perm_data["code"])
            result = await session.execute(query)
            existing = result.scalar_one_or_none()
            
            if not existing:
                perm = Permission(code=perm_data["code"], description=perm_data["description"])
                session.add(perm)
                db_permissions[perm_data["code"]] = perm
                print(f" -> Created permission: {perm_data['code']}")
            else:
                db_permissions[perm_data["code"]] = existing
        
        await session.flush()

        # 2. Seed Roles & Map Permissions
        print("Seeding roles and mapping permissions...")
        db_roles = {}
        for role_name, perm_codes in ROLES_PERMISSIONS.items():
            query = select(Role).where(Role.name == role_name)
            result = await session.execute(query)
            role = result.scalar_one_or_none()
            
            # Fetch permission models for this role
            target_permissions = [db_permissions[code] for code in perm_codes if code in db_permissions]
            
            if not role:
                role = Role(
                    name=role_name,
                    description=f"Standard {role_name} role",
                    permissions=target_permissions
                )
                session.add(role)
                print(f" -> Created role: {role_name}")
            else:
                # Update role permissions mapping
                role.permissions = target_permissions
                print(f" -> Updated permissions for role: {role_name}")
            
            db_roles[role_name] = role
            
        await session.flush()

        # 3. Seed default Admin user
        print("Seeding default administrator user...")
        query = select(User).where(User.username == "admin")
        result = await session.execute(query)
        admin_user = result.scalar_one_or_none()
        
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
            print(" -> Created user: admin (Password: AdminSecure123!)")
        else:
            admin_user.password_hash = admin_pw_hash
            admin_user.role_id = db_roles["admin"].id
            admin_user.failed_login_attempts = 0
            admin_user.locked_until = None
            admin_user.is_active = True
            print(" -> Admin user already exists, updated password, reset locks, and updated role mapping.")

        await session.commit()
        print("Database seeding completed successfully!")


if __name__ == "__main__":
    asyncio.run(seed())
