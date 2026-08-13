import uuid
from datetime import datetime, timezone
from typing import List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from manager.database.models.auth import Role, Permission, User
from manager.database.models.audit import AuditLog, ActorType
from manager.auth.exceptions import RoleNotFoundError

class RBACService:
    """Handles authorization checks, role creations, and assignments with audit logging."""

    def __init__(self, db_session: AsyncSession):
        self.db = db_session

    async def get_permissions_for_role(self, role_id: uuid.UUID) -> List[str]:
        """Fetches the list of permission codes associated with a specific role."""
        query = select(Role).where(Role.id == role_id)
        result = await self.db.execute(query)
        role = result.scalar_one_or_none()
        if not role:
            raise RoleNotFoundError(f"Role with ID {role_id} not found")
        
        # permissions relationship uses lazy='selectin' in the model
        return [perm.code for perm in role.permissions]

    async def user_has_permission(self, user_id: uuid.UUID, permission_code: str) -> bool:
        """Checks if a user has a specific permission code.
        The 'admin' role automatically possesses all permissions (returns True).
        """
        query = select(User).where(User.id == user_id)
        result = await self.db.execute(query)
        user = result.scalar_one_or_none()
        if not user or not user.role:
            return False

        # Admin bypass
        if user.role.name == "admin":
            return True

        # Check permissions list
        permissions = await self.get_permissions_for_role(user.role_id)
        return permission_code in permissions

    async def assign_role(self, user_id: uuid.UUID, role_id: uuid.UUID, actor_id: uuid.UUID) -> None:
        """Assigns a role to a user and writes an audit log entry."""
        # Validate role exists
        role_query = select(Role).where(Role.id == role_id)
        role_result = await self.db.execute(role_query)
        role = role_result.scalar_one_or_none()
        if not role:
            raise RoleNotFoundError(f"Role with ID {role_id} not found")

        # Fetch user
        user_query = select(User).where(User.id == user_id)
        user_result = await self.db.execute(user_query)
        user = user_result.scalar_one_or_none()
        if not user:
            raise ValueError(f"User with ID {user_id} not found")

        # Update user's role
        old_role_id = user.role_id
        user.role_id = role_id
        await self.db.flush()

        # Write audit log
        audit = AuditLog(
            actor_type=ActorType.USER,
            actor_id=actor_id,
            action="rbac.role.assigned",
            target_type="user",
            target_id=user_id,
            details_json={
                "old_role_id": str(old_role_id) if old_role_id else None,
                "new_role_id": str(role_id),
                "role_name": role.name
            },
            timestamp=datetime.now(timezone.utc)
        )
        self.db.add(audit)
        await self.db.flush()

    async def create_role(self, name: str, description: str, permission_codes: List[str]) -> Role:
        """Creates a new Role and links permissions to it by permission codes."""
        # Find permission objects
        perm_query = select(Permission).where(Permission.code.in_(permission_codes))
        perm_result = await self.db.execute(perm_query)
        permissions = list(perm_result.scalars().all())

        role = Role(
            name=name,
            description=description,
            permissions=permissions
        )
        self.db.add(role)
        await self.db.flush()
        return role
