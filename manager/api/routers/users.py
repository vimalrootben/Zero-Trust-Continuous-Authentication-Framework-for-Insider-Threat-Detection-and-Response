import uuid
from typing import List
from fastapi import APIRouter, Depends, Response, status, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from manager.api.dependencies import get_db, get_current_user, require_permission
from manager.api.schemas.rbac import (
    PermissionResponse,
    RoleResponse,
    RoleCreate,
    AssignRoleRequest,
)
from manager.auth.rbac import RBACService
from manager.database.models.auth import Role, Permission, User

router = APIRouter(prefix="", tags=["RBAC & Users"])


def get_rbac_service(db: AsyncSession = Depends(get_db)) -> RBACService:
    """Dependency helper to instantiate the RBACService."""
    return RBACService(db)


@router.get(
    "/roles",
    response_model=List[RoleResponse],
    dependencies=[Depends(require_permission("roles:read"))],
    summary="Get all defined roles and their permissions."
)
async def get_roles(db: AsyncSession = Depends(get_db)):
    query = select(Role)
    result = await db.execute(query)
    return list(result.scalars().all())


@router.post(
    "/roles",
    response_model=RoleResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission("roles:write"))],
    summary="Create a new role with standard permissions (Admin only)."
)
async def create_role(
    payload: RoleCreate,
    rbac_service: RBACService = Depends(get_rbac_service)
):
    try:
        # Check if role name already exists
        db = rbac_service.db
        chk_query = select(Role).where(Role.name == payload.name)
        chk_res = await db.execute(chk_query)
        if chk_res.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Role with name '{payload.name}' already exists"
            )
        
        return await rbac_service.create_role(
            name=payload.name,
            description=payload.description,
            permission_codes=payload.permission_codes
        )
    except Exception as e:
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create role: {str(e)}"
        )


@router.get(
    "/permissions",
    response_model=List[PermissionResponse],
    dependencies=[Depends(require_permission("roles:read"))],
    summary="Get list of all granular system permission codes."
)
async def get_permissions(db: AsyncSession = Depends(get_db)):
    query = select(Permission)
    result = await db.execute(query)
    return list(result.scalars().all())


@router.put(
    "/users/{user_id}/role",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_permission("users:write"))],
    summary="Assign a role to a user (Admin only)."
)
async def assign_role(
    user_id: uuid.UUID,
    payload: AssignRoleRequest,
    current_user: User = Depends(get_current_user),
    rbac_service: RBACService = Depends(get_rbac_service)
):
    try:
        await rbac_service.assign_role(
            user_id=user_id,
            role_id=payload.role_id,
            actor_id=current_user.id
        )
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to assign role: {str(e)}"
        )
