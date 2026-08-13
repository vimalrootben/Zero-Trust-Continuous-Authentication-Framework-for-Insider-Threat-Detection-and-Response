import uuid
from typing import List, Optional
from pydantic import BaseModel, ConfigDict

class PermissionResponse(BaseModel):
    """Pydantic schema representing a permission definition response."""
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    code: str
    description: Optional[str] = None


class RoleResponse(BaseModel):
    """Pydantic schema representing a role response, including its associated permissions."""
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    description: Optional[str] = None
    permissions: List[PermissionResponse] = []


class RoleCreate(BaseModel):
    """Pydantic schema representing a request payload to create a new role."""
    name: str
    description: Optional[str] = None
    permission_codes: List[str]


class AssignRoleRequest(BaseModel):
    """Pydantic schema representing a request payload to assign a role to a user."""
    role_id: uuid.UUID
