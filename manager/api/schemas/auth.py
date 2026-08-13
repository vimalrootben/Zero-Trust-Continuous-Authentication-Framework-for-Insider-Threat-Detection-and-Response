import uuid
from typing import Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator

class UserPublic(BaseModel):
    """Publicly visible user profile details."""
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    username: str
    email: str
    role: str = ""
    department: Optional[str] = None
    mfa_enabled: bool

    @field_validator("role", mode="before")
    @classmethod
    def get_role_name(cls, v):
        """Extracts the role name string from a Role object, falling back to viewer."""
        if v and hasattr(v, "name"):
            return v.name
        if isinstance(v, str):
            return v
        return "viewer"


class LoginRequest(BaseModel):
    """Payload to request authentication credentials check."""
    username: str
    password: str
    totp_code: Optional[str] = None


class LoginResponse(BaseModel):
    """Successful authentication response payload."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserPublic


class RefreshRequest(BaseModel):
    """Payload to request access token rotation using a refresh token."""
    refresh_token: str


class RefreshResponse(BaseModel):
    """Rotated access and refresh tokens response payload."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class ChangePasswordRequest(BaseModel):
    """Payload to request modification of user authentication password."""
    old_password: str
    new_password: str


class ConfirmMFARequest(BaseModel):
    """Payload to verify first TOTP code and enable MFA."""
    totp_code: str


class MFAEnableResponse(BaseModel):
    """MFA setup credentials response payload."""
    secret: str
    provisioning_uri: str
