import uuid
from typing import List
from pydantic import BaseModel, Field, ConfigDict

class TokenPayload(BaseModel):
    """Pydantic model representing the decoded access token payload."""
    model_config = ConfigDict(populate_by_name=True)

    user_id: uuid.UUID = Field(..., alias="sub")
    role: str
    permissions: List[str]
    exp: int
