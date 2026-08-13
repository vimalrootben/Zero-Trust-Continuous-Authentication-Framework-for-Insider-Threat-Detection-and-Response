"""
FastAPI Router for Policies endpoints.
"""
from typing import List, Optional
import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from manager.database.session import get_db
from manager.database.models.policy import Policy as PolicyModel
from manager.api.dependencies import get_current_user, require_permission

router = APIRouter(prefix="/api/v1/policies", tags=["policies"])


class PolicyCreate(BaseModel):
    name: str = Field(..., description="Policy name")
    description: Optional[str] = None
    action: str = Field(..., description="Action e.g. DISABLE_NETWORK, KILL_PROCESS, LOGOFF_USER")
    condition_field: str = Field("risk_score", description="Field to test e.g. risk_score, rule_code")
    condition_operator: str = Field("gt", description="Operator e.g. gt, eq, ioc_match")
    condition_value: str = Field("75", description="Value to match")
    priority: int = Field(1, ge=1)
    enabled: bool = True


class PolicyResponse(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    action: str
    condition: dict
    priority: int
    enabled: bool
    created_at: str


@router.get("", response_model=List[PolicyResponse])
async def list_policies(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user)
):
    """List all security response policies."""
    result = await db.execute(select(PolicyModel).order_by(PolicyModel.priority.asc()))
    policies = result.scalars().all()
    out = []
    for p in policies:
        action_val = p.actions_json.get("action", "DISABLE_NETWORK") if p.actions_json else "DISABLE_NETWORK"
        out.append(PolicyResponse(
            id=str(p.id),
            name=p.name,
            description=p.description,
            action=action_val,
            condition=p.condition_json or {},
            priority=p.priority,
            enabled=p.enabled,
            created_at=p.created_at.isoformat() if p.created_at else datetime.now(timezone.utc).isoformat()
        ))
    return out


@router.post("", response_model=PolicyResponse, status_code=status.HTTP_201_CREATED)
async def create_policy(
    req: PolicyCreate,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user)
):
    """Create a new automated security response policy."""
    policy_id = uuid.uuid4()
    now = datetime.now(timezone.utc)

    # Build condition tree JSON
    condition_json = {
        "operator": "and",
        "conditions": [
            {
                "field": req.condition_field,
                "operator": req.condition_operator,
                "value": int(req.condition_value) if req.condition_value.isdigit() else req.condition_value
            }
        ]
    }
    actions_json = {"action": req.action}

    p = PolicyModel(
        id=policy_id,
        name=req.name,
        description=req.description,
        condition_json=condition_json,
        actions_json=actions_json,
        priority=req.priority,
        enabled=req.enabled,
        created_at=now
    )
    db.add(p)
    await db.commit()
    await db.refresh(p)

    return PolicyResponse(
        id=str(p.id),
        name=p.name,
        description=p.description,
        action=req.action,
        condition=p.condition_json,
        priority=p.priority,
        enabled=p.enabled,
        created_at=now.isoformat()
    )


@router.put("/{policy_id}/toggle", response_model=PolicyResponse)
async def toggle_policy(
    policy_id: str,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user)
):
    """Toggle policy enabled status."""
    u_id = uuid.UUID(policy_id)
    result = await db.execute(select(PolicyModel).where(PolicyModel.id == u_id))
    p = result.scalar_one_or_none()
    if not p:
        raise HTTPException(status_code=404, detail="Policy not found")

    p.enabled = not p.enabled
    await db.commit()
    await db.refresh(p)

    action_val = p.actions_json.get("action", "DISABLE_NETWORK") if p.actions_json else "DISABLE_NETWORK"
    return PolicyResponse(
        id=str(p.id),
        name=p.name,
        description=p.description,
        action=action_val,
        condition=p.condition_json or {},
        priority=p.priority,
        enabled=p.enabled,
        created_at=p.created_at.isoformat() if p.created_at else datetime.now(timezone.utc).isoformat()
    )
