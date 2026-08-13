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
    policy_code: Optional[str] = None
    name: str
    description: Optional[str] = None
    category: Optional[str] = None
    severity: Optional[str] = "medium"
    risk_impact: int = 10
    mitre_technique_id: Optional[str] = None
    action: str
    condition: dict
    priority: int
    enabled: bool
    mode: str = "ALERT_ONLY"
    trigger_count: int = 0
    last_triggered_at: Optional[str] = None
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
        action_val = p.actions_json.get("action", "ALERT") if p.actions_json else "ALERT"
        out.append(PolicyResponse(
            id=str(p.id),
            policy_code=p.policy_code or str(p.id)[:8],
            name=p.name,
            description=p.description,
            category=p.category or "general",
            severity=p.severity or "medium",
            risk_impact=p.risk_impact if p.risk_impact is not None else 10,
            mitre_technique_id=p.mitre_technique_id,
            action=action_val,
            condition=p.condition_json or {},
            priority=p.priority,
            enabled=p.enabled,
            mode=p.mode or "ALERT_ONLY",
            trigger_count=p.trigger_count or 0,
            last_triggered_at=p.last_triggered_at.isoformat() if p.last_triggered_at else None,
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
    policy_code = f"POL-CUSTOM-{str(policy_id)[:4].upper()}"

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
        policy_code=policy_code,
        name=req.name,
        description=req.description,
        category="custom",
        severity="medium",
        risk_impact=15,
        condition_json=condition_json,
        actions_json=actions_json,
        priority=req.priority,
        enabled=req.enabled,
        mode="ALERT_ONLY",
        created_at=now
    )
    db.add(p)
    await db.commit()
    await db.refresh(p)

    return PolicyResponse(
        id=str(p.id),
        policy_code=p.policy_code,
        name=p.name,
        description=p.description,
        category=p.category,
        severity=p.severity,
        risk_impact=p.risk_impact,
        mitre_technique_id=p.mitre_technique_id,
        action=req.action,
        condition=p.condition_json,
        priority=p.priority,
        enabled=p.enabled,
        mode=p.mode,
        trigger_count=0,
        last_triggered_at=None,
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

    action_val = p.actions_json.get("action", "ALERT") if p.actions_json else "ALERT"
    return PolicyResponse(
        id=str(p.id),
        policy_code=p.policy_code or str(p.id)[:8],
        name=p.name,
        description=p.description,
        category=p.category or "general",
        severity=p.severity or "medium",
        risk_impact=p.risk_impact if p.risk_impact is not None else 10,
        mitre_technique_id=p.mitre_technique_id,
        action=action_val,
        condition=p.condition_json or {},
        priority=p.priority,
        enabled=p.enabled,
        mode=p.mode or "ALERT_ONLY",
        trigger_count=p.trigger_count or 0,
        last_triggered_at=p.last_triggered_at.isoformat() if p.last_triggered_at else None,
        created_at=p.created_at.isoformat() if p.created_at else datetime.now(timezone.utc).isoformat()
    )
