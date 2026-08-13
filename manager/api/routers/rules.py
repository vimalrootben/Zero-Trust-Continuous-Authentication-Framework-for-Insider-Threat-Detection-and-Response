"""
FastAPI Router for Rules endpoints connected to DB.
"""
from typing import List, Optional
import uuid
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from manager.database.session import get_db
from manager.database.models.rule import Rule as RuleModel, Severity
from manager.api.dependencies import get_current_user
from manager.api.schemas.rules import (
    RuleCreate,
    RuleResponse,
    RuleUpdate,
    RuleValidateRequest,
    RuleValidateResponse,
)
from manager.rules.rule_loader import InvalidRuleError, RuleLoader

router = APIRouter(prefix="/api/v1/rules", tags=["rules"])
rule_loader = RuleLoader()


@router.get("", response_model=List[RuleResponse])
async def list_rules(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user)
):
    """List all configured detection rules from database."""
    result = await db.execute(select(RuleModel))
    rules = result.scalars().all()
    out = []
    for r in rules:
        out.append(RuleResponse(
            id=str(r.id),
            rule_code=r.rule_code,
            name=r.name,
            category=r.category or "general",
            severity=r.severity.value if hasattr(r.severity, "value") else str(r.severity),
            mitre_technique_id=r.mitre_technique_id,
            score_impact=20,
            condition=r.condition_json or {},
            enabled=r.enabled,
            description=r.description
        ))
    return out


@router.post("", response_model=RuleResponse, status_code=status.HTTP_201_CREATED)
async def create_rule(
    rule_in: RuleCreate,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user)
):
    """Create a new detection rule in database."""
    try:
        rule_loader.validate_rule(rule_in.model_dump())
    except InvalidRuleError as e:
        raise HTTPException(status_code=400, detail=str(e))

    sev = Severity(rule_in.severity.lower()) if hasattr(Severity, rule_in.severity.upper()) else Severity.MEDIUM
    new_rule = RuleModel(
        rule_code=rule_in.rule_code,
        name=rule_in.name,
        category=rule_in.category,
        condition_json=rule_in.condition,
        severity=sev,
        mitre_technique_id=rule_in.mitre_technique_id,
        description=rule_in.description,
        enabled=rule_in.enabled
    )
    db.add(new_rule)
    await db.commit()
    await db.refresh(new_rule)

    return RuleResponse(
        id=str(new_rule.id),
        rule_code=new_rule.rule_code,
        name=new_rule.name,
        category=new_rule.category or "general",
        severity=new_rule.severity.value,
        mitre_technique_id=new_rule.mitre_technique_id,
        score_impact=rule_in.score_impact or 20,
        condition=new_rule.condition_json,
        enabled=new_rule.enabled,
        description=new_rule.description
    )


@router.get("/{rule_id}", response_model=RuleResponse)
async def get_rule(
    rule_id: str,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user)
):
    """Get a specific detection rule by ID."""
    try:
        u_id = uuid.UUID(rule_id)
        result = await db.execute(select(RuleModel).where(RuleModel.id == u_id))
    except ValueError:
        result = await db.execute(select(RuleModel).where(RuleModel.rule_code == rule_id))
    
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    
    return RuleResponse(
        id=str(rule.id),
        rule_code=rule.rule_code,
        name=rule.name,
        category=rule.category or "general",
        severity=rule.severity.value if hasattr(rule.severity, "value") else str(rule.severity),
        mitre_technique_id=rule.mitre_technique_id,
        score_impact=20,
        condition=rule.condition_json or {},
        enabled=rule.enabled,
        description=rule.description
    )


@router.put("/{rule_id}/toggle", response_model=RuleResponse)
async def toggle_rule(
    rule_id: str,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user)
):
    """Toggle a rule enabled/disabled status."""
    try:
        u_id = uuid.UUID(rule_id)
        result = await db.execute(select(RuleModel).where(RuleModel.id == u_id))
    except ValueError:
        result = await db.execute(select(RuleModel).where(RuleModel.rule_code == rule_id))
    
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    
    rule.enabled = not rule.enabled
    await db.commit()
    await db.refresh(rule)

    return RuleResponse(
        id=str(rule.id),
        rule_code=rule.rule_code,
        name=rule.name,
        category=rule.category or "general",
        severity=rule.severity.value if hasattr(rule.severity, "value") else str(rule.severity),
        mitre_technique_id=rule.mitre_technique_id,
        score_impact=20,
        condition=rule.condition_json or {},
        enabled=rule.enabled,
        description=rule.description
    )


@router.post("/validate", response_model=RuleValidateResponse)
async def validate_rule_endpoint(rule_in: RuleValidateRequest, current_user=Depends(get_current_user)):
    """Dry-run validation of a rule structure without saving."""
    try:
        rule_loader.validate_rule(rule_in.model_dump())
        return RuleValidateResponse(valid=True, message="Rule structure and condition tree are valid.")
    except InvalidRuleError as e:
        return RuleValidateResponse(valid=False, message=str(e))
