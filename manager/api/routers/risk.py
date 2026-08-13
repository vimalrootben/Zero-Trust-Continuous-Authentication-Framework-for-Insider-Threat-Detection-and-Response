"""
FastAPI Router for Risk Engine endpoints.
"""
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException

from manager.api.dependencies import get_current_user
from manager.api.schemas.risk import RiskHistoryResponse, RiskScoreEntryResponse, RiskScoreResponse
from manager.risk.risk_engine import RiskEngine

router = APIRouter(prefix="/api/v1/agents", tags=["risk"])

# Global risk engine instance
risk_engine = RiskEngine()


@router.get("/{agent_id}/risk-score", response_model=RiskScoreResponse)
async def get_agent_risk_score(agent_id: str, current_user=Depends(get_current_user)):
    """Get current risk score and risk level for an agent."""
    result = risk_engine.get_current_score(agent_id)
    return RiskScoreResponse(**result)


@router.get("/{agent_id}/risk-history", response_model=RiskHistoryResponse)
async def get_agent_risk_history(
    agent_id: str,
    since: Optional[str] = None,
    current_user=Depends(get_current_user),
):
    """Get chronological risk score update history for an agent."""
    entries = risk_engine.get_score_history(agent_id, since=since)
    response_entries = [
        RiskScoreEntryResponse(
            agent_id=e.agent_id,
            score=e.score,
            delta=e.delta,
            reason=e.reason,
            rule_id=e.rule_id,
            timestamp=e.timestamp,
        )
        for e in entries
    ]
    return RiskHistoryResponse(agent_id=agent_id, history=response_entries)
