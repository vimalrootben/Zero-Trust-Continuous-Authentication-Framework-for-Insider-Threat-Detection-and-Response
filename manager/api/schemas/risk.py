"""
Pydantic Schemas for Risk Engine API.
"""
from typing import List, Optional
from pydantic import BaseModel


class RiskScoreResponse(BaseModel):
    agent_id: str
    score: int
    level: str


class RiskScoreEntryResponse(BaseModel):
    agent_id: str
    score: int
    delta: int
    reason: str
    rule_id: Optional[str] = None
    timestamp: str


class RiskHistoryResponse(BaseModel):
    agent_id: str
    history: List[RiskScoreEntryResponse]
