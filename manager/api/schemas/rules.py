"""
Pydantic Schemas for Rules API.
"""
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class RuleBase(BaseModel):
    rule_code: str = Field(..., json_schema_extra={"example": "RULE-0142"})
    name: str = Field(..., json_schema_extra={"example": "Suspicious PowerShell Encoded Command"})
    category: str = Field(..., json_schema_extra={"example": "execution"})
    severity: str = Field(..., json_schema_extra={"example": "high"})
    condition: Dict[str, Any] = Field(..., json_schema_extra={"example": {"all": [{"field": "collector_type", "op": "eq", "value": "process"}]}})
    score_impact: int = Field(10, json_schema_extra={"example": 20})
    mitre_technique_id: Optional[str] = Field(None, json_schema_extra={"example": "T1059.001"})
    response_action: Optional[str] = Field(None, json_schema_extra={"example": "KILL_PROCESS"})
    enabled: bool = True
    false_positive_notes: Optional[str] = None
    references: List[str] = Field(default_factory=list)


class RuleCreate(RuleBase):
    pass


class RuleUpdate(BaseModel):
    name: Optional[str] = None
    category: Optional[str] = None
    severity: Optional[str] = None
    condition: Optional[Dict[str, Any]] = None
    score_impact: Optional[int] = None
    mitre_technique_id: Optional[str] = None
    response_action: Optional[str] = None
    enabled: Optional[bool] = None
    false_positive_notes: Optional[str] = None
    references: Optional[List[str]] = None


class RuleResponse(RuleBase):
    id: Optional[str] = None
    version: int = 1


class RuleValidateRequest(BaseModel):
    rule_code: str
    name: str
    category: str
    severity: str
    condition: Dict[str, Any]


class RuleValidateResponse(BaseModel):
    valid: bool
    message: str = "Rule validation successful"
