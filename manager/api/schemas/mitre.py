"""
Pydantic Schemas for MITRE ATT&CK API.
"""
from typing import Dict, List, Optional
from pydantic import BaseModel


class TacticResponse(BaseModel):
    tactic_id: str
    name: str
    description: Optional[str] = ""


class TechniqueResponse(BaseModel):
    technique_id: str
    tactic_id: str
    name: str
    description: Optional[str] = ""
    detection_notes: Optional[str] = ""
    data_sources: List[str] = []


class CoverageMatrixResponse(BaseModel):
    coverage_matrix: Dict[str, Dict[str, int]]
