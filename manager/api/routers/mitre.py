"""
FastAPI Router for MITRE ATT&CK endpoints.
"""
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException

from manager.api.dependencies import get_current_user
from manager.api.schemas.mitre import CoverageMatrixResponse, TacticResponse, TechniqueResponse
from manager.mitre.mitre_mapper import MitreMapper, TacticDTO, TechniqueDTO

router = APIRouter(prefix="/api/v1/mitre", tags=["mitre"])

# Global mapper instance populated with reference tactics/techniques
mitre_mapper = MitreMapper(
    tactics=[
        TacticDTO(tactic_id="TA0001", name="Initial Access", description="Drive-by download, phishing, etc."),
        TacticDTO(tactic_id="TA0002", name="Execution", description="Command and scripting interpreter execution."),
        TacticDTO(tactic_id="TA0003", name="Persistence", description="Maintain access across restarts."),
        TacticDTO(tactic_id="TA0005", name="Defense Evasion", description="Avoid detection mechanisms."),
        TacticDTO(tactic_id="TA0006", name="Credential Access", description="Steal credentials like passwords."),
    ],
    techniques=[
        TechniqueDTO(technique_id="T1059", tactic_id="TA0002", name="Command and Scripting Interpreter"),
        TechniqueDTO(technique_id="T1059.001", tactic_id="TA0002", name="PowerShell"),
        TechniqueDTO(technique_id="T1053.005", tactic_id="TA0003", name="Scheduled Task"),
        TechniqueDTO(technique_id="T1543.003", tactic_id="TA0003", name="Windows Service"),
        TechniqueDTO(technique_id="T1547.001", tactic_id="TA0003", name="Registry Run Keys"),
        TechniqueDTO(technique_id="T1070.001", tactic_id="TA0005", name="Clear Windows Event Logs"),
    ],
)


@router.get("/tactics", response_model=List[TacticResponse])
async def list_tactics(current_user=Depends(get_current_user)):
    """List all MITRE ATT&CK tactics."""
    return [t.__dict__ for t in mitre_mapper.list_tactics()]


@router.get("/techniques", response_model=List[TechniqueResponse])
async def list_techniques(tactic_id: Optional[str] = None, current_user=Depends(get_current_user)):
    """List MITRE ATT&CK techniques, optionally filtered by tactic_id."""
    if tactic_id:
        return [t.__dict__ for t in mitre_mapper.get_techniques_by_tactic(tactic_id)]
    return [t.__dict__ for t in mitre_mapper._techniques.values()]


@router.get("/techniques/{technique_id}", response_model=TechniqueResponse)
async def get_technique(technique_id: str, current_user=Depends(get_current_user)):
    """Get details for a specific MITRE ATT&CK technique."""
    tech = mitre_mapper.get_technique(technique_id)
    if not tech:
        raise HTTPException(status_code=404, detail="MITRE technique not found")
    return tech.__dict__


@router.get("/coverage-matrix", response_model=CoverageMatrixResponse)
async def get_coverage_matrix(current_user=Depends(get_current_user)):
    """Get MITRE ATT&CK coverage matrix of active detection rules."""
    # In a full deployment, rules are pulled from DB; here we query active mapped rules
    sample_rules = [
        {"mitre_technique_id": "T1059.001"},
        {"mitre_technique_id": "T1053.005"},
        {"mitre_technique_id": "T1543.003"},
        {"mitre_technique_id": "T1547.001"},
        {"mitre_technique_id": "T1070.001"},
    ]
    matrix = mitre_mapper.get_coverage_matrix(sample_rules)
    return CoverageMatrixResponse(coverage_matrix=matrix)
