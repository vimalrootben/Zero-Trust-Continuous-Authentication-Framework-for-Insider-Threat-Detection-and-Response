"""
Unit tests for MitreDataImporter and MitreMapper (M10).
"""
from manager.mitre.mitre_mapper import MitreMapper, TacticDTO, TechniqueDTO


def test_mitre_mapper_lookups_and_coverage():
    tactics = [
        TacticDTO(tactic_id="TA0002", name="Execution", description="Execution tactic"),
        TacticDTO(tactic_id="TA0003", name="Persistence", description="Persistence tactic"),
    ]
    techniques = [
        TechniqueDTO(technique_id="T1059.001", tactic_id="TA0002", name="PowerShell"),
        TechniqueDTO(technique_id="T1543.003", tactic_id="TA0003", name="Windows Service"),
    ]

    mapper = MitreMapper(tactics=tactics, techniques=techniques)

    # Test tactic lookup
    assert mapper.get_tactic("TA0002") is not None
    assert mapper.get_tactic("TA0002").name == "Execution"

    # Test technique lookup
    tech = mapper.get_technique("T1059.001")
    assert tech is not None
    assert tech.name == "PowerShell"

    # Test techniques by tactic
    exec_techs = mapper.get_techniques_by_tactic("TA0002")
    assert len(exec_techs) == 1
    assert exec_techs[0].technique_id == "T1059.001"

    # Test coverage matrix calculation
    rules = [
        {"mitre_technique_id": "T1059.001"},
        {"mitre_technique_id": "T1059.001"},
        {"mitre_technique_id": "T1543.003"},
    ]
    matrix = mapper.get_coverage_matrix(rules)

    assert "TA0002" in matrix
    assert matrix["TA0002"]["T1059.001"] == 2
    assert matrix["TA0003"]["T1543.003"] == 1
