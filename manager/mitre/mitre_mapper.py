"""
MitreMapper (M10) — MITRE ATT&CK dataset parser, repository, and coverage matrix calculator.

Design:
  - Parses official STIX JSON bundles or local fixtures into Tactic and Technique DTOs.
  - Exposes query interface for tactics, techniques, and coverage matrix calculations.
"""
import json
import logging
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class TacticDTO:
    tactic_id: str
    name: str
    description: str = ""


@dataclass
class TechniqueDTO:
    technique_id: str
    tactic_id: str
    name: str
    description: str = ""
    detection_notes: str = ""
    data_sources: List[str] = field(default_factory=list)


class MitreDataImporter:
    """Parses MITRE ATT&CK STIX JSON bundle files."""

    def parse_stix_bundle(self, filepath: str) -> tuple[List[TacticDTO], List[TechniqueDTO]]:
        tactics: List[TacticDTO] = []
        techniques: List[TechniqueDTO] = []

        if not os.path.exists(filepath):
            logger.warning(f"STIX bundle file '{filepath}' not found.")
            return tactics, techniques

        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)

            objects = data.get("objects", [])
            tactic_id_map: Dict[str, str] = {}  # stix_id -> tactic_id (e.g. TA0002)

            for obj in objects:
                if obj.get("type") == "x-mitre-tactic":
                    stix_id = obj.get("id")
                    name = obj.get("name", "")
                    desc = obj.get("description", "")
                    ext_refs = obj.get("external_references", [])
                    tac_id = ""
                    for ref in ext_refs:
                        if ref.get("source_name") in ("mitre-attack", "mitre-enterprise-attack"):
                            tac_id = ref.get("external_id", "")
                    if tac_id:
                        tactic_id_map[stix_id] = tac_id
                        tactics.append(TacticDTO(tactic_id=tac_id, name=name, description=desc))

            for obj in objects:
                if obj.get("type") == "attack-pattern" and not obj.get("revoked", False):
                    name = obj.get("name", "")
                    desc = obj.get("description", "")
                    ext_refs = obj.get("external_references", [])
                    tech_id = ""
                    for ref in ext_refs:
                        if ref.get("source_name") in ("mitre-attack", "mitre-enterprise-attack"):
                            tech_id = ref.get("external_id", "")

                    if tech_id:
                        kc_phases = obj.get("kill_chain_phases", [])
                        tac_id = kc_phases[0].get("phase_name", "") if kc_phases else ""
                        data_sources = obj.get("x_mitre_data_sources", [])

                        techniques.append(
                            TechniqueDTO(
                                technique_id=tech_id,
                                tactic_id=tac_id,
                                name=name,
                                description=desc,
                                detection_notes=obj.get("x_mitre_detection", ""),
                                data_sources=data_sources if isinstance(data_sources, list) else [],
                            )
                        )
        except Exception as e:
            logger.error(f"Error parsing STIX bundle '{filepath}': {e}")

        logger.info(f"Parsed {len(tactics)} tactics and {len(techniques)} techniques from STIX bundle.")
        return tactics, techniques


class MitreMapper:
    """Provides lookup and coverage matrix metrics for MITRE ATT&CK framework."""

    def __init__(
        self,
        tactics: Optional[List[TacticDTO]] = None,
        techniques: Optional[List[TechniqueDTO]] = None,
    ) -> None:
        self._tactics: Dict[str, TacticDTO] = {t.tactic_id: t for t in (tactics or [])}
        self._techniques: Dict[str, TechniqueDTO] = {t.technique_id: t for t in (techniques or [])}

    def load_data(self, tactics: List[TacticDTO], techniques: List[TechniqueDTO]) -> None:
        self._tactics = {t.tactic_id: t for t in tactics}
        self._techniques = {t.technique_id: t for t in techniques}

    def get_tactic(self, tactic_id: str) -> Optional[TacticDTO]:
        return self._tactics.get(tactic_id)

    def list_tactics(self) -> List[TacticDTO]:
        return list(self._tactics.values())

    def get_technique(self, technique_id: str) -> Optional[TechniqueDTO]:
        return self._techniques.get(technique_id)

    def get_techniques_by_tactic(self, tactic_id: str) -> List[TechniqueDTO]:
        return [t for t in self._techniques.values() if t.tactic_id.lower() == tactic_id.lower()]

    def get_coverage_matrix(self, rules: List[Any]) -> dict:
        """
        Calculate coverage matrix mapping tactic_id -> { technique_id: count_of_rules }.
        """
        matrix: Dict[str, Dict[str, int]] = {}

        for rule in rules:
            tech_id = getattr(rule, "mitre_technique_id", None) or (rule.get("mitre_technique_id") if isinstance(rule, dict) else None)
            if not tech_id:
                continue

            tech = self.get_technique(tech_id)
            tactic_id = tech.tactic_id if tech else "uncategorized"

            if tactic_id not in matrix:
                matrix[tactic_id] = {}

            matrix[tactic_id][tech_id] = matrix[tactic_id].get(tech_id, 0) + 1

        return matrix
