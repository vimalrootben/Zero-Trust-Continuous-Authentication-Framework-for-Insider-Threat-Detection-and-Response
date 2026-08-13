"""
Scoring Rules & Thresholds for Risk Engine (M7).

Risk Levels:
  0 - 29:  LOW
  30 - 59: MEDIUM
  60 - 84: HIGH
  85 - 100: CRITICAL
"""
from enum import Enum
from typing import Dict


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


DEFAULT_SCORE_DELTAS: Dict[str, int] = {
    "usb_device_inserted": 10,
    "powershell_unsigned_exec": 20,
    "unknown_binary_exec": 15,
    "credential_dumping": 40,
    "failed_login_threshold": 15,
    "off_hours_access": 20,
    "ioc_match": 35,
    "lateral_movement": 30,
    "baseline_decay": -5,
}

SCORE_MIN = 0
SCORE_MAX = 100
DEFAULT_DECAY_GRACE_HOURS = 24
DEFAULT_DECAY_AMOUNT = -5


def get_risk_level(score: int) -> RiskLevel:
    """
    Return derived RiskLevel string enum for a numeric risk score (0-100).
    """
    clamped = max(SCORE_MIN, min(SCORE_MAX, score))
    if clamped < 30:
        return RiskLevel.LOW
    if clamped < 60:
        return RiskLevel.MEDIUM
    if clamped < 85:
        return RiskLevel.HIGH
    return RiskLevel.CRITICAL
