"""ZTA Behavioral Correlation Engine."""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from zta.engine.events.models import ZTAEvent


@dataclass
class BehavioralFinding:
    """Represents a finding emitted by the correlation engine."""
    finding_id: str
    rule_id: str
    rule_name: str
    agent_id: str
    severity: str
    description: str
    risk_delta: int
    matched_events: List[ZTAEvent]
    timestamp: datetime = field(default_factory=datetime.utcnow)


class ZTACorrelationEngine:
    """Engine that correlates events over time windows to detect multi-event attack sequences."""

    def __init__(self, window_seconds: int = 300):
        self.window_seconds = window_seconds
        # agent_id -> list of ZTAEvent
        self._buffers: Dict[str, List[ZTAEvent]] = {}
        # Track failed logins per user/agent: (agent_id, user_name) -> list of timestamps
        self._failed_logins: Dict[str, List[datetime]] = {}

    def _prune_buffer(self, agent_id: str, current_time: datetime):
        """Prunes events older than the window_seconds threshold."""
        cutoff = current_time - timedelta(seconds=self.window_seconds)
        if agent_id in self._buffers:
            self._buffers[agent_id] = [
                evt for evt in self._buffers[agent_id] if evt.timestamp >= cutoff
            ]

    def process_event(self, event: ZTAEvent) -> List[BehavioralFinding]:
        """Ingests a ZTAEvent, updates sliding windows, and evaluates correlation rules.
        
        Returns:
            List of BehavioralFinding objects triggered by this event.
        """
        findings: List[BehavioralFinding] = []
        agent_id = event.agent.id
        current_time = event.timestamp

        # Add event to agent's buffer and prune old events
        if agent_id not in self._buffers:
            self._buffers[agent_id] = []
        self._buffers[agent_id].append(event)
        self._prune_buffer(agent_id, current_time)

        # Rule 1: Suspicious Authentication Sequence (Failed logins followed by successful login)
        if event.wazuh_rule and "authentication" in event.wazuh_rule.groups:
            desc_lower = event.wazuh_rule.description.lower()
            key = f"{agent_id}:{event.user.name or 'unknown'}"

            if "failed" in desc_lower or "failure" in desc_lower:
                if key not in self._failed_logins:
                    self._failed_logins[key] = []
                self._failed_logins[key].append(current_time)
            elif "success" in desc_lower or "succeeded" in desc_lower:
                # Check if preceded by multiple failed logins within window
                cutoff = current_time - timedelta(seconds=self.window_seconds)
                recent_failures = [t for t in self._failed_logins.get(key, []) if t >= cutoff]
                if len(recent_failures) >= 3:
                    findings.append(
                        BehavioralFinding(
                            finding_id=f"find-auth-{current_time.timestamp()}",
                            rule_id="CORR-AUTH-001",
                            rule_name="Suspicious Authentication Sequence",
                            agent_id=agent_id,
                            severity="HIGH",
                            description=f"{len(recent_failures)} failed logins followed by successful login for user '{event.user.name}'",
                            risk_delta=30,
                            matched_events=[event],
                            timestamp=current_time,
                        )
                    )
                    # Clear processed failures
                    self._failed_logins[key] = []

        # Rule 2: Execution + Outbound Network Sequence
        buffer = self._buffers[agent_id]
        has_powershell = any(
            evt.process.name and "powershell" in evt.process.name.lower() for evt in buffer
        )
        has_network = event.destination_ip is not None or (
            event.wazuh_rule and "network" in event.wazuh_rule.groups
        )

        if has_powershell and has_network and event.destination_ip:
            findings.append(
                BehavioralFinding(
                    finding_id=f"find-exec-net-{current_time.timestamp()}",
                    rule_id="CORR-EXEC-002",
                    rule_name="PowerShell Execution Followed by Network Connection",
                    agent_id=agent_id,
                    severity="HIGH",
                    description=f"PowerShell activity followed by network connection to {event.destination_ip}:{event.destination_port}",
                    risk_delta=35,
                    matched_events=[event],
                    timestamp=current_time,
                )
            )

        return findings
