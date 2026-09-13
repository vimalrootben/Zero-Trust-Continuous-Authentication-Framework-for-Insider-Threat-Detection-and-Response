"""Adapter for transforming raw Wazuh alert JSON into canonical ZTAEvent objects."""

from datetime import datetime, timezone
import uuid
from typing import Any, Dict, Optional

from .models import ZTAAgent, ZTAEvent, ZTAMitre, ZTAProcess, ZTAUser, ZTAWazuhRule


class ZTAAdapterError(Exception):
    """Custom exception raised when alert parsing fails."""
    pass


class ZTAEventAdapter:
    """Ingests raw Wazuh alert dictionaries and normalizes them into ZTAEvent models."""

    @staticmethod
    def parse_timestamp(ts_str: Optional[str]) -> datetime:
        """Parses ISO timestamp string or returns current UTC time."""
        if not ts_str:
            return datetime.now(timezone.utc)
        try:
            # Handle ISO formats
            clean_ts = ts_str.replace("Z", "+00:00")
            dt = datetime.fromisoformat(clean_ts)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception as exc:
            raise ValueError("Invalid event timestamp") from exc

    @staticmethod
    def extract_severity(level: int) -> str:
        """Maps Wazuh rule level (0-15) to ZTA severity string."""
        if level >= 12:
            return "CRITICAL"
        elif level >= 8:
            return "HIGH"
        elif level >= 4:
            return "MEDIUM"
        return "LOW"

    @classmethod
    def from_dict(cls, alert: Dict[str, Any]) -> ZTAEvent:
        """Transforms a raw Wazuh alert JSON dictionary into a ZTAEvent instance.
        
        Args:
            alert: Raw Wazuh alert dictionary.
            
        Returns:
            ZTAEvent normalized instance.
            
        Raises:
            ValueError: If required fields (agent/rule) are completely missing.
        """
        if not isinstance(alert, dict):
            raise ValueError("Alert must be a dictionary.")

        # Extract Agent Identity
        agent_data = alert.get("agent", {})
        agent_id = str(agent_data.get("id", "000"))
        agent_name = str(agent_data.get("name", "unknown-agent"))
        agent_ip = agent_data.get("ip")
        agent = ZTAAgent(id=agent_id, name=agent_name, ip=agent_ip)

        # Extract Wazuh Rule Metadata
        rule_data = alert.get("rule", {})
        rule_id = rule_data.get("id", 0)
        rule_level = rule_data.get("level", 0)
        rule_desc = rule_data.get("description", "")
        rule_groups = rule_data.get("groups", [])
        wazuh_rule = ZTAWazuhRule(
            id=rule_id,
            level=rule_level,
            description=rule_desc,
            groups=rule_groups,
        )

        # Extract MITRE Mapping
        mitre_data = rule_data.get("mitre", {})
        tactics = mitre_data.get("tactic", [])
        techniques = mitre_data.get("technique", [])
        technique_ids = mitre_data.get("id", [])

        mitre = ZTAMitre(
            tactic=tactics[0] if isinstance(tactics, list) and tactics else (tactics if isinstance(tactics, str) else None),
            technique=techniques[0] if isinstance(techniques, list) and techniques else (techniques if isinstance(techniques, str) else None),
            technique_id=technique_ids[0] if isinstance(technique_ids, list) and technique_ids else (technique_ids if isinstance(technique_ids, str) else None),
        )

        # Extract Data Payload (Windows / Sysmon / Event Data)
        data = alert.get("data", {})
        win_data = data.get("win", {})
        event_data = win_data.get("eventdata", {})

        # Extract User Context
        username = (
            event_data.get("user")
            or event_data.get("targetUserName")
            or event_data.get("subjectUserName")
            or (data.get("srcuser") if isinstance(data, dict) else None)
            or (data.get("dstuser") if isinstance(data, dict) else None)
            or (alert.get("user", {}).get("name") if isinstance(alert.get("user"), dict) else alert.get("user"))
        )
        domain = (
            event_data.get("targetDomainName")
            or event_data.get("subjectDomainName")
            or (alert.get("user", {}).get("domain") if isinstance(alert.get("user"), dict) else None)
        )
        session_id = (alert.get("user") or {}).get("session_id") if isinstance(alert.get("user"), dict) else None
        session_id = session_id if session_id is not None else event_data.get("terminalSessionId")
        user = ZTAUser(name=username, domain=domain, session_id=int(session_id) if session_id is not None else None)

        # Extract Process Context
        proc_raw = alert.get("process") if isinstance(alert.get("process"), dict) else {}
        proc_name = (
            event_data.get("image")
            or (data.get("process") if isinstance(data, dict) else None)
            or proc_raw.get("name")
            or (alert.get("process") if isinstance(alert.get("process"), str) else None)
        )
        if proc_name and "\\" in proc_name:
            proc_path = proc_name
            proc_name = proc_name.rsplit("\\", 1)[-1]
        else:
            proc_path = proc_raw.get("path")

        parent_proc = (
            event_data.get("parentImage")
            or proc_raw.get("parent_name")
            or proc_raw.get("parentImage")
        )
        if parent_proc and "\\" in parent_proc:
            parent_proc = parent_proc.rsplit("\\", 1)[-1]

        cmd_line = (
            event_data.get("commandLine")
            or proc_raw.get("command_line")
            or proc_raw.get("commandLine")
        )
        proc_pid = (
            event_data.get("processId")
            or proc_raw.get("pid")
            or proc_raw.get("processId")
        )
        if proc_pid:
            try:
                proc_pid = int(proc_pid, 16) if isinstance(proc_pid, str) and proc_pid.startswith("0x") else int(proc_pid)
            except ValueError:
                proc_pid = None

        process = ZTAProcess(
            name=proc_name,
            path=proc_path,
            pid=proc_pid,
            parent_name=parent_proc,
            command_line=cmd_line,
        )

        # Network context
        src_ip = alert.get("source_ip") or event_data.get("sourceIp") or (data.get("srcip") if isinstance(data, dict) else None)
        dst_ip = alert.get("destination_ip") or event_data.get("destinationIp") or (data.get("dstip") if isinstance(data, dict) else None)
        dst_port = alert.get("destination_port") or event_data.get("destinationPort") or (data.get("dstport") if isinstance(data, dict) else None)
        if dst_port:
            try:
                dst_port = int(dst_port)
            except ValueError:
                dst_port = None

        # Determine Event Type
        event_type = alert.get("event_type") or "GENERAL_ALERT"
        if not alert.get("event_type"):
            if proc_name:
                event_type = "PROCESS_CREATION"
            elif "authentication" in rule_groups or "syslog" in rule_groups:
                event_type = "AUTHENTICATION"

        # Unique Event ID & Timestamp
        event_id = str(alert.get("id") or alert.get("event_id") or uuid.uuid4())
        timestamp = cls.parse_timestamp(alert.get("timestamp"))
        severity = alert.get("severity") or cls.extract_severity(rule_level)

        return ZTAEvent(
            event_id=event_id,
            timestamp=timestamp,
            agent=agent,
            user=user,
            process=process,
            wazuh_rule=wazuh_rule,
            mitre=mitre,
            event_type=event_type,
            severity=severity,
            source_ip=src_ip,
            destination_ip=dst_ip,
            destination_port=dst_port,
            raw_event=alert,
        )
