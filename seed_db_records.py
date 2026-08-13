import asyncio
import os
import uuid
from datetime import datetime, timezone
from sqlalchemy import select
from manager.database.session import async_session_maker
from manager.database.models.agent import Agent, AgentStatus
from manager.database.models.alert import Alert, AlertStatus
from manager.database.models.audit import AuditLog, ActorType
from manager.database.models.policy import Policy
from manager.database.models.rule import Rule as RuleModel, Severity
from manager.database.models.mitre import MitreTactic, MitreTechnique

from scripts.seed_db import seed

async def seed_data():
    await seed()
    async with async_session_maker() as db:
        agents = (await db.execute(select(Agent))).scalars().all()
        if not agents:
            demo_agent_1 = Agent(
                id=uuid.uuid4(),
                hostname="EDR-SEC-WIN11-01",
                ip_address="192.168.1.105",
                os_version="Windows 11 Enterprise (22H2)",
                agent_version="1.0.0",
                status=AgentStatus.ACTIVE,
                current_risk_score=78,
                department="Security Operations",
                device_fingerprint="A1B2C3D4E5F678901234567890ABCDEF",
                last_seen_at=datetime.now(timezone.utc),
            )
            demo_agent_2 = Agent(
                id=uuid.uuid4(),
                hostname="EDR-FIN-WIN10-02",
                ip_address="192.168.1.112",
                os_version="Windows 10 Pro (21H2)",
                agent_version="1.0.0",
                status=AgentStatus.ACTIVE,
                current_risk_score=25,
                department="Finance",
                device_fingerprint="FE9876543210FEDCBA09876543210FED",
                last_seen_at=datetime.now(timezone.utc),
            )
            db.add(demo_agent_1)
            db.add(demo_agent_2)
            await db.flush()
            agents = [demo_agent_1, demo_agent_2]
            print(f'Created {len(agents)} demo agent endpoints.')
        
        agent_id = agents[0].id
        
        # 1. Seed Alerts
        alert_rows = (await db.execute(select(Alert))).scalars().all()
        if not alert_rows:
            alerts = [
                Alert(
                    id=uuid.uuid4(), agent_id=agent_id, title='Unusual PowerShell Execution',
                    description='Encoded PowerShell command executed with bypass flags.',
                    severity=Severity.HIGH, status=AlertStatus.OPEN, created_at=datetime.now(timezone.utc)
                ),
                Alert(
                    id=uuid.uuid4(), agent_id=agent_id, title='Suspicious Outbound Connection to Unknown IP',
                    description='Network process initiated connection to untrusted external IP.',
                    severity=Severity.MEDIUM, status=AlertStatus.INVESTIGATING, created_at=datetime.now(timezone.utc)
                ),
                Alert(
                    id=uuid.uuid4(), agent_id=agent_id, title='Ransomware Mass File Rename Pattern',
                    description='Mass file write and extension renaming detected in Documents directory.',
                    severity=Severity.CRITICAL, status=AlertStatus.OPEN, created_at=datetime.now(timezone.utc)
                )
            ]
            for a in alerts: db.add(a)

        # 2. Seed Audit Logs
        audit_rows = (await db.execute(select(AuditLog))).scalars().all()
        if len(audit_rows) < 5:
            logs = [
                AuditLog(
                    id=uuid.uuid4(), actor_type=ActorType.USER, action='policy.create',
                    target_type='policy', details_json={'policy_name': 'Ransomware Auto-Isolate'},
                    ip_address='127.0.0.1', timestamp=datetime.now(timezone.utc)
                ),
                AuditLog(
                    id=uuid.uuid4(), actor_type=ActorType.SYSTEM, action='agent.isolate',
                    target_type='agent', target_id=agent_id, details_json={'reason': 'Automated Risk Threshold Exceeded'},
                    ip_address='127.0.0.1', timestamp=datetime.now(timezone.utc)
                ),
                AuditLog(
                    id=uuid.uuid4(), actor_type=ActorType.USER, action='rule.enable',
                    target_type='rule', details_json={'rule_code': 'PROC001'},
                    ip_address='127.0.0.1', timestamp=datetime.now(timezone.utc)
                )
            ]
            for l in logs: db.add(l)

        # 3. Seed Policies (Idempotent for ALL 35+ YAML policies + legacy demo policies)
        from manager.rules.rule_loader import RuleLoader
        loader = RuleLoader()
        rules_dir = os.path.join(os.path.dirname(__file__), "manager", "rules", "rules")
        yaml_policies = loader.load_rules_from_files(rules_dir)

        # Seed legacy demo policies if not existing
        legacy_1 = (await db.execute(select(Policy).where(Policy.name == 'Auto-Isolate Ransomware'))).scalar_one_or_none()
        if not legacy_1:
            db.add(Policy(
                id=uuid.uuid4(),
                policy_code='DEMO-001',
                name='Auto-Isolate Ransomware',
                description='Automatically disable network interface if file encryption entropy exceeds threshold.',
                category='impact',
                severity='critical',
                risk_impact=50,
                mitre_technique_id='T1486',
                condition_json={'operator': 'and', 'conditions': [{'field': 'risk_score', 'operator': 'gt', 'value': 75}]},
                actions_json={'action': 'DISABLE_NETWORK'},
                enabled=True,
                priority=1,
                created_at=datetime.now(timezone.utc)
            ))

        legacy_2 = (await db.execute(select(Policy).where(Policy.name == 'Kill Malicious PowerShell Process'))).scalar_one_or_none()
        if not legacy_2:
            db.add(Policy(
                id=uuid.uuid4(),
                policy_code='DEMO-002',
                name='Kill Malicious PowerShell Process',
                description='Terminate process matching encoded PowerShell pattern.',
                category='powershell',
                severity='high',
                risk_impact=30,
                mitre_technique_id='T1059.001',
                condition_json={'operator': 'and', 'conditions': [{'field': 'rule_code', 'operator': 'eq', 'value': 'PROC001'}]},
                actions_json={'action': 'KILL_PROCESS'},
                enabled=True,
                priority=2,
                created_at=datetime.now(timezone.utc)
            ))

        # Seed/update all YAML policies idempotently
        for idx, dto in enumerate(yaml_policies, start=3):
            existing_p = (await db.execute(select(Policy).where(Policy.policy_code == dto.rule_code))).scalar_one_or_none()
            actions_json = {"action": dto.response_action or "ALERT"}
            if not existing_p:
                db.add(Policy(
                    id=uuid.uuid4(),
                    policy_code=dto.rule_code,
                    name=dto.name,
                    description=f"Policy {dto.rule_code}: {dto.name}",
                    category=dto.category,
                    severity=dto.severity,
                    risk_impact=dto.score_impact,
                    mitre_technique_id=dto.mitre_technique_id,
                    condition_json=dto.condition,
                    actions_json=actions_json,
                    priority=idx,
                    enabled=dto.enabled,
                    mode=getattr(dto, "mode", "ALERT_ONLY"),
                    created_at=datetime.now(timezone.utc)
                ))
            else:
                existing_p.name = dto.name
                existing_p.category = dto.category
                existing_p.severity = dto.severity
                existing_p.risk_impact = dto.score_impact
                existing_p.mitre_technique_id = dto.mitre_technique_id
                existing_p.condition_json = dto.condition
                existing_p.actions_json = actions_json
                existing_p.enabled = dto.enabled
                existing_p.mode = getattr(dto, "mode", "ALERT_ONLY")

        # 4. Seed Detection Rules into the `rules` DB table
        # Map MITRE technique IDs used by our rules to their parent tactics
        mitre_map = {
            "T1218.011": ("TA0005", "Defense Evasion",    "Signed Binary Proxy Execution: Rundll32"),
            "T1218.005": ("TA0005", "Defense Evasion",    "Signed Binary Proxy Execution: Mshta"),
            "T1105":     ("TA0011", "Command and Control","Ingress Tool Transfer"),
            "T1059.001": ("TA0002", "Execution",          "Command and Scripting Interpreter: PowerShell"),
            "T1059.003": ("TA0002", "Execution",          "Command and Scripting Interpreter: Windows Command Shell"),
            "T1218.010": ("TA0005", "Defense Evasion",    "Signed Binary Proxy Execution: Regsvr32"),
            "T1562.001": ("TA0005", "Defense Evasion",    "Impair Defenses: Disable or Modify Tools"),
            "T1543.003": ("TA0003", "Persistence",        "Create or Modify System Process: Windows Service"),
            "T1574.011": ("TA0003", "Persistence",        "Hijack Execution Flow: Services Registry Permissions Weakness"),
            "T1053.005": ("TA0003", "Persistence",        "Scheduled Task/Job: Scheduled Task"),
            "T1547.001": ("TA0003", "Persistence",        "Boot or Logon Autostart Execution: Registry Run Keys"),
            "T1546.008": ("TA0003", "Persistence",        "Event Triggered Execution: Accessibility Features"),
            "T1547.004": ("TA0003", "Persistence",        "Boot or Logon Autostart Execution: Winlogon Helper DLL"),
            "T1547.009": ("TA0003", "Persistence",        "Boot or Logon Autostart Execution: Shortcut Modification"),
            "T1486":     ("TA0040", "Impact",             "Data Encrypted for Impact"),
            "T1547.015": ("TA0003", "Persistence",        "Boot or Logon Autostart Execution: Login Items"),
            "T1036.007": ("TA0005", "Defense Evasion",    "Masquerading: Double File Extension"),
            "T1071.001": ("TA0011", "Command and Control","Application Layer Protocol: Web Protocols"),
            "T1046":     ("TA0007", "Discovery",          "Network Service Discovery"),
            "T1571":     ("TA0011", "Command and Control","Non-Standard Port"),
            "T1562.004": ("TA0005", "Defense Evasion",    "Impair Defenses: Disable or Modify System Firewall"),
            "T1091":     ("TA0008", "Lateral Movement",   "Replication Through Removable Media"),
            "T1052.001": ("TA0010", "Exfiltration",       "Exfiltration Over Physical Medium: USB"),
            "T1110.001": ("TA0006", "Credential Access",  "Brute Force: Password Guessing"),
            "T1021.001": ("TA0008", "Lateral Movement",   "Remote Services: Remote Desktop Protocol"),
            "T1134.001": ("TA0004", "Privilege Escalation","Access Token Manipulation: Token Impersonation"),
            "T1489":     ("TA0040", "Impact",             "Service Stop"),
            "T1565.001": ("TA0040", "Impact",             "Data Manipulation: Stored Data Manipulation"),
        }
        # Ensure MITRE tactic/technique rows exist for FK integrity
        existing_tactics = {t.tactic_id for t in (await db.execute(select(MitreTactic))).scalars().all()}
        existing_techs = {t.technique_id for t in (await db.execute(select(MitreTechnique))).scalars().all()}
        for tech_id, (tactic_id, tactic_name, tech_name) in mitre_map.items():
            if tactic_id not in existing_tactics:
                db.add(MitreTactic(tactic_id=tactic_id, name=tactic_name))
                existing_tactics.add(tactic_id)
            if tech_id not in existing_techs:
                db.add(MitreTechnique(technique_id=tech_id, tactic_id=tactic_id, name=tech_name))
                existing_techs.add(tech_id)
        await db.flush()

        # Seed rule rows from YAML into the `rules` table
        for dto in yaml_policies:
            existing_rule = (await db.execute(
                select(RuleModel).where(RuleModel.rule_code == dto.rule_code)
            )).scalar_one_or_none()
            sev_val = dto.severity.lower() if dto.severity else "medium"
            try:
                sev_enum = Severity(sev_val)
            except ValueError:
                sev_enum = Severity.MEDIUM
            mitre_id = dto.mitre_technique_id if dto.mitre_technique_id in existing_techs else None
            if not existing_rule:
                db.add(RuleModel(
                    rule_code=dto.rule_code,
                    name=dto.name,
                    category=dto.category,
                    description=f"Detection rule: {dto.name}",
                    condition_json=dto.condition,
                    severity=sev_enum,
                    mitre_technique_id=mitre_id,
                    enabled=dto.enabled,
                ))
            else:
                existing_rule.name = dto.name
                existing_rule.category = dto.category
                existing_rule.condition_json = dto.condition
                existing_rule.severity = sev_enum
                existing_rule.mitre_technique_id = mitre_id
                existing_rule.enabled = dto.enabled
        print('DB rule seeding complete!')

        await db.commit()
        print('DB policy seeding complete!')

if __name__ == '__main__':
    asyncio.run(seed_data())

