import asyncio
from manager.database.session import async_session_maker
from manager.database.models.agent import Agent, AgentStatus
from manager.database.models.alert import Alert, AlertStatus
from manager.database.models.audit import AuditLog, ActorType
from manager.database.models.policy import Policy
from manager.database.models.rule import Severity
from sqlalchemy import select
from datetime import datetime, timezone
import uuid

async def seed_data():
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

        # 3. Seed Policies
        policy_rows = (await db.execute(select(Policy))).scalars().all()
        if not policy_rows:
            policies = [
                Policy(
                    id=uuid.uuid4(), name='Auto-Isolate Ransomware',
                    description='Automatically disable network interface if file encryption entropy exceeds threshold.',
                    condition_json={'operator': 'and', 'conditions': [{'field': 'risk_score', 'operator': 'gt', 'value': 75}]},
                    actions_json={'action': 'DISABLE_NETWORK'}, enabled=True, priority=1, created_at=datetime.now(timezone.utc)
                ),
                Policy(
                    id=uuid.uuid4(), name='Kill Malicious PowerShell Process',
                    description='Terminate process matching encoded PowerShell pattern.',
                    condition_json={'operator': 'and', 'conditions': [{'field': 'rule_code', 'operator': 'eq', 'value': 'PROC001'}]},
                    actions_json={'action': 'KILL_PROCESS'}, enabled=True, priority=2, created_at=datetime.now(timezone.utc)
                )
            ]
            for p in policies: db.add(p)

        await db.commit()
        print('DB seeding complete!')

if __name__ == '__main__':
    asyncio.run(seed_data())
