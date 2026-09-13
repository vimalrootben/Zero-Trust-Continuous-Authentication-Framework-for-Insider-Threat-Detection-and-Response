"""One durable SQLite worker shared by dashboard and agent listeners."""
import json
import logging
import threading
from datetime import datetime, timezone
from zta.engine.events.serialization import decode

logger = logging.getLogger(__name__)


class BackgroundWorker:
    def __init__(self, engine):
        self.engine = engine
        self.stop_event = threading.Event()
        self.wake = threading.Event()
        self.thread = threading.Thread(target=self.run, name='zta-background', daemon=True)

    def start(self):
        self.thread.start()

    def close(self):
        self.stop_event.set()
        self.wake.set()
        self.thread.join(timeout=35)
        for name in ('Telemetry Processor', 'Rule Engine', 'Policy Engine', 'Command Dispatcher', 'Heartbeat Monitor', 'Offline Sync Processor', 'WebSocket Hub'):
            self.engine.repo.update_service_heartbeat(name, 'STOPPED')

    def run(self):
        while not self.stop_event.is_set():
            self.wake.clear()
            try:
                self.tick()
            except Exception:
                self.engine.hub.rollback()
                logger.exception('Background cycle failed')
                self.engine.repo.update_service_heartbeat('Telemetry Processor', 'FAILED')
            self.wake.wait(1)

    def tick(self):
        repo, hub = self.engine.repo, self.engine.hub
        with repo.db.get_connection() as conn:
            rows = conn.execute("SELECT * FROM zta_events WHERE processing_state='PENDING' ORDER BY rowid LIMIT 50").fetchall()
        for row in rows:
            try:
                hub.begin()
                self.engine.process_event(decode(json.loads(row['normalized_json'])), row['execution_source'], row['synced_at'])
                hub.commit()
            except Exception as exc:
                hub.rollback()
                with repo.db.get_connection() as conn:
                    conn.execute("UPDATE zta_events SET processing_state='FAILED', processing_error=? WHERE event_id=?", (str(exc), row['event_id']))
                repo.update_service_heartbeat('Rule Engine', 'FAILED', {'event_id': row['event_id'], 'error': str(exc)})
                logger.exception('Event processing failed')
        now = datetime.now(timezone.utc).isoformat()
        hub.begin()
        with repo.db.transaction() as conn:
            for agent in repo.get_agents():
                stored = conn.execute('SELECT connection_state FROM agents WHERE id=?', (agent['id'],)).fetchone()[0]
                if agent['connection_state'] == 'OFFLINE' and stored != 'OFFLINE':
                    conn.execute("UPDATE agents SET connection_state='OFFLINE' WHERE id=?", (agent['id'],))
                    repo.save_audit('AGENT_OFFLINE', 'Heartbeat deadline exceeded', agent['id'])
                    hub.broadcast('agent.offline', {'agent_id': agent['id']})
            commands = conn.execute("SELECT * FROM commands WHERE status IN ('PENDING','QUEUED','AUTHORIZED','DISPATCHED','EXECUTING') AND (expires_at IS NULL OR expires_at<=?)", (now,)).fetchall()
            for cmd in commands:
                conn.execute("UPDATE commands SET status='EXPIRED', error_message='Command expired before confirmed completion', completed_at=? WHERE command_id=?", (now, cmd['command_id']))
                conn.execute("UPDATE incidents SET response_status='EXPIRED', updated_at=? WHERE incident_id=?", (now, cmd['alert_id']))
                repo.save_audit('COMMAND_EXPIRED', cmd['action_type'], cmd['agent_id'], details={'command_id': cmd['command_id'], 'alert_id': cmd['alert_id']}, status='EXPIRED')
                hub.broadcast('response.failed', {'command_id': cmd['command_id'], 'status': 'EXPIRED'})
            # Apply existing risk decay only when no unresolved critical incident exists.
            import os
            from zta.engine.risk.engine import RiskEvent
            decay_rate = max(0, float(os.environ.get('ZTA_RISK_DECAY_PER_MINUTE','1')))
            risk_agents = conn.execute('SELECT DISTINCT agent_id FROM risk_history').fetchall()
            for identity in risk_agents:
                latest = conn.execute('SELECT * FROM risk_history WHERE agent_id=? ORDER BY timestamp DESC,id DESC LIMIT 1',(identity[0],)).fetchone()
                active = conn.execute("SELECT 1 FROM incidents WHERE agent_id=? AND severity='CRITICAL' AND status NOT IN ('RESOLVED','CLOSED','FALSE_POSITIVE')",(identity[0],)).fetchone()
                elapsed = (datetime.now(timezone.utc)-datetime.fromisoformat(latest['timestamp'])).total_seconds()/60
                decrement = min(latest['new_score'], max(0,int(elapsed*decay_rate)))
                if decrement and not active:
                    risk = RiskEvent(datetime.now(timezone.utc), identity[0], latest['new_score'], -decrement, latest['new_score']-decrement, 'Background risk decay')
                    repo.save_risk_event(risk)
                    repo.save_audit('RISK_UPDATED',risk.reason,identity[0],details={'previous_score':risk.previous_score,'new_score':risk.new_score})
                    hub.broadcast('risk.updated',{'agent_id':identity[0],'risk_score':risk.new_score})
            failed = conn.execute("SELECT COUNT(*) FROM zta_events WHERE processing_state='FAILED'").fetchone()[0]
        hub.commit()
        for name in ('Telemetry Processor', 'Rule Engine', 'Policy Engine', 'Command Dispatcher', 'Heartbeat Monitor', 'Offline Sync Processor', 'WebSocket Hub'):
            repo.update_service_heartbeat(name, 'DEGRADED' if failed and name in ('Telemetry Processor', 'Rule Engine', 'Policy Engine') else 'RUNNING', {'failed_events': failed} if failed else {}, activity=False)
