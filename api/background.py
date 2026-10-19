"""One durable SQLite worker shared by dashboard and agent listeners."""
import json
import logging
import os
import threading
from datetime import datetime, timedelta, timezone
from uuid import uuid4
from zta.engine.events.serialization import decode

logger = logging.getLogger(__name__)


class BackgroundWorker:
    def __init__(self, engine):
        self.engine = engine
        self.worker_id = 'manager-' + uuid4().hex
        self.max_attempts = max(1, int(os.environ.get('ZTA_EVENT_MAX_ATTEMPTS', '5')))
        self.retry_base_seconds = max(0.01, float(os.environ.get('ZTA_EVENT_RETRY_BASE_SECONDS', '1')))
        self.stop_event = threading.Event()
        self.wake = threading.Event()
        self.thread = threading.Thread(target=self.run, name='zta-background', daemon=True)
        # A process cannot still own work after restart. Requeue abandoned claims;
        # the event transaction makes replay safe and idempotent.
        with self.engine.repo.db.get_connection() as conn:
            conn.execute("""UPDATE zta_events SET processing_state='FAILED',
                processing_worker_id=NULL, processing_started_at=NULL,
                processing_next_attempt_at=COALESCE(processing_next_attempt_at, ?)
                WHERE processing_state='PROCESSING'""", (datetime.now(timezone.utc).isoformat(),))

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
        hub.recover_pending()
        now = datetime.now(timezone.utc).isoformat()
        with repo.db.transaction() as conn:
            candidates = conn.execute("""SELECT event_id FROM zta_events
                WHERE processing_state='PENDING'
                   OR (processing_state='FAILED' AND processing_attempt_count<?
                       AND processing_next_attempt_at IS NOT NULL AND processing_next_attempt_at<=?)
                ORDER BY timestamp, rowid LIMIT 50""", (self.max_attempts, now)).fetchall()
            ids = [row['event_id'] for row in candidates]
            for event_id in ids:
                conn.execute("""UPDATE zta_events SET processing_state='PROCESSING',
                    processing_attempt_count=processing_attempt_count+1,
                    processing_started_at=?, processing_worker_id=? WHERE event_id=?
                    AND processing_state IN ('PENDING','FAILED')""",
                    (now, self.worker_id, event_id))
            rows = [conn.execute("SELECT * FROM zta_events WHERE event_id=? AND processing_worker_id=?",
                                 (event_id, self.worker_id)).fetchone() for event_id in ids]
            rows = [row for row in rows if row]
        for row in rows:
            try:
                hub.begin()
                self.engine.process_event(decode(json.loads(row['normalized_json'])), row['execution_source'], row['synced_at'])
                hub.commit()
            except Exception as exc:
                hub.rollback()
                attempts = int(row['processing_attempt_count'] or 0)
                terminal = attempts >= self.max_attempts
                retry_at = (datetime.now(timezone.utc) + timedelta(
                    seconds=min(300, self.retry_base_seconds * (2 ** max(0, attempts - 1))))).isoformat()
                error = f'{type(exc).__name__}: {exc}'[:2000]
                with repo.db.transaction() as conn:
                    conn.execute("""UPDATE zta_events SET processing_state=?, processing_error=?,
                        processing_last_error_at=?, processing_next_attempt_at=?,
                        processing_started_at=NULL, processing_worker_id=NULL WHERE event_id=?""",
                        ('FAILED', error,
                         datetime.now(timezone.utc).isoformat(), None if terminal else retry_at, row['event_id']))
                    repo.save_audit('EVENT_PROCESSING_DEAD_LETTERED' if terminal else 'EVENT_PROCESSING_RETRY',
                                    'Automatic detection processing failed', row['agent_id'],
                                    details={'event_id': row['event_id'], 'attempt': attempts,
                                             'max_attempts': self.max_attempts, 'retry_at': None if terminal else retry_at,
                                             'error': error}, status='FAILED')
                repo.update_service_heartbeat('Rule Engine', 'FAILED', {'event_id': row['event_id'], 'error': error})
                logger.exception('Event processing failed')
        now = datetime.now(timezone.utc).isoformat()
        hub.begin()
        with repo.db.transaction() as conn:
            for agent in repo.get_agents():
                stored = conn.execute('SELECT connection_state FROM agents WHERE id=?', (agent['id'],)).fetchone()[0]
                evaluated = agent['connection_state']
                if evaluated in ('DEGRADED', 'OFFLINE') and stored != evaluated:
                    conn.execute("UPDATE agents SET connection_state=? WHERE id=?", (evaluated, agent['id']))
                    event = 'AGENT_OFFLINE' if evaluated == 'OFFLINE' else 'AGENT_DEGRADED'
                    repo.save_audit(event, 'Manager heartbeat liveness threshold exceeded', agent['id'],
                                    details={'manager_received_time': agent.get('manager_received_time')}, status=evaluated)
                    hub.broadcast('agent.' + evaluated.lower(), {'agent_id': agent['id'], 'connection_state': evaluated})
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
        repo.prune_realtime_outbox(int(os.environ.get('ZTA_OUTBOX_RETENTION', '1000')))
