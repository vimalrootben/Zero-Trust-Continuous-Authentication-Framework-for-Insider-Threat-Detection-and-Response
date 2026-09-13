"""Background endpoint monitoring, authenticated commands and durable reconnect."""
import hashlib
import json
import logging
import os
import platform
import threading
import time
from dataclasses import asdict
from datetime import datetime, timezone
from types import SimpleNamespace

import requests
from zta.agent.commands.authorization import verify, sign, canonical
from zta.agent.commands.command_receiver import AgentCommandReceiver, CommandValidationError
from zta.agent.storage.offline_queue import OfflineQueue
from zta.agent.state import AgentState
from zta.agent.collectors import WindowsEventCollector, JsonlCollector
from zta.agent.rules.local_rule_engine import LocalRuleEngine
from zta.engine.events.serialization import encode
from zta.engine.events.wazuh_adapter import ZTAEventAdapter
from zta.agent.network_identity import get_active_network_identity

logger = logging.getLogger(__name__)


def default_command_validator(payload):
    raise CommandValidationError('Agent identity and authorization must be configured')


class ZTAAgentDaemon:
    def __init__(self, manager_url='http://127.0.0.1:8080', db_path='storage/zta_agent_offline.db', agent_id=None, token=None, telemetry_path=None):
        self.manager_url = manager_url.rstrip('/')
        self.agent_id = agent_id or os.environ.get('ZTA_AGENT_ID') or platform.node()
        self.token = token if token is not None else os.environ.get('ZTA_AGENT_TOKEN', '')
        self.hostname, self.os_type = platform.node(), platform.system()
        self.offline_queue = OfflineQueue(db_path=db_path)
        self.state = AgentState(self.offline_queue)
        self.command_receiver = AgentCommandReceiver(command_validator=self.validate_command)
        self.local_rule_engine = LocalRuleEngine([])
        self.connection_state = 'RECONNECTING'
        self.is_running = False
        self.stop_event = threading.Event()
        self.local_lock = threading.RLock()
        self.local_engine = None
        self.collector_error = None
        path = telemetry_path or os.environ.get('ZTA_TELEMETRY_PATH')
        self.collector = JsonlCollector(path, self.state) if path else WindowsEventCollector(self.state)

    def validate_command(self, command):
        verify(command, self.token, self.agent_id)
        if not command.get('command_id') or command.get('status') not in ('DISPATCHED','QUEUED'):
            raise CommandValidationError('Command identity/state invalid')
        if command.get('execution_source') == 'AGENT_OFFLINE':
            cache = verify(self.state.get('configuration') or {}, self.token, self.agent_id)
            policy = next((p for p in cache['policies'] if p['policy_id'] == command.get('policy_id')), None)
            if not policy or not policy.get('enabled') or not policy.get('allow_offline') or policy.get('mode') != 'ENFORCE' or policy['action'] != command.get('action_type'):
                raise CommandValidationError('Offline policy authorization denied')

    def post(self, path, payload, timeout=10):
        # Requests verifies HTTPS certificates by default. Remote cleartext credentials are refused.
        from urllib.parse import urlparse
        url = urlparse(self.manager_url)
        if url.scheme != 'https' and url.hostname not in ('127.0.0.1','localhost','::1'):
            raise ValueError('Remote agent communication requires HTTPS')
        return requests.post(self.manager_url+path, json=payload, headers={'Authorization': 'Bearer '+self.token}, timeout=timeout)

    def get_system_telemetry(self):
        net_info = get_active_network_identity(self.manager_url)
        return {'agent_id': self.agent_id, 'hostname': self.hostname, 'os': self.os_type,
                'agent_version': '0.1.0', 'platform': platform.platform(), 'python_version':platform.python_version(),
                'connection_state': self.connection_state, 'queue_depth': self.offline_queue.queue_depth(),
                'sync_state': 'SYNCING' if self.connection_state == 'SYNCING' else 'IDLE',
                'collector_error': self.collector_error,
                'local_ipv4': net_info.get('local_ipv4'),
                'local_ipv6': net_info.get('local_ipv6'),
                'active_interface': net_info.get('active_interface'),
                'interface_name': net_info.get('interface_name'),
                'ip': net_info.get('ip'),
                'interfaces': net_info.get('interfaces', []),
                'timestamp': datetime.now(timezone.utc).isoformat().replace('+00:00','Z')}

    def emit_log(self, level, event_type, message, component='AGENT', correlation_id=None, metadata=None):
        """Emits structured operational log to Manager or local offline queue."""
        log_entry = {
            'log_id': f"log-{hashlib.sha256((str(time.time())+message).encode()).hexdigest()[:16]}",
            'timestamp': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            'agent_id': self.agent_id,
            'hostname': self.hostname,
            'level': level.upper(),
            'component': component,
            'event_type': event_type,
            'message': message,
            'correlation_id': correlation_id,
            'metadata': metadata or {},
        }
        if self.connection_state == 'ONLINE':
            try:
                self.post('/api/v1/agents/logs', log_entry, timeout=3)
            except Exception:
                self.offline_queue.enqueue(log_entry['log_id'], 'OPERATIONAL_LOG', 'LOW', {'id': log_entry['log_id'], 'log_entry': log_entry})
        else:
            self.offline_queue.enqueue(log_entry['log_id'], 'OPERATIONAL_LOG', 'LOW', {'id': log_entry['log_id'], 'log_entry': log_entry})

    def configure(self, cache):
        verify(cache, self.token, self.agent_id)
        with self.local_lock:
            self.state.set('configuration', cache)
            from zta.storage.database import ZTADatabase, ZTARepository
            from zta.api.server import ZTABackgroundEngine, WebSocketHub
            repo = ZTARepository(ZTADatabase(self.offline_queue.db_path, seed_defaults=False))
            with repo.db.transaction() as conn:
                for table in ('rules','policies'):
                    conn.execute('DELETE FROM '+table)
                    columns = {r['name'] for r in conn.execute('PRAGMA table_info('+table+')')}
                    for definition in cache[table]:
                        data = {k:v for k,v in definition.items() if k in columns}
                        data['condition_json'] = json.dumps(definition.get('condition'))
                        keys = list(data)
                        conn.execute('INSERT INTO '+table+' ('+','.join(keys)+') VALUES ('+','.join('?' for _ in keys)+')', [data[k] for k in keys])
            self.local_engine = ZTABackgroundEngine(repo, WebSocketHub())
            self.local_engine.offline_enforcement = True
            self.local_rule_engine = LocalRuleEngine([r for r in cache['rules'] if r.get('enabled') and r.get('allow_offline')])

    def execute_command(self, command):
        self.validate_command(command)
        command_id = command['command_id']
        with self.offline_queue._get_connection() as conn:
            conn.execute('BEGIN IMMEDIATE')
            existing = conn.execute('SELECT * FROM command_journal WHERE command_id=?', (command_id,)).fetchone()
            if existing:
                if existing['report']: return json.loads(existing['report'])
                # Never replay an action whose outcome was lost on process/power failure.
                report = dict(command_id=command_id, agent_id=self.agent_id, action_type=command['action_type'], status='FAILED',
                              error='INTERRUPTED: execution outcome is unknown; action was not repeated', output='', verification=None,
                              executed_at='', completed_at=datetime.now(timezone.utc).isoformat())
                conn.execute('UPDATE command_journal SET report=? WHERE command_id=?', (json.dumps(report),command_id))
                return report
            conn.execute('INSERT INTO command_journal (command_id,payload) VALUES (?,?)', (command_id,json.dumps(command)))
        started = datetime.now(timezone.utc).isoformat()
        if command.get('execution_source') != 'AGENT_OFFLINE':
            try:
                self.post('/api/v1/commands/result', {'command_id': command_id, 'agent_id': self.agent_id, 'status':'EXECUTING','executed_at':started})
            except Exception: logger.warning('Execution-start upload failed; result remains durable')
        report = asdict(self.command_receiver.process_command(command))
        report.update(agent_id=self.agent_id, completed_at=datetime.now(timezone.utc).isoformat())
        with self.offline_queue._get_connection() as conn:
            conn.execute('UPDATE command_journal SET report=? WHERE command_id=?', (json.dumps(report),command_id))
        return report

    def upload_results(self):
        with self.offline_queue._get_connection() as conn:
            rows = conn.execute('SELECT * FROM command_journal WHERE report IS NOT NULL AND reported=0').fetchall()
        for row in rows:
            if json.loads(row['payload']).get('execution_source') == 'AGENT_OFFLINE': continue
            response = self.post('/api/v1/commands/result', json.loads(row['report']))
            if response.status_code == 200:
                with self.offline_queue._get_connection() as conn:
                    conn.execute('UPDATE command_journal SET reported=1 WHERE command_id=?', (row['command_id'],))

    def process_offline_event(self, event):
        with self.local_lock:
            with self.offline_queue._get_connection() as conn:
                queued = conn.execute('SELECT payload_json FROM offline_events WHERE event_id=?', (event.event_id,)).fetchone()
            if queued:
                payload = json.loads(queued[0])
                if payload.get('normalized_event') != encode(event): raise ValueError('Conflicting event identity')
                return payload.get('offline_evidence')
            evidence = None
            cache = self.state.get('configuration')
            try:
                if not self.local_engine and cache: self.configure(cache)
                if cache: verify(cache, self.token, self.agent_id)
            except Exception as exc:
                logger.warning('Offline cache unavailable: %s', exc)
                cache = None
            if cache and self.local_engine:
                repo = self.local_engine.repo
                repo.save_event(event, 'AGENT_OFFLINE')
                self.local_engine.process_event(event, 'AGENT_OFFLINE')
                with repo.db.get_connection() as conn:
                    matches = [dict(r) for r in conn.execute('SELECT * FROM rule_matches WHERE event_id=?',(event.event_id,))]
                alerts = [m['alert_id'] for m in matches]
                for alert_id in alerts:
                    for command in repo.get_commands_for_alert(alert_id):
                        if command['status'] not in ('QUEUED','DISPATCHED'): continue
                        command['status'] = 'DISPATCHED'
                        repo.save_command(command)
                        report = self.execute_command(sign(command, self.token))
                        from zta.api.ingestion import command_result
                        command_result(SimpleNamespace(repo=repo,hub=self.local_engine.hub), report)
                evidence = {'configuration': cache, 'evaluated_at': datetime.now(timezone.utc).isoformat(), 'rule_matches': [], 'incidents': [], 'commands': [], 'policy_evaluations': [], 'audit': [], 'rule_evaluations': [], 'risk_history': []}
                for match in matches:
                    match['matched_conditions'] = json.loads(match['matched_conditions_json'])
                    evidence['rule_matches'].append(match)
                with repo.db.get_connection() as conn:
                    evidence['rule_evaluations'] = [dict(r) for r in conn.execute('SELECT * FROM rule_evaluations WHERE event_id=?',(event.event_id,))]
                    for alert_id in alerts:
                        incident = repo.get_incident_by_id(alert_id)
                        incident['detection_json'] = incident['detection']
                        evidence['incidents'].append(incident)
                        evidence['commands'].extend(incident['commands'])
                        evidence['policy_evaluations'].extend(incident['policy_evaluations'])
                        evidence['risk_history'].extend(incident['risk_history'])
                        evidence['audit'].extend(incident['audit'])
            payload = {'id': event.event_id, 'normalized_event': encode(event), 'execution_source':'AGENT_OFFLINE'}
            if evidence: payload['offline_evidence'] = evidence
            self.offline_queue.enqueue(event.event_id, event.event_type, event.severity, payload)
            return evidence

    def collect(self, raw):
        raw = dict(raw)
        raw.setdefault('agent', {'id': self.agent_id, 'name': self.hostname})
        event = ZTAEventAdapter.from_dict(raw)
        if event.agent.id != self.agent_id: raise ValueError('Collector event belongs to another agent')
        if self.connection_state != 'ONLINE':
            self.process_offline_event(event)
        else:
            self.offline_queue.enqueue(event.event_id,event.event_type,event.severity, {'id':event.event_id,'normalized_event':encode(event),'execution_source':'AGENT_ONLINE'})

    def send_heartbeat(self):
        previous_state = self.connection_state
        if self.connection_state == 'OFFLINE': self.connection_state = 'RECONNECTING'
        try:
            response = self.post('/api/v1/agents/heartbeat', self.get_system_telemetry(), timeout=5)
            if response.status_code != 200: raise ValueError('Heartbeat rejected: '+str(response.status_code))
            data = response.json()
            if data.get('configuration'): self.configure(data['configuration'])
            self.connection_state = 'SYNCING' if self.offline_queue.queue_depth() else 'ONLINE'
            for command in data.get('pending_commands', []):
                try: self.execute_command(command)
                except Exception: logger.exception('Rejected command')
            self.upload_results()
            return True
        except Exception as exc:
            self.connection_state = 'OFFLINE'
            if previous_state != 'OFFLINE':
                stamp = datetime.now(timezone.utc).isoformat()
                self.offline_queue.enqueue('connection-'+hashlib.sha256(stamp.encode()).hexdigest(), 'HEARTBEAT_FAILURE', 'LOW',
                    {'id':'connection-'+hashlib.sha256(stamp.encode()).hexdigest(), 'telemetry':self.get_system_telemetry(), 'error':str(exc)})
            logger.warning('Manager communication failed: %s', exc)
            return False

    def sync_offline_queue(self):
        pending = self.offline_queue.dequeue_batch(50)
        if not pending: return
        self.connection_state = 'SYNCING'
        records = [p['payload'] for p in pending]
        payload = {'agent_id': self.agent_id, 'batch_id': hashlib.sha256(canonical(records)).hexdigest(), 'telemetry': records}
        try:
            response = self.post('/api/v1/sync/offline', payload)
            if response.status_code not in (200,201):
                self.connection_state = 'DEGRADED'
                return
            accepted = response.json().get('accepted_event_ids')
            if not isinstance(accepted,list) or not all(isinstance(i,str) for i in accepted):
                self.connection_state = 'DEGRADED'
                return
            self.offline_queue.mark_synced([p['event_id'] for p in pending if p['event_id'] in accepted])
            self.connection_state = 'SYNCING' if self.offline_queue.queue_depth() else 'ONLINE'
        except Exception as exc:
            self.connection_state = 'OFFLINE'
            logger.warning('Sync failed; evidence retained: %s', exc)

    def collection_loop(self):
        while not self.stop_event.is_set():
            try:
                self.collector.poll(self.collect)
                self.collector_error = None
            except Exception as exc:
                self.collector_error = str(exc)
                logger.warning('Collector failed: %s', exc)
            self.stop_event.wait(2)

    def run_loop(self, interval=30):
        self.is_running = True
        collector = threading.Thread(target=self.collection_loop, name='zta-collectors',daemon=True)
        collector.start()
        try:
            while self.is_running and not self.stop_event.is_set():
                if self.send_heartbeat():
                    self.sync_offline_queue()
                    self.upload_results()
                self.stop_event.wait(interval)
        finally:
            self.stop_event.set()
            collector.join(timeout=20)


def main():
    """CLI entry point for ZTA Endpoint Agent daemon."""
    import argparse
    from pathlib import Path
    parser = argparse.ArgumentParser(description='ZTA background endpoint agent')
    parser.add_argument('--config', help='Protected agent environment configuration file')
    parser.add_argument('--manager-url', default=os.environ.get('ZTA_MANAGER_URL', 'http://127.0.0.1:8080'), help='Manager API endpoint URL')
    parser.add_argument('--agent-id', default=os.environ.get('ZTA_AGENT_ID', 'agent-unknown'), help='Agent identifier')
    parser.add_argument('--token', default=os.environ.get('ZTA_AGENT_TOKEN', ''), help='Agent authentication token')
    parser.add_argument('--db', default=os.environ.get('ZTA_LOCAL_DB_PATH', 'storage/zta_agent_offline.db'), help='Local SQLite database path')
    parser.add_argument('--interval', type=int, default=int(os.environ.get('ZTA_HEARTBEAT_INTERVAL', '15')), help='Heartbeat interval in seconds')
    args = parser.parse_args()
    if args.config:
        for line in Path(args.config).read_text(encoding='utf-8-sig').splitlines():
            if line.strip() and not line.lstrip().startswith('#'):
                key, value = line.split('=', 1)
                if key.strip().startswith('ZTA_'):
                    os.environ[key.strip()] = value.strip()
    logging.basicConfig(level=logging.INFO)
    manager_url = os.environ.get('ZTA_MANAGER_URL', args.manager_url)
    db_path = os.environ.get('ZTA_LOCAL_DB_PATH', args.db)
    agent_id = os.environ.get('ZTA_AGENT_ID', args.agent_id)
    token = os.environ.get('ZTA_AGENT_TOKEN', args.token)
    interval = int(os.environ.get('ZTA_HEARTBEAT_INTERVAL', str(args.interval)))
    daemon = ZTAAgentDaemon(manager_url=manager_url, db_path=db_path, agent_id=agent_id, token=token)
    try:
        daemon.run_loop(interval)
    except KeyboardInterrupt:
        daemon.stop_event.set()


if __name__ == '__main__':
    main()
