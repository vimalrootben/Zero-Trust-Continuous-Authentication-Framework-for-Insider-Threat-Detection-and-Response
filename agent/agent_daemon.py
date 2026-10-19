"""Background endpoint monitoring, authenticated commands and durable reconnect."""
import hashlib
import hmac
import json
import logging
import os
import platform
import sys
import threading
import time
import queue
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
from zta.agent.workers import BackgroundWorkerSupervisor
from zta.agent.connection import ConnectionStateMachine

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
        self.offline_queue.recover_interrupted_commands(self.agent_id)
        self.state = AgentState(self.offline_queue)
        if not self.state.get('legacy_batch_rejections_recovered', False):
            recovered = self.offline_queue.recover_legacy_batch_rejections()
            self.state.set('legacy_batch_rejections_recovered', True)
            if recovered:
                logger.warning('telemetry.legacy_batch_rejections_recovered', extra={
                    'event_type': 'TELEMETRY_LEGACY_BATCH_REJECTIONS_RECOVERED',
                    'count': recovered,
                })
        from urllib.parse import urlparse
        self.command_receiver = AgentCommandReceiver(
            command_validator=self.validate_command,
            agent_id=self.agent_id,
            manager_address=urlparse(self.manager_url).hostname,
        )
        self.local_rule_engine = LocalRuleEngine([])
        self.is_running = False
        self.stop_event = threading.Event()
        self.local_lock = threading.RLock()
        self.local_engine = None
        self.collector_error = None
        self.connection = ConnectionStateMachine(self.state)
        self.command_queue = queue.Queue(maxsize=max(1, int(os.environ.get('ZTA_COMMAND_QUEUE_SIZE', '100'))))
        self.last_telemetry_at = None
        self._last_network_identity = None
        self._last_worker_warning = {}
        self._last_sync_warning = {}
        self.worker_supervisor = BackgroundWorkerSupervisor(self.stop_event, self._worker_transition)
        path = telemetry_path or os.environ.get('ZTA_TELEMETRY_PATH')
        self.collector = JsonlCollector(path, self.state) if path else WindowsEventCollector(self.state)
        self._register_workers(path is not None)

    def _register_workers(self, jsonl=False):
        collector_interval = float(os.environ.get('ZTA_COLLECTOR_INTERVAL', '5'))
        process_interval = float(os.environ.get('ZTA_PROCESS_INTERVAL', '5'))
        network_interval = float(os.environ.get('ZTA_NETWORK_INTERVAL', '5'))
        heartbeat_interval = float(os.environ.get('ZTA_HEARTBEAT_INTERVAL', '15'))
        if jsonl:
            self.worker_supervisor.register('telemetry-collector', lambda: self.collector.poll(self.collect), collector_interval)
        else:
            self.worker_supervisor.register('event-collector', lambda: self.collector.poll_events(self.collect), collector_interval)
            self.worker_supervisor.register('process-collector', lambda: self.collector.poll_processes(self.collect), process_interval)
            self.worker_supervisor.register('network-collector', lambda: self.collector.poll_network(self.collect), network_interval)
        reconnect_max = float(os.environ.get('ZTA_RECONNECT_MAX_DELAY', '300'))
        reconnect_jitter = float(os.environ.get('ZTA_RECONNECT_JITTER', '0.2'))
        self.worker_supervisor.register('heartbeat-worker', self.heartbeat_cycle, heartbeat_interval,
                                        max_backoff=reconnect_max, jitter_fraction=reconnect_jitter)
        self.worker_supervisor.register('telemetry-upload-worker', self.telemetry_cycle,
                                        float(os.environ.get('ZTA_UPLOAD_INTERVAL', '2')), max_backoff=60, jitter_fraction=0.1)
        self.worker_supervisor.register('command-worker', self.command_cycle, 0.1, max_backoff=5)

    @property
    def connection_state(self):
        return self.connection.state

    @connection_state.setter
    def connection_state(self, value):
        self.connection.transition(value, reason='compatibility assignment', force=True)

    def _worker_transition(self, status):
        state = status['current_state']
        event_type = {
            'STARTING': 'WORKER_STARTING', 'RUNNING': 'WORKER_STARTED',
            'DEGRADED': 'WORKER_FAILED', 'RESTARTING': 'WORKER_RESTARTING',
            'STOPPED': 'WORKER_STOPPED', 'FAILED': 'WORKER_FAILED',
        }.get(state, 'WORKER_STATE_CHANGED')
        warning_key = (status['worker_name'], state, status.get('last_error') or '')
        now = time.monotonic()
        noisy = state in ('DEGRADED', 'RESTARTING')
        emit = not noisy or now - self._last_worker_warning.get(warning_key, 0) >= 300
        if emit:
            self._last_worker_warning[warning_key] = now
            self.emit_log('ERROR' if state == 'FAILED' else 'WARNING' if noisy else 'INFO',
                          event_type, f"{status['worker_name']} entered {state}", component='WORKER_SUPERVISOR',
                          metadata={'worker_name': status['worker_name'], 'state': state,
                                    'restart_count': status['restart_count'],
                                    'error': (status.get('last_error') or '')[:1000] or None})
        if state in ('DEGRADED', 'FAILED', 'RESTARTING'):
            self.collector_error = status.get('last_error')
            if emit:
                logger.warning('%s entered %s: %s', status['worker_name'], status['current_state'], status.get('last_error'))
        elif status['current_state'] == 'RUNNING':
            unhealthy = [item for item in self.worker_supervisor.snapshot().values()
                         if item['current_state'] in ('DEGRADED', 'FAILED', 'RESTARTING')]
            self.collector_error = '; '.join(f"{item['worker_name']}: {item['last_error']}" for item in unhealthy) or None

    def heartbeat_cycle(self):
        if not self.send_heartbeat():
            raise ConnectionError('Authenticated Manager heartbeat failed')

    connection_cycle = heartbeat_cycle

    def telemetry_cycle(self):
        if self.connection_state not in ('ONLINE', 'SYNCING'):
            return
        if not self.sync_offline_queue():
            return
        self.upload_results()

    def command_cycle(self):
        try:
            command = self.command_queue.get_nowait()
        except queue.Empty:
            return
        try:
            self.execute_command(command)
            self.upload_results()
        finally:
            self.command_queue.task_done()

    def validate_command(self, command):
        verify(command, self.token, self.agent_id)
        if not command.get('command_id') or command.get('status') not in ('DISPATCHED','QUEUED'):
            raise CommandValidationError('Command identity/state invalid')
        if command.get('execution_source') == 'AGENT_OFFLINE':
            if command.get('action_type') in ('KILL_PROCESS', 'LOGOUT_USER', 'LOGOFF_USER', 'LOGOUT_SESSION',
                                               'LOCK_LOCAL_ACCOUNT', 'UNLOCK_LOCAL_ACCOUNT'):
                raise CommandValidationError('Offline destructive action is disabled pending native verification')
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
        verify_target = os.environ.get('ZTA_CA_BUNDLE') or True
        client_cert, client_key = os.environ.get('ZTA_CLIENT_CERT'), os.environ.get('ZTA_CLIENT_KEY')
        if bool(client_cert) != bool(client_key):
            raise ValueError('Both ZTA_CLIENT_CERT and ZTA_CLIENT_KEY are required for mTLS')
        cert = (client_cert, client_key) if client_cert and client_key else None
        return requests.post(self.manager_url+path, json=payload, headers={'Authorization': 'Bearer '+self.token},
                             timeout=timeout, verify=verify_target, cert=cert)

    def get_system_telemetry(self):
        heartbeat_timestamp = datetime.now(timezone.utc).isoformat().replace('+00:00','Z')
        net_info = get_active_network_identity(self.manager_url)
        previous = self._last_network_identity
        identity_key = (net_info.get('local_ipv4'), net_info.get('local_ipv6'), net_info.get('interface_name'))
        network_change = None
        if previous and previous != identity_key:
            network_change = {'previous': previous, 'current': identity_key, 'detected_at': datetime.now(timezone.utc).isoformat()}
        self._last_network_identity = identity_key
        try:
            from zta.powershell.windows_sessions import WindowsSessions
            sessions = WindowsSessions().sessions()
        except Exception:
            sessions = []
        state_path = os.path.join(os.environ.get('ProgramData','C:\\ProgramData'), 'ZTA', 'network-isolation-state.json')
        network_state = {'enabled':os.environ.get('ZTA_ENABLE_NETWORK_ISOLATION','false').lower() == 'true',
                         'isolated':os.path.exists(state_path), 'manager_connectivity':self.connection_state,
                         'firewall_state':'ISOLATED' if os.path.exists(state_path) else 'NORMAL'}
        inventory_limit = max(0, int(os.environ.get('ZTA_HEARTBEAT_INVENTORY_LIMIT', '1000')))
        listening_ports = list(getattr(self.collector, 'listening_ports', []))
        process_inventory = list(getattr(self.collector, 'process_inventory', []))
        return {'agent_id': self.agent_id, 'hostname': self.hostname, 'os': self.os_type,
                'agent_version': '0.1.0', 'platform': platform.platform(), 'python_version':platform.python_version(),
                'connection_state': self.connection_state, 'queue_depth': self.offline_queue.pending_depth(),
                'quarantined_telemetry_count': self.offline_queue.permanent_error_count(),
                'sync_state': 'SYNCING' if self.connection_state == 'SYNCING' else 'IDLE',
                'collector_error': self.collector_error,
                'worker_health': self.worker_supervisor.snapshot(),
                'last_telemetry_at': self.last_telemetry_at,
                'last_collected_event_at': self.last_telemetry_at,
                'pending_telemetry_count': self.offline_queue.pending_depth(),
                'oldest_pending_age_seconds': self.offline_queue.oldest_pending_age_seconds(),
                'network_change': network_change,
                'local_ipv4': net_info.get('local_ipv4'),
                'local_ipv6': net_info.get('local_ipv6'),
                'active_interface': net_info.get('active_interface'),
                'interface_name': net_info.get('interface_name'),
                'ip': net_info.get('ip'),
                'interfaces': net_info.get('interfaces', []),
                'listening_ports': listening_ports[:inventory_limit],
                'process_inventory': process_inventory[:inventory_limit],
                'inventory_truncated': len(listening_ports) > inventory_limit or len(process_inventory) > inventory_limit,
                'sessions': sessions,
                'network_state': network_state,
                'timestamp': heartbeat_timestamp, 'heartbeat_timestamp': heartbeat_timestamp}

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
        if self.connection_state == 'ONLINE' and not self.stop_event.is_set():
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
            self.state.set('configuration_rejected_signature', None)
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
        received_at = datetime.now(timezone.utc).isoformat()
        params = command.get('params') or {}
        target_identity = json.dumps(params, sort_keys=True)
        with self.offline_queue._get_connection() as conn:
            conn.execute('BEGIN IMMEDIATE')
            existing = conn.execute('SELECT * FROM command_journal WHERE command_id=?', (command_id,)).fetchone()
            if existing:
                if existing['report']: return json.loads(existing['report'])
                # Another thread owns the durable claim. Never race it or repeat the action.
                return dict(command_id=command_id, agent_id=self.agent_id, action_type=command['action_type'],
                            status='UNKNOWN', error='Command already has an unfinished execution claim',
                            error_code='EXECUTION_IN_PROGRESS', output='', verification='UNKNOWN',
                            verification_status='UNKNOWN', executed_at=existing['execution_started_at'] or '',
                            completed_at='', correlation_id=existing['correlation_id'] or '')
            correlation_id = str(command.get('correlation_id') or command.get('params', {}).get('correlation_id') or '')
            safe_payload = {k: v for k, v in command.items() if k != 'signature'}
            conn.execute('''INSERT INTO command_journal
                (command_id,correlation_id,action,payload,target_identity,timestamp,received_at,state)
                VALUES (?,?,?,?,?,?,?,'RECEIVED')''',
                (command_id, correlation_id, command['action_type'], json.dumps(safe_payload),
                 target_identity, received_at, received_at))
        started = datetime.now(timezone.utc).isoformat()
        with self.offline_queue._get_connection() as conn:
            conn.execute("""UPDATE command_journal SET state='EXECUTING',validated_at=?,
                execution_started_at=? WHERE command_id=?""", (started, started, command_id))
        if command.get('execution_source') != 'AGENT_OFFLINE':
            try:
                self.post('/api/v1/commands/result', {'command_id': command_id, 'agent_id': self.agent_id, 'status':'EXECUTING','executed_at':started})
            except Exception: logger.warning('Execution-start upload failed; result remains durable')
        report = asdict(self.command_receiver.process_command(command))
        completed = report.get('completed_at') or datetime.now(timezone.utc).isoformat()
        report.update(agent_id=self.agent_id, completed_at=completed)
        report['result_id'] = 'result-' + hashlib.sha256(
            canonical({k: report.get(k) for k in ('command_id','agent_id','status','verification','error','completed_at')})
        ).hexdigest()
        with self.offline_queue._get_connection() as conn:
            conn.execute('''UPDATE command_journal SET state=?,result=?,result_status=?,verification=?,
                verification_status=?,failure_reason=?,error_code=?,error_message=?,execution_finished_at=?,
                timestamp=?,report=? WHERE command_id=?''',
                (report['status'], report['status'], report['status'], json.dumps(report.get('verification')),
                 report.get('verification_status'), report.get('failure_reason') or report.get('error'),
                 report.get('error_code'), report.get('error'), completed, completed, json.dumps(report), command_id))
        return report

    def upload_results(self):
        with self.offline_queue._get_connection() as conn:
            rows = conn.execute('SELECT * FROM command_journal WHERE report IS NOT NULL AND reported=0 ORDER BY timestamp, rowid').fetchall()
        for row in rows:
            if json.loads(row['payload']).get('execution_source') == 'AGENT_OFFLINE': continue
            response = self.post('/api/v1/commands/result', json.loads(row['report']))
            if response.status_code == 200:
                with self.offline_queue._get_connection() as conn:
                    conn.execute('UPDATE command_journal SET reported=1,result_uploaded_at=? WHERE command_id=?',
                                 (datetime.now(timezone.utc).isoformat(), row['command_id']))

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
            cache_fingerprint = hashlib.sha256(canonical(cache)).hexdigest() if cache else None
            if cache_fingerprint == self.state.get('configuration_rejected_signature'):
                cache = None
            try:
                if not self.local_engine and cache: self.configure(cache)
                if cache: verify(cache, self.token, self.agent_id)
            except Exception as exc:
                logger.warning('Offline cache unavailable: %s', exc)
                # Preserve the signed cache for forensic/recovery purposes, but do not
                # re-verify and re-log the same stale signature for every event.
                self.state.set('configuration_rejected_signature', cache_fingerprint)
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
        process = raw.get('process') or {}
        event_data = ((raw.get('data') or {}).get('win') or {}).get('eventdata') or {}
        observed_pid = process.get('pid') or event_data.get('processId') or event_data.get('newProcessId')
        try:
            observed_pid = int(str(observed_pid), 0)
        except (TypeError, ValueError):
            observed_pid = -1
        observed_name = str(process.get('name') or event_data.get('image') or event_data.get('newProcessName') or '')
        # Exclude only this exact running agent process. Child processes retain different PIDs and are collected.
        if observed_pid == os.getpid() and os.path.basename(observed_name).lower() == os.path.basename(sys.executable).lower():
            return None
        raw.setdefault('agent', {'id': self.agent_id, 'name': self.hostname})
        event = ZTAEventAdapter.from_dict(raw)
        if event.agent.id != self.agent_id: raise ValueError('Collector event belongs to another agent')
        if self.connection_state != 'ONLINE':
            self.process_offline_event(event)
        else:
            self.offline_queue.enqueue(event.event_id,event.event_type,event.severity, {'id':event.event_id,'normalized_event':encode(event),'execution_source':'AGENT_ONLINE'})
        self.last_telemetry_at = event.timestamp.isoformat().replace('+00:00', 'Z')
        return event

    def send_heartbeat(self):
        previous_state = self.connection_state
        target = 'RECONNECTING' if previous_state in ('OFFLINE', 'DEGRADED') else 'CONNECTING'
        if previous_state not in ('ONLINE', 'SYNCING', target):
            self.connection.transition(target, reason='heartbeat attempt', force=previous_state == 'STOPPED')
        elif previous_state in ('OFFLINE', 'DEGRADED'):
            self.connection.transition('RECONNECTING', reason='automatic reconnect')
        if previous_state not in ('ONLINE', 'SYNCING'):
            logger.info('agent.connection_attempt', extra={'event_type': 'AGENT_CONNECTION_ATTEMPT'})
            if previous_state in ('OFFLINE', 'DEGRADED'):
                logger.info('agent.reconnecting', extra={'event_type': 'AGENT_RECONNECTING'})
        try:
            response = self.post('/api/v1/agents/heartbeat', self.get_system_telemetry(), timeout=5)
            if response.status_code in (401, 403):
                raise PermissionError('Agent authentication rejected')
            if response.status_code != 200:
                try:
                    reason = str(response.json().get('error', ''))[:300]
                except Exception:
                    reason = ''
                raise ConnectionError('Heartbeat rejected: '+str(response.status_code)+((': '+reason) if reason else ''))
            data = response.json()
            if data.get('configuration'): self.configure(data['configuration'])
            desired = 'SYNCING' if self.offline_queue.pending_depth() else 'ONLINE'
            self.connection.transition(desired, reason='authenticated heartbeat accepted')
            for command in data.get('pending_commands', []):
                try:
                    if self.worker_supervisor.started:
                        self.command_queue.put_nowait(command)
                    else:
                        self.execute_command(command)
                except Exception:
                    logger.exception('Rejected or backpressured command')
            if not self.worker_supervisor.started:
                self.upload_results()
            if previous_state not in ('ONLINE', 'SYNCING'):
                self.emit_log('INFO', 'MANAGER_CONNECTED', 'Authenticated Manager heartbeat succeeded', component='CONNECTION')
                logger.info('agent.connected', extra={'event_type': 'AGENT_CONNECTED'})
                logger.info('heartbeat.success', extra={'event_type': 'HEARTBEAT_SUCCESS'})
            return True
        except Exception as exc:
            self.connection.transition('OFFLINE', reason=type(exc).__name__, force=True)
            if previous_state != 'OFFLINE':
                stamp = datetime.now(timezone.utc).isoformat()
                self.offline_queue.enqueue('connection-'+hashlib.sha256(stamp.encode()).hexdigest(), 'HEARTBEAT_FAILURE', 'LOW',
                    {'id':'connection-'+hashlib.sha256(stamp.encode()).hexdigest(), 'telemetry':self.get_system_telemetry(), 'error':str(exc)})
                self.emit_log('WARNING', 'MANAGER_DISCONNECTED', 'Manager heartbeat failed; telemetry remains queued',
                              component='CONNECTION', metadata={'error_type': type(exc).__name__})
                logger.warning('heartbeat.failure', extra={'event_type': 'HEARTBEAT_FAILURE', 'error_type': type(exc).__name__})
                logger.warning('agent.offline', extra={'event_type': 'AGENT_OFFLINE'})
            logger.warning('Manager communication failed: %s', exc)
            return False

    def sync_offline_queue(self):
        configured_batch_size = max(1, min(500, int(os.environ.get('ZTA_TELEMETRY_BATCH_SIZE', '50'))))
        operational_limit = max(1, min(50, int(os.environ.get('ZTA_TELEMETRY_OPERATIONAL_BATCH_SIZE', '20'))))
        operational_max = min(configured_batch_size, operational_limit)
        batch_size = max(1, min(operational_max,
                                int(self.state.get('telemetry_adaptive_batch_size', operational_max))))
        pending = self.offline_queue.claim_batch(batch_size)
        if not pending:
            if self.connection_state == 'SYNCING':
                self.connection.transition('ONLINE', reason='queue empty')
            return True
        self.connection.transition('SYNCING', reason='telemetry batch claimed', force=True)
        logger.info('agent.sync_started', extra={'event_type': 'AGENT_SYNC_STARTED', 'batch_size': len(pending)})
        uploadable = []
        quarantined = {}
        for record in pending:
            item = record['payload']
            normalized = item.get('normalized_event') or {}
            queued_agent = ((normalized.get('agent') or {}).get('id') or
                            (item.get('telemetry') or {}).get('agent_id') or
                            (item.get('log_entry') or {}).get('agent_id') or item.get('agent_id'))
            reason = None
            if queued_agent and queued_agent != self.agent_id:
                reason = 'Queued telemetry belongs to a different agent identity'
            evidence = item.get('offline_evidence') or {}
            cache = evidence.get('configuration')
            if not reason and cache:
                try:
                    actual = str(cache.get('signature', ''))
                    expected = sign(cache, self.token).get('signature', '')
                    if cache.get('agent_id') != self.agent_id or not hmac.compare_digest(expected, actual):
                        reason = 'Offline evidence has an invalid authorization signature'
                except Exception:
                    reason = 'Offline evidence authorization is malformed'
            if reason:
                quarantined.setdefault(reason, []).append(record['event_id'])
            else:
                uploadable.append(record)
        if quarantined:
            for reason, event_ids in quarantined.items():
                self.offline_queue.mark_retry(event_ids, reason, 'SECURITY')
            logger.warning('telemetry.records_quarantined', extra={
                'event_type': 'TELEMETRY_RECORDS_QUARANTINED',
                'count': sum(len(event_ids) for event_ids in quarantined.values()),
                'reason': 'identity_or_signature_mismatch',
            })
        pending = uploadable
        if not pending:
            self.connection.transition('SYNCING' if self.offline_queue.pending_depth() else 'ONLINE',
                                       reason='ineligible evidence preserved', force=True)
            return True
        records = [p['payload'] for p in pending]
        payload = {'agent_id': self.agent_id, 'batch_id': hashlib.sha256(canonical(records)).hexdigest(), 'telemetry': records}
        upload_timeout = max(5, int(os.environ.get('ZTA_TELEMETRY_UPLOAD_TIMEOUT', '30')))
        try:
            response = self.post('/api/v1/sync/offline', payload, timeout=upload_timeout)
            if response.status_code not in (200,201):
                error_class = 'AUTHENTICATION' if response.status_code in (401,403) else 'TRANSIENT' if response.status_code == 429 or response.status_code >= 500 else 'VALIDATION'
                try:
                    validation_error = str(response.json().get('error', ''))[:300]
                except Exception:
                    validation_error = ''
                failure = 'HTTP '+str(response.status_code)+((': '+validation_error) if validation_error else '')
                if error_class == 'VALIDATION' and len(pending) > 1:
                    # A transactional Manager rejection does not identify the bad row.
                    # Retry a smaller batch until the exact record can be preserved and quarantined.
                    next_size = max(1, len(pending) // 2)
                    self.state.set('telemetry_adaptive_batch_size', next_size)
                    self.offline_queue.mark_retry([p['event_id'] for p in pending], failure,
                                                  'TRANSIENT', delay_seconds=0)
                    retry_state = 'SPLITTING_BATCH'
                else:
                    self.offline_queue.mark_retry([p['event_id'] for p in pending], failure, error_class)
                    retry_state = 'QUARANTINED' if error_class == 'VALIDATION' else 'RETRY_PENDING'
                logger.warning('telemetry.upload_rejected', extra={
                    'event_type': 'TELEMETRY_UPLOAD_REJECTED', 'http_status': response.status_code,
                    'error_class': error_class, 'validation_error': validation_error or None,
                    'batch_size': len(pending), 'retry_state': retry_state,
                    'next_batch_size': self.state.get('telemetry_adaptive_batch_size', configured_batch_size),
                })
                self.connection.transition('SYNCING', reason='telemetry upload retry scheduled', force=True)
                return False
            accepted = response.json().get('accepted_event_ids')
            if not isinstance(accepted,list) or not all(isinstance(i,str) for i in accepted):
                self.offline_queue.mark_retry([p['event_id'] for p in pending], 'Invalid acknowledgement', 'VALIDATION')
                self.connection.transition('DEGRADED', reason='invalid acknowledgement', force=True)
                return False
            accepted_ids = {p['event_id'] for p in pending if p['event_id'] in accepted}
            rejected_ids = [p['event_id'] for p in pending if p['event_id'] not in accepted_ids]
            acknowledged_commands = []
            for record in pending:
                if record['event_id'] not in accepted_ids:
                    continue
                evidence = record['payload'].get('offline_evidence') or {}
                acknowledged_commands.extend(
                    cmd['command_id'] for cmd in evidence.get('commands', []) if cmd.get('command_id')
                )
            if acknowledged_commands:
                with self.offline_queue._get_connection() as conn:
                    conn.executemany('UPDATE command_journal SET reported=1 WHERE command_id=?',
                                     [(command_id,) for command_id in acknowledged_commands])
            self.offline_queue.mark_synced(list(accepted_ids))
            adaptive = int(self.state.get('telemetry_adaptive_batch_size', operational_max))
            if adaptive < operational_max:
                self.state.set('telemetry_adaptive_batch_size', min(operational_max, adaptive * 2))
            if rejected_ids:
                self.offline_queue.mark_retry(rejected_ids, 'Manager did not acknowledge event', 'TRANSIENT')
            self.connection.transition('SYNCING' if self.offline_queue.pending_depth() else 'ONLINE', reason='batch acknowledged', force=True)
            logger.info('telemetry.batch_acknowledged', extra={'event_type': 'TELEMETRY_BATCH_ACKNOWLEDGED',
                                                               'accepted': len(accepted_ids), 'retry_pending': len(rejected_ids)})
            if not self.offline_queue.pending_depth():
                logger.info('agent.sync_completed', extra={'event_type': 'AGENT_SYNC_COMPLETED'})
            return True
        except Exception as exc:
            self.offline_queue.mark_retry([p['event_id'] for p in pending], exc, 'TRANSIENT')
            if len(pending) > 1:
                self.state.set('telemetry_adaptive_batch_size', max(1, len(pending) // 2))
            self.connection.transition('SYNCING', reason='telemetry transport retry scheduled', force=True)
            warning_key = (type(exc).__name__, str(exc)[:200])
            now = time.monotonic()
            if now - self._last_sync_warning.get(warning_key, 0) >= 300:
                self._last_sync_warning[warning_key] = now
                logger.warning('telemetry.retry', extra={'event_type': 'TELEMETRY_RETRY',
                                                         'error_type': type(exc).__name__, 'batch_size': len(pending)})
                logger.warning('Sync failed; evidence retained: %s', exc)
            return False

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
        self.emit_log('INFO', 'AGENT_STARTED', 'Endpoint background agent started', component='AGENT')
        # Keep the CLI interval authoritative without rebuilding registered workers.
        if 'heartbeat-worker' in self.worker_supervisor._workers:
            self.worker_supervisor._workers['heartbeat-worker']['interval'] = max(0.05, float(interval))
        self.worker_supervisor.start()
        try:
            while self.is_running and not self.stop_event.wait(0.5):
                pass
        finally:
            self.is_running = False
            self.connection.transition('STOPPING', reason='agent shutdown', force=True)
            self.worker_supervisor.stop()
            self.connection.transition('STOPPED', reason='workers stopped')
            self.emit_log('INFO', 'AGENT_STOPPED', 'Endpoint background agent stopped', component='AGENT')


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
    from zta.agent.operational_logging import configure_agent_logging
    configure_agent_logging()
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
