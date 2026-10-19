"""Read actual Windows event channels or an explicitly configured JSONL feed.

No native Wazuh output location/schema is assumed. Windows channel permissions,
Sysmon installation and audit policy remain deployment prerequisites.
"""
import hashlib
import json
import logging
import os
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
import xml.etree.ElementTree as ET

logger = logging.getLogger(__name__)


class WindowsEventCollector:
    CHANNELS = ('Microsoft-Windows-Sysmon/Operational', 'Security', 'Microsoft-Windows-PowerShell/Operational', 'System', 'Application')

    def __init__(self, checkpoint):
        self.checkpoint = checkpoint
        self.listening_ports = []
        self.process_inventory = []
        self._process_baseline_set = False  # True after first poll_processes call
        self._network_baseline_set = False   # True after first poll_network call
        self._last_channel_warning = {}
        self._channel_disabled_until = {}

    def _channel_failure(self, channel, exc):
        """Report inaccessible/absent channels without breaking healthy channels."""
        detail = ((getattr(exc, 'stderr', '') or '') + ' ' + str(exc)).strip()
        expected = (getattr(exc, 'returncode', None) in (5, 15007) or
                    any(marker in detail.lower() for marker in
                        ('error 5', '15007', 'access is denied', 'channel could not be found',
                         'specified channel could not be found', 'not found', 'cannot find',
                         'failed to read configuration for log')))
        key = (channel, 'unavailable' if expected else type(exc).__name__)
        now = time.monotonic()
        if now - self._last_channel_warning.get(key, 0) >= 300:
            logger.warning('event_channel.unavailable', extra={
                'channel': channel, 'expected_unavailable': expected,
                'error_type': type(exc).__name__,
            })
            self._last_channel_warning[key] = now
        if expected:
            suppress_duration = max(60, min(1800, int(os.environ.get('ZTA_CHANNEL_RECHECK_INTERVAL', '600'))))
            self._channel_disabled_until[channel] = now + suppress_duration
        return expected

    def _channel_is_suppressed(self, channel):
        return self._channel_disabled_until.get(channel, 0) > time.monotonic()

    def poll(self, consume):
        """Unified collection: Windows event channels + listening ports + process inventory."""
        if os.name != 'nt':
            raise OSError('Windows event collection requires a Windows endpoint')
        errors = []
        for channel in self.CHANNELS:
            if self._channel_is_suppressed(channel):
                continue
            try:
                last = int(self.checkpoint.get('channel:' + channel, 0))
                result = subprocess.run(['wevtutil.exe', 'qe', channel, '/q:*[System[EventRecordID >'+str(last)+']]', '/rd:false', '/c:100', '/f:xml'], capture_output=True, text=True, errors='replace', timeout=15, check=True)
                self._channel_disabled_until.pop(channel, None)
                xml = result.stdout.strip()
                if not xml: continue
                root = ET.fromstring(xml if xml.startswith('<Events') else '<Events>'+xml+'</Events>')
                for node in root:
                    ns = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}
                    system = node.find('e:System', ns)
                    if system is None: continue
                    record = int(system.findtext('e:EventRecordID', namespaces=ns))
                    event_id = int(system.findtext('e:EventID', namespaces=ns))
                    stamp = system.find('e:TimeCreated', ns).get('SystemTime')
                    data = {n.get('Name'): n.text for n in node.findall('e:EventData/e:Data', ns) if n.get('Name')}
                    normalized = {k[0].lower()+k[1:]: v for k,v in data.items()}
                    kind = 'SYSTEM_EVENT'
                    if 'Sysmon' in channel:
                        kind = {1:'PROCESS_CREATION',2:'FILE_MODIFICATION',3:'NETWORK_CONNECTION',5:'PROCESS_TERMINATION',11:'FILE_CREATION',12:'REGISTRY_MODIFICATION',13:'REGISTRY_MODIFICATION',15:'FILE_MODIFICATION',23:'FILE_DELETION'}.get(event_id, 'SYSTEM_EVENT')
                    elif channel == 'Security':
                        kind = {4624:'AUTHENTICATION',4625:'AUTHENTICATION',4688:'PROCESS_CREATION',4698:'SCHEDULED_TASK',1102:'EVENT_LOG_CLEARED'}.get(event_id,'AUTH_EVENT')
                    elif 'PowerShell' in channel: kind = 'POWERSHELL_EVENT'
                    elif channel == 'System' and event_id == 7045: kind = 'SERVICE_INSTALL'
                    raw_xml = ET.tostring(node, encoding='unicode')
                    consume({'id': 'win-'+hashlib.sha256(raw_xml.encode()).hexdigest(), 'timestamp': stamp,
                             'event_type': kind, 'collector_type': channel,
                             'data': {'win': {'system': {'eventID': event_id, 'channel': channel, 'eventRecordID': record}, 'eventdata': normalized}},
                             'original_xml': raw_xml})
                    self.checkpoint.set('channel:'+channel, record)
            except Exception as exc:
                if not self._channel_failure(channel, exc):
                    errors.append(channel+': '+str(exc))
        try:
            self._poll_listening_ports(consume)
        except Exception as exc:
            errors.append('LISTENING_PORTS: '+str(exc))
        try:
            self._poll_process_inventory()
        except Exception as exc:
            errors.append('PROCESS_INVENTORY: '+str(exc))
        if errors: raise OSError('; '.join(errors))

    # --- Split-worker interface used by agent_daemon._register_workers ---

    def poll_events(self, consume):
        """Collect Windows event-log channels only (called by the event-collector worker)."""
        if os.name != 'nt':
            raise OSError('Windows event collection requires a Windows endpoint')
        errors = []
        successful_channels = 0
        for channel in self.CHANNELS:
            if self._channel_is_suppressed(channel):
                continue
            try:
                last = int(self.checkpoint.get('channel:' + channel, 0))
                result = subprocess.run(
                    ['wevtutil.exe', 'qe', channel,
                     '/q:*[System[EventRecordID >'+str(last)+']]',
                     '/rd:false', '/c:100', '/f:xml'],
                    capture_output=True, text=True, errors='replace', timeout=15, check=True)
                successful_channels += 1
                self._channel_disabled_until.pop(channel, None)
                xml = result.stdout.strip()
                if not xml:
                    continue
                root = ET.fromstring(xml if xml.startswith('<Events') else '<Events>'+xml+'</Events>')
                for node in root:
                    ns = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}
                    system = node.find('e:System', ns)
                    if system is None:
                        continue
                    record = int(system.findtext('e:EventRecordID', namespaces=ns))
                    event_id = int(system.findtext('e:EventID', namespaces=ns))
                    stamp = system.find('e:TimeCreated', ns).get('SystemTime')
                    data = {n.get('Name'): n.text for n in node.findall('e:EventData/e:Data', ns) if n.get('Name')}
                    normalized = {k[0].lower()+k[1:]: v for k, v in data.items()}
                    kind = 'SYSTEM_EVENT'
                    if 'Sysmon' in channel:
                        kind = {1: 'PROCESS_CREATION', 2: 'FILE_MODIFICATION', 3: 'NETWORK_CONNECTION',
                                5: 'PROCESS_TERMINATION', 11: 'FILE_CREATION', 12: 'REGISTRY_MODIFICATION',
                                13: 'REGISTRY_MODIFICATION', 15: 'FILE_MODIFICATION',
                                23: 'FILE_DELETION'}.get(event_id, 'SYSTEM_EVENT')
                    elif channel == 'Security':
                        kind = {4624: 'AUTHENTICATION', 4625: 'AUTHENTICATION', 4688: 'PROCESS_CREATION',
                                4698: 'SCHEDULED_TASK', 1102: 'EVENT_LOG_CLEARED'}.get(event_id, 'AUTH_EVENT')
                    elif 'PowerShell' in channel:
                        kind = 'POWERSHELL_EVENT'
                    elif channel == 'System' and event_id == 7045:
                        kind = 'SERVICE_INSTALL'
                    raw_xml = ET.tostring(node, encoding='unicode')
                    consume({'id': 'win-'+hashlib.sha256(raw_xml.encode()).hexdigest(), 'timestamp': stamp,
                             'event_type': kind, 'collector_type': channel,
                             'data': {'win': {'system': {'eventID': event_id, 'channel': channel,
                                                         'eventRecordID': record}, 'eventdata': normalized}},
                             'original_xml': raw_xml})
                    self.checkpoint.set('channel:'+channel, record)
            except Exception as exc:
                if not self._channel_failure(channel, exc):
                    errors.append(channel+': '+str(exc))
        if errors and not successful_channels:
            raise OSError('; '.join(errors))

    def poll_processes(self, consume):
        """Diff process inventory and emit PROCESS_STARTED / PROCESS_EXITED events.

        Identity is (pid, created_at) so PID reuse is detected correctly.
        The first call establishes a silent baseline; events are emitted from
        the second call onward. Called by the process-collector worker.
        """
        command = (
            "Get-Process -ErrorAction Stop | ForEach-Object { "
            "[pscustomobject]@{pid=$_.Id;name=$_.ProcessName;path=$_.Path;"
            "username=$null;domain=$null;"
            "created_at=if($_.StartTime){$_.StartTime.ToUniversalTime().ToString('o')}else{$null};"
            "parent_pid=$null} } | ConvertTo-Json -Compress"
        )
        result = subprocess.run(
            ['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', command],
            capture_output=True, text=True, errors='replace', timeout=30, check=True,
        )
        decoded = json.loads(result.stdout) if result.stdout.strip() else []
        rows = decoded if isinstance(decoded, list) else [decoded]
        stamp = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')

        # Build identity key: (pid, created_at) — detects PID reuse.
        def _key(row):
            return (str(row.get('pid', '')), str(row.get('created_at', '')))

        if not self._process_baseline_set:
            # First call: store baseline silently, emit no events.
            self.process_inventory = [{**r, 'last_observed': stamp, 'status': 'RUNNING'} for r in rows]
            self._process_baseline_set = True
            return

        previous_by_key = {_key(p): p for p in self.process_inventory}
        current_by_key = {_key(r): r for r in rows}

        # Emit PROCESS_STARTED for processes not in previous snapshot.
        for key, row in current_by_key.items():
            if key not in previous_by_key:
                event_id = 'proc-start-' + hashlib.sha256(
                    (str(key) + stamp).encode()).hexdigest()
                consume({
                    'id': event_id, 'timestamp': stamp,
                    'event_type': 'PROCESS_STARTED',
                    'collector_type': 'PROCESS_INVENTORY',
                    'process': {
                        'pid': row.get('pid'), 'name': row.get('name'),
                        'path': row.get('path'), 'username': row.get('username'),
                        'domain': row.get('domain'), 'created_at': row.get('created_at'),
                        'parent_pid': row.get('parent_pid'),
                    },
                    'data': {'process': row},
                })

        # Emit PROCESS_EXITED for processes not in current snapshot.
        for key, row in previous_by_key.items():
            if key not in current_by_key:
                event_id = 'proc-exit-' + hashlib.sha256(
                    (str(key) + stamp).encode()).hexdigest()
                consume({
                    'id': event_id, 'timestamp': stamp,
                    'event_type': 'PROCESS_EXITED',
                    'collector_type': 'PROCESS_INVENTORY',
                    'process': {
                        'pid': row.get('pid'), 'name': row.get('name'),
                        'path': row.get('path'), 'username': row.get('username'),
                        'domain': row.get('domain'), 'created_at': row.get('created_at'),
                        'parent_pid': row.get('parent_pid'),
                    },
                    'data': {'process': row},
                })

        self.process_inventory = [{**r, 'last_observed': stamp, 'status': 'RUNNING'} for r in rows]

    def poll_network(self, consume):
        """Diff all network connections and emit LISTENER_STARTED / LISTENER_STOPPED / CONNECTION_CLOSED.

        Calls subprocess once per poll to get the current connection snapshot.
        Called by the network-collector worker.
        """
        command = (
            "Get-NetTCPConnection -ErrorAction Stop | ForEach-Object { "
            "[pscustomobject]@{protocol='TCP';local_address=$_.LocalAddress;"
            "local_port=$_.LocalPort;remote_address=$_.RemoteAddress;"
            "remote_port=$_.RemotePort;state=$_.State;pid=$_.OwningProcess;"
            "process=$null} } | ConvertTo-Json -Compress -Depth 3"
        )
        try:
            result = subprocess.run(
                ['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', command],
                capture_output=True, text=True, errors='replace', timeout=15, check=True,
            )
            decoded = json.loads(result.stdout) if result.stdout.strip() else []
            rows = decoded if isinstance(decoded, list) else [decoded]
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            # Get-NetTCPConnection is CIM-backed and can be denied or stall for
            # standard users. netstat is one bounded native snapshot with PIDs.
            result = subprocess.run(['netstat.exe', '-ano', '-p', 'tcp'], capture_output=True,
                                    text=True, errors='replace', timeout=10, check=True)
            rows = []
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) < 5 or parts[0].upper() != 'TCP':
                    continue
                def endpoint(value):
                    host, _, port = value.rpartition(':')
                    return host.strip('[]'), int(port) if port.isdigit() else 0
                local_address, local_port = endpoint(parts[1])
                remote_address, remote_port = endpoint(parts[2])
                rows.append({'protocol': 'TCP', 'local_address': local_address,
                             'local_port': local_port, 'remote_address': remote_address,
                             'remote_port': remote_port, 'state': parts[3],
                             'pid': int(parts[4]), 'process': None})
        process_by_pid = {str(row.get('pid')): row for row in list(self.process_inventory)}
        for row in rows:
            proc = process_by_pid.get(str(row.get('pid')))
            if not isinstance(row.get('process'), dict):
                row['process'] = ({'name': proc.get('name'), 'path': proc.get('path'),
                                   'created_at': proc.get('created_at')} if proc else {})
        stamp = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')

        def _conn_key(row):
            return (
                row.get('protocol', 'TCP'),
                str(row.get('local_address', '')),
                str(row.get('local_port', '')),
                str(row.get('remote_address', '')),
                str(row.get('remote_port', '')),
                str(row.get('pid', '')),
            )

        def _is_listener(row):
            return str(row.get('state', '')).lower() in ('listen', 'listening')

        previous = self.checkpoint.get('network:connections', {})
        current = {}
        for row in rows:
            key = _conn_key(row)
            key_str = '|'.join(key)
            current[key_str] = row

        if not self._network_baseline_set:
            # First call: store baseline silently, emit no events.
            self.checkpoint.set('network:connections', current)
            self._network_baseline_set = True
            self.listening_ports = [
                {
                    'port': row.get('local_port'), 'protocol': row.get('protocol', 'TCP'),
                    'local_address': row.get('local_address'), 'pid': row.get('pid'),
                    'process_name': (row.get('process') or {}).get('name'),
                    'state': row.get('state', 'Listen'), 'last_observed': stamp,
                }
                for row in rows if _is_listener(row)
            ]
            return

        for key_str, row in current.items():
            if key_str not in previous:
                event_type = 'LISTENER_STARTED' if _is_listener(row) else 'CONNECTION_OPENED'
                proc = row.get('process') or {}
                event_id = 'net-' + hashlib.sha256(
                    (key_str + '|' + stamp).encode()).hexdigest()
                consume({
                    'id': event_id, 'timestamp': stamp,
                    'event_type': event_type,
                    'collector_type': 'NETWORK_CONNECTION',
                    'process': {
                        'pid': row.get('pid'),
                        'name': proc.get('name') if isinstance(proc, dict) else None,
                    },
                    'source_ip': row.get('local_address'),
                    'destination_port': row.get('local_port'),
                    'data': {
                        'protocol': row.get('protocol', 'TCP'),
                        'local_address': row.get('local_address'),
                        'local_port': row.get('local_port'),
                        'remote_address': row.get('remote_address'),
                        'remote_port': row.get('remote_port'),
                        'state': row.get('state'),
                        'pid': row.get('pid'),
                        'process': proc,
                    },
                })

        # Disappeared connections.
        for key_str, row in previous.items():
            if key_str not in current:
                event_type = 'LISTENER_STOPPED' if _is_listener(row) else 'CONNECTION_CLOSED'
                proc = row.get('process') or {}
                event_id = 'net-close-' + hashlib.sha256(
                    (key_str + '|' + stamp).encode()).hexdigest()
                consume({
                    'id': event_id, 'timestamp': stamp,
                    'event_type': event_type,
                    'collector_type': 'NETWORK_CONNECTION',
                    'process': {
                        'pid': row.get('pid'),
                        'name': proc.get('name') if isinstance(proc, dict) else None,
                    },
                    'source_ip': row.get('local_address'),
                    'destination_port': row.get('local_port'),
                    'data': {
                        'protocol': row.get('protocol', 'TCP'),
                        'local_address': row.get('local_address'),
                        'local_port': row.get('local_port'),
                        'remote_address': row.get('remote_address'),
                        'remote_port': row.get('remote_port'),
                        'state': row.get('state'),
                        'pid': row.get('pid'),
                        'process': proc,
                    },
                })

        self.checkpoint.set('network:connections', current)
        # Update the listening_ports inventory for heartbeat telemetry.
        self.listening_ports = [
            {
                'port': row.get('local_port'), 'protocol': row.get('protocol', 'TCP'),
                'local_address': row.get('local_address'), 'pid': row.get('pid'),
                'process_name': (row.get('process') or {}).get('name'),
                'state': row.get('state', 'Listen'), 'last_observed': stamp,
            }
            for row in rows if _is_listener(row)
        ]

    def _poll_process_inventory(self):
        command = ("Get-Process -ErrorAction Stop | ForEach-Object { "
                   "[pscustomobject]@{pid=$_.Id;name=$_.ProcessName;path=$_.Path;"
                   "username=$null;domain=$null;created_at=if($_.StartTime){$_.StartTime.ToUniversalTime().ToString('o')}else{$null};parent_pid=$null} } | ConvertTo-Json -Compress")
        result = subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',command],
                                capture_output=True,text=True,errors='replace',timeout=30,check=True)
        decoded = json.loads(result.stdout) if result.stdout.strip() else []
        rows = decoded if isinstance(decoded, list) else [decoded]
        stamp = datetime.now(timezone.utc).isoformat().replace('+00:00','Z')
        self.process_inventory = [{**row, 'last_observed': stamp, 'status': 'RUNNING'} for row in rows]

    def _poll_listening_ports(self, consume):
        """Emit newly observed TCP listeners into the canonical event pipeline."""
        command = (
            "Get-NetTCPConnection -State Listen -ErrorAction Stop | ForEach-Object { "
            "[pscustomobject]@{LocalAddress=$_.LocalAddress;LocalPort=$_.LocalPort;"
            "OwningProcess=$_.OwningProcess;State=$_.State;Protocol='TCP'} } | "
            "ConvertTo-Json -Compress"
        )
        result = subprocess.run(
            ['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', command],
            capture_output=True, text=True, errors='replace', timeout=15, check=True,
        )
        decoded = json.loads(result.stdout) if result.stdout.strip() else []
        rows = decoded if isinstance(decoded, list) else [decoded]
        process_by_pid = {str(row.get('pid')): row for row in list(self.process_inventory)}
        for row in rows:
            owner = process_by_pid.get(str(row.get('OwningProcess')))
            row['ProcessName'] = owner.get('name') if owner else None
        observed = [(f"{row.get('LocalAddress')}:{row.get('LocalPort')}:{row.get('OwningProcess')}", row) for row in rows]
        observed.sort(key=lambda item: item[0])
        current = [identity for identity, _ in observed]
        previous = set(self.checkpoint.get('network:listeners', []))
        stamp = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
        self.listening_ports = [{
            'port': row.get('LocalPort'), 'protocol': row.get('Protocol', 'TCP'),
            'local_address': row.get('LocalAddress'), 'pid': row.get('OwningProcess'),
            'process_name': row.get('ProcessName'), 'state': row.get('State', 'Listen'),
            'last_observed': stamp,
        } for _, row in observed]
        for identity, row in observed:
            if identity in previous:
                continue
            event_id = 'listener-' + hashlib.sha256((identity+'|'+stamp).encode()).hexdigest()
            consume({
                'id': event_id, 'timestamp': stamp, 'event_type': 'LISTENING_PORT',
                'collector_type': 'NETWORK_LISTENER',
                'process': {'pid': row.get('OwningProcess'), 'name': row.get('ProcessName')},
                'source_ip': row.get('LocalAddress'),
                'destination_port': row.get('LocalPort'),
                'data': {'network': row},
            })
        self.checkpoint.set('network:listeners', current)


class JsonlCollector:
    def __init__(self, path, checkpoint):
        self.path, self.checkpoint = Path(path), checkpoint

    def poll(self, consume):
        stat = self.path.stat()
        key = 'jsonl:'+str(self.path.resolve())
        saved = self.checkpoint.get(key, {})
        offset = saved.get('offset', 0) if saved.get('inode') == stat.st_ino else 0
        if offset > stat.st_size: offset = 0
        with self.path.open('rb') as stream:
            stream.seek(offset)
            for _ in range(100):
                line = stream.readline()
                if not line or not line.endswith(b'\n'): break
                event = json.loads(line)
                if not event.get('id') and not event.get('event_id'):
                    event['id'] = 'feed-'+hashlib.sha256(line).hexdigest()
                consume(event)
                self.checkpoint.set(key, {'inode': stat.st_ino, 'offset': stream.tell()})
