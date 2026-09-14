"""Read actual Windows event channels or an explicitly configured JSONL feed.

No native Wazuh output location/schema is assumed. Windows channel permissions,
Sysmon installation and audit policy remain deployment prerequisites.
"""
import hashlib
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
import xml.etree.ElementTree as ET


class WindowsEventCollector:
    CHANNELS = ('Microsoft-Windows-Sysmon/Operational', 'Security', 'Microsoft-Windows-PowerShell/Operational', 'System', 'Application')

    def __init__(self, checkpoint):
        self.checkpoint = checkpoint
        self.listening_ports = []
        self.process_inventory = []

    def poll(self, consume):
        if os.name != 'nt':
            raise OSError('Windows event collection requires a Windows endpoint')
        errors = []
        for channel in self.CHANNELS:
            try:
                last = int(self.checkpoint.get('channel:' + channel, 0))
                result = subprocess.run(['wevtutil.exe', 'qe', channel, '/q:*[System[EventRecordID > '+str(last)+']]', '/rd:false', '/c:100', '/f:xml'], capture_output=True, text=True, timeout=15, check=True)
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

    def _poll_process_inventory(self):
        command = ("Get-CimInstance Win32_Process | ForEach-Object { $owner=$_.GetOwner(); "
                   "[pscustomobject]@{pid=$_.ProcessId;name=$_.Name;path=$_.ExecutablePath;"
                   "username=$owner.User;domain=$owner.Domain;created_at=$_.CreationDate.ToUniversalTime().ToString('o');parent_pid=$_.ParentProcessId} } | ConvertTo-Json -Compress")
        result = subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',command],
                                capture_output=True,text=True,timeout=30,check=True)
        decoded = json.loads(result.stdout) if result.stdout.strip() else []
        rows = decoded if isinstance(decoded, list) else [decoded]
        stamp = datetime.now(timezone.utc).isoformat().replace('+00:00','Z')
        self.process_inventory = [{**row, 'last_observed': stamp, 'status': 'RUNNING'} for row in rows]

    def _poll_listening_ports(self, consume):
        """Emit newly observed TCP listeners into the canonical event pipeline."""
        command = (
            "Get-NetTCPConnection -State Listen -ErrorAction Stop | ForEach-Object { "
            "$owner = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue; "
            "[pscustomobject]@{LocalAddress=$_.LocalAddress;LocalPort=$_.LocalPort;"
            "OwningProcess=$_.OwningProcess;ProcessName=$owner.ProcessName;State=$_.State;Protocol='TCP'} } | "
            "ConvertTo-Json -Compress"
        )
        result = subprocess.run(
            ['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', command],
            capture_output=True, text=True, timeout=15, check=True,
        )
        decoded = json.loads(result.stdout) if result.stdout.strip() else []
        rows = decoded if isinstance(decoded, list) else [decoded]
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
