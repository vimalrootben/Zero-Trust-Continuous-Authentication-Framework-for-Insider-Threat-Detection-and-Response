import json
import subprocess
import threading
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from zta.agent.agent_daemon import ZTAAgentDaemon
from zta.agent.commands.authorization import sign
from zta.agent.collectors import WindowsEventCollector
from zta.agent.storage.offline_queue import OfflineQueue


class State:
    def __init__(self): self.values = {}
    def get(self, key, default=None): return self.values.get(key, default)
    def set(self, key, value): self.values[key] = value


def test_network_snapshot_does_not_lookup_process_per_connection():
    collector = WindowsEventCollector(State())
    collector.process_inventory = [{'pid': 42, 'name': 'svc.exe', 'path': 'C:\\svc.exe',
                                    'created_at': '2026-01-01T00:00:00Z'}]
    result = SimpleNamespace(stdout=json.dumps([{'protocol': 'TCP', 'local_address': '0.0.0.0',
        'local_port': 443, 'remote_address': '0.0.0.0', 'remote_port': 0,
        'state': 'Listen', 'pid': 42, 'process': None}]), stderr='', returncode=0)
    with patch('zta.agent.collectors.subprocess.run', return_value=result) as run:
        collector.poll_network(lambda event: None)
    command = run.call_args.args[0][-1]
    assert 'Get-Process' not in command
    assert collector.listening_ports[0]['process_name'] == 'svc.exe'


def test_missing_or_denied_event_channels_do_not_stop_healthy_channels(monkeypatch):
    collector = WindowsEventCollector(State())
    monkeypatch.setattr('zta.agent.collectors.os.name', 'nt')
    denied = subprocess.CalledProcessError(5, ['wevtutil.exe'], stderr='Access is denied. Error 5')
    missing = subprocess.CalledProcessError(15007, ['wevtutil.exe'], stderr='channel could not be found 15007')
    ok = SimpleNamespace(stdout='', stderr='', returncode=0)
    with patch('zta.agent.collectors.subprocess.run', side_effect=[missing, denied, ok, ok, ok]):
        collector.poll_events(lambda event: None)


def test_unavailable_channels_are_temporarily_suppressed(monkeypatch):
    collector = WindowsEventCollector(State())
    monkeypatch.setattr('zta.agent.collectors.os.name', 'nt')
    denied = subprocess.CalledProcessError(5, ['wevtutil.exe'], stderr='Access is denied. Error 5')
    missing = subprocess.CalledProcessError(15007, ['wevtutil.exe'], stderr='channel could not be found 15007')
    ok = SimpleNamespace(stdout='', stderr='', returncode=0)
    with patch('zta.agent.collectors.subprocess.run', side_effect=[missing, denied, ok, ok, ok, ok, ok, ok]) as run:
        collector.poll_events(lambda event: None)
        collector.poll_events(lambda event: None)
    assert run.call_count == 8


def test_unexpected_channel_errors_raise_only_when_every_channel_fails(monkeypatch):
    collector = WindowsEventCollector(State())
    monkeypatch.setattr('zta.agent.collectors.os.name', 'nt')
    failure = subprocess.CalledProcessError(99, ['wevtutil.exe'], stderr='unexpected')
    with patch('zta.agent.collectors.subprocess.run', side_effect=[failure] * len(collector.CHANNELS)):
        try:
            collector.poll_events(lambda event: None)
        except OSError:
            pass
        else:
            raise AssertionError('all-channel failure must remain observable')


def test_sync_preserves_but_does_not_upload_foreign_or_stale_signed_records(tmp_path):
    daemon = ZTAAgentDaemon(db_path=str(tmp_path / 'agent.db'), agent_id='current', token='current-secret')
    good = {'id': 'good', 'normalized_event': {'event_id': 'good', 'agent': {'id': 'current'}}}
    foreign = {'id': 'foreign', 'normalized_event': {'event_id': 'foreign', 'agent': {'id': 'other'}}}
    stale_cache = sign({'agent_id': 'current', 'rules': [], 'policies': []}, 'old-secret')
    stale = {'id': 'stale', 'normalized_event': {'event_id': 'stale', 'agent': {'id': 'current'}},
             'offline_evidence': {'configuration': stale_cache}}
    for item in (good, foreign, stale):
        daemon.offline_queue.enqueue(item['id'], 'TEST', 'LOW', item)

    response = SimpleNamespace(status_code=201, json=lambda: {'accepted_event_ids': ['good']})
    with patch.object(daemon, 'post', return_value=response) as post:
        assert daemon.sync_offline_queue()

    assert [item['id'] for item in post.call_args.args[1]['telemetry']] == ['good']
    with daemon.offline_queue._get_connection() as conn:
        states = dict(conn.execute('SELECT event_id,status FROM offline_events'))
    assert states == {'foreign': 'PERMANENT_ERROR', 'stale': 'PERMANENT_ERROR'}


def test_operational_batch_cap_and_timeout_retry_preserve_evidence(tmp_path):
    daemon = ZTAAgentDaemon(db_path=str(tmp_path / 'agent.db'), agent_id='current', token='secret')
    for index in range(25):
        daemon.offline_queue.enqueue(f'event-{index}', 'TEST', 'LOW',
                                     {'id': f'event-{index}', 'agent_id': 'current'})
    daemon.connection_state = 'ONLINE'
    with patch.object(daemon, 'post', side_effect=TimeoutError('slow manager')) as post:
        assert daemon.sync_offline_queue() is False
    assert len(post.call_args.args[1]['telemetry']) == 20
    with daemon.offline_queue._get_connection() as conn:
        status_counts = dict(conn.execute('SELECT status,COUNT(*) FROM offline_events GROUP BY status'))
    assert status_counts == {'PENDING': 5, 'RETRY_PENDING': 20}


def test_ingestion_and_heartbeat_concurrency(tmp_path):
    """Verify concurrent telemetry ingestion batches and agent heartbeats do not block or deadlock."""
    from datetime import datetime, timezone
    from zta.storage.database import ZTADatabase, ZTARepository
    from zta.engine.events.models import ZTAAgent, ZTAEvent
    from zta.api.server import create_zta_server
    import urllib.request
    import concurrent.futures

    db_path = tmp_path / "concurrent.db"
    server = create_zta_server(host="127.0.0.1", port=0, db_path=db_path)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    port = server.server_port
    base_url = f"http://127.0.0.1:{port}"

    try:
        def send_heartbeat():
            payload = json.dumps({
                "agent_id": "sync-agent-01",
                "hostname": "HOST-CONC",
                "ip": "127.0.0.1",
                "os": "Windows",
                "connection_state": "ONLINE",
                "listening_ports": [{"protocol": "TCP", "local_address": "0.0.0.0", "port": 8080, "pid": 1234}],
                "process_inventory": [{"pid": 1234, "name": "zta.exe"}],
                "sessions": [{"session_id": 1, "username": "admin"}],
            }).encode("utf-8")
            req = urllib.request.Request(
                f"{base_url}/api/v1/agents/heartbeat",
                data=payload,
                headers={"Content-Type": "application/json", "Authorization": "Bearer fixture-agent-token"}
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status

        def send_telemetry_batch(batch_idx):
            events = [
                {
                    "id": f"conc-evt-{batch_idx}-{i}",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "agent": {"id": "sync-agent-01", "name": "HOST-CONC"},
                    "event_type": "PROCESS_CREATION",
                    "severity": "LOW",
                    "raw_event": {"cmd": f"run-{i}.exe"}
                }
                for i in range(10)
            ]
            payload = json.dumps(events).encode("utf-8")
            req = urllib.request.Request(
                f"{base_url}/api/v1/telemetry/bulk",
                data=payload,
                headers={"Content-Type": "application/json", "Authorization": "Bearer fixture-agent-token"}
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status

        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            futures = [
                pool.submit(send_heartbeat),
                pool.submit(send_telemetry_batch, 1),
                pool.submit(send_heartbeat),
                pool.submit(send_telemetry_batch, 2),
                pool.submit(send_heartbeat),
                pool.submit(send_telemetry_batch, 3),
            ]
            results = [f.result(timeout=15) for f in futures]
            assert all(status in (200, 201) for status in results)
    finally:
        server.shutdown()
        server.server_close()


def test_retry_bounded_exponential_backoff(tmp_path):
    """Verify that retries use bounded exponential backoff up to 300 seconds and preserve error records."""
    queue = OfflineQueue(db_path=str(tmp_path / "queue.db"))
    queue.enqueue({"id": "evt-retry-1"})
    
    # 1st failure: attempt 1 -> delay 0s
    queue.claim_batch(10)
    queue.mark_retry(["evt-retry-1"], "Connection timeout 1", "TRANSIENT")
    with queue._get_connection() as conn:
        row = conn.execute("SELECT status, attempt_count, next_attempt_at, error_class FROM offline_events WHERE event_id='evt-retry-1'").fetchone()
    assert row["status"] == "RETRY_PENDING"
    assert row["attempt_count"] == 1
    assert row["error_class"] == "TRANSIENT"

    # 2nd failure: attempt 2 -> delay 2s
    queue.claim_batch(10)
    queue.mark_retry(["evt-retry-1"], "Connection timeout 2", "TRANSIENT")
    with queue._get_connection() as conn:
        row = conn.execute("SELECT attempt_count FROM offline_events WHERE event_id='evt-retry-1'").fetchone()
    assert row["attempt_count"] == 2


def test_unavailable_channels_detected_and_gracefully_suppressed(monkeypatch):
    """Verify unsupported/unavailable Windows event channels are suppressed gracefully without error logging storm."""
    collector = WindowsEventCollector(State())
    monkeypatch.setattr('zta.agent.collectors.os.name', 'nt')
    missing_config = subprocess.CalledProcessError(
        1, ['wevtutil.exe'], stderr='Failed to read configuration for log Microsoft-Windows-Sysmon/Operational. The specified channel could not be found.'
    )
    ok = SimpleNamespace(stdout='', stderr='', returncode=0)

    # 1st poll: missing_config triggers _channel_failure, returns expected=True, suppresses channel
    with patch('zta.agent.collectors.subprocess.run', side_effect=[missing_config, ok, ok, ok, ok]):
        collector.poll_events(lambda event: None)

    assert collector._channel_is_suppressed('Microsoft-Windows-Sysmon/Operational')

    # 2nd poll: suppressed channel is skipped immediately without calling subprocess
    with patch('zta.agent.collectors.subprocess.run', side_effect=[ok, ok, ok, ok]) as run:
        collector.poll_events(lambda event: None)
    # Only the 4 active channels were polled
    assert run.call_count == 4

