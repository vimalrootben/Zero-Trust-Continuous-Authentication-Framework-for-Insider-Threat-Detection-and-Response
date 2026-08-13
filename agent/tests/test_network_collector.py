"""
Unit tests for NetworkCollector (A9).
"""
import time
from agent.collectors.network_collector import NetworkCollector, NetworkConnectionProvider
from agent.storage.models import TelemetryEventDTO


class MockNetworkConnectionProvider(NetworkConnectionProvider):
    """Mock connection provider."""

    def __init__(self, conn_batches=None):
        self.conn_batches = conn_batches or [[]]
        self._index = 0

    def get_connections(self):
        if self._index < len(self.conn_batches):
            batch = self.conn_batches[self._index]
            self._index += 1
            return batch
        return self.conn_batches[-1] if self.conn_batches else []


def test_network_collector_delta_detection():
    events = []
    # Batch 0: baseline, Batch 1: new connection
    provider = MockNetworkConnectionProvider([
        [
            {
                "local_addr": "127.0.0.1",
                "local_port": 8080,
                "remote_addr": "127.0.0.1",
                "remote_port": 5000,
                "protocol": "TCP",
                "status": "ESTABLISHED",
                "pid": 1234,
                "process_name": "python.exe",
                "direction": "inbound",
                "dns_query": None,
            }
        ],
        [
            {
                "local_addr": "127.0.0.1",
                "local_port": 8080,
                "remote_addr": "127.0.0.1",
                "remote_port": 5000,
                "protocol": "TCP",
                "status": "ESTABLISHED",
                "pid": 1234,
                "process_name": "python.exe",
                "direction": "inbound",
                "dns_query": None,
            },
            {
                "local_addr": "192.168.1.10",
                "local_port": 54321,
                "remote_addr": "1.2.3.4",
                "remote_port": 4444,
                "protocol": "TCP",
                "status": "ESTABLISHED",
                "pid": 5678,
                "process_name": "powershell.exe",
                "direction": "outbound",
                "dns_query": "malicious.com",
            },
        ]
    ])

    collector = NetworkCollector(
        event_sink=events.append,
        provider=provider,
        poll_interval=0.1,
    )
    assert collector.collector_type() == "network"

    collector.start()
    time.sleep(0.3)
    collector.stop()

    assert len(events) == 1
    ev = events[0]
    assert ev.collector_type == "network"
    assert ev.event_type == "network_connection"
    assert ev.data["remote_addr"] == "1.2.3.4"
    assert ev.severity == "high"
