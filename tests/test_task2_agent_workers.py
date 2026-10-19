"""Focused Task 2 tests; OS calls are isolated, never fabricated as live evidence."""
import json
import threading
import time
from types import SimpleNamespace
from unittest.mock import patch

from zta.agent.collectors import WindowsEventCollector
from zta.agent.workers import BackgroundWorkerSupervisor


class MemoryState:
    def __init__(self):
        self.values = {}

    def get(self, key, default=None):
        return self.values.get(key, default)

    def set(self, key, value):
        self.values[key] = value


def completed(rows):
    return SimpleNamespace(stdout=json.dumps(rows), stderr="", returncode=0)


def test_worker_supervisor_is_idempotent_and_isolates_failures():
    stop = threading.Event()
    calls = {"healthy": 0, "failed": 0}

    def healthy():
        calls["healthy"] += 1

    def failed():
        calls["failed"] += 1
        raise RuntimeError("isolated failure")

    supervisor = BackgroundWorkerSupervisor(stop)
    supervisor.register("healthy", healthy, 0.01, 0.02)
    supervisor.register("failed", failed, 0.01, 0.02)
    assert supervisor.start() is True
    assert supervisor.start() is False
    time.sleep(0.07)
    supervisor.stop(timeout=1)
    states = supervisor.snapshot()
    assert calls["healthy"] > 1
    assert calls["failed"] > 0
    assert states["healthy"]["current_state"] == "STOPPED"
    assert states["failed"]["restart_count"] > 0


def test_process_snapshot_emits_start_exit_once_and_protects_pid_reuse():
    state = MemoryState()
    collector = WindowsEventCollector(state)
    first = [
        {"pid": 10, "parent_pid": 1, "name": "old.exe", "path": "C:\\old.exe",
         "command_line": "old.exe", "username": "alice", "domain": "TEST",
         "session_id": 2, "created_at": "2026-01-01T00:00:00Z"}
    ]
    second = [
        {"pid": 10, "parent_pid": 1, "name": "new.exe", "path": "C:\\new.exe",
         "command_line": "new.exe", "username": None, "domain": None,
         "session_id": 2, "created_at": "2026-01-01T00:01:00Z"}
    ]
    events = []
    with patch("zta.agent.collectors.subprocess.run", side_effect=[completed(first), completed(second), completed(second)]):
        collector.poll_processes(events.append)  # establishes current-state baseline
        collector.poll_processes(events.append)
        collector.poll_processes(events.append)
    assert [event["event_type"] for event in events] == ["PROCESS_STARTED", "PROCESS_EXITED"]
    started = next(event for event in events if event["event_type"] == "PROCESS_STARTED")
    exited = next(event for event in events if event["event_type"] == "PROCESS_EXITED")
    assert started["process"]["name"] == "new.exe"
    assert exited["process"]["name"] == "old.exe"
    assert started["id"] != exited["id"]


def test_network_snapshot_tracks_tcp_udp_listener_and_close_without_duplicates():
    state = MemoryState()
    collector = WindowsEventCollector(state)
    tcp = {"protocol": "TCP", "local_address": "127.0.0.1", "local_port": 4444,
           "remote_address": "127.0.0.1", "remote_port": 5555, "state": "Established", "pid": 20,
           "process": {"name": "client.exe", "path": "C:\\client.exe", "username": "alice",
                       "created_at": "2026-01-01T00:00:00Z"}}
    listener = {"protocol": "TCP", "local_address": "0.0.0.0", "local_port": 8080,
                "remote_address": "0.0.0.0", "remote_port": 0, "state": "Listen", "pid": 30,
                "process": {"name": "server.exe", "created_at": "2026-01-01T00:00:00Z"}}
    udp = {"protocol": "UDP", "local_address": "0.0.0.0", "local_port": 5353,
           "remote_address": None, "remote_port": None, "state": "BOUND", "pid": 40, "process": {}}
    events = []
    with patch("zta.agent.collectors.subprocess.run", side_effect=[
        completed([tcp, listener, udp]), completed([tcp, listener, udp]), completed([])]):
        collector.poll_network(events.append)
        collector.poll_network(events.append)
        assert events == []
        collector.poll_network(events.append)
    assert sorted(event["event_type"] for event in events) == [
        "CONNECTION_CLOSED", "CONNECTION_CLOSED", "LISTENER_STOPPED"
    ]
    correlated = next(event for event in events if event["process"].get("name") == "client.exe")
    assert correlated["data"]["local_port"] == 4444
    assert correlated["data"]["protocol"] == "TCP"


def test_network_open_and_listener_started_after_baseline():
    state = MemoryState()
    collector = WindowsEventCollector(state)
    listener = {"protocol": "TCP", "local_address": "0.0.0.0", "local_port": 9000,
                "remote_address": "0.0.0.0", "remote_port": 0, "state": "Listen", "pid": 33,
                "process": {"name": None, "created_at": None}}
    events = []
    with patch("zta.agent.collectors.subprocess.run", side_effect=[completed([]), completed([listener]), completed([listener])]):
        collector.poll_network(events.append)
        collector.poll_network(events.append)
        collector.poll_network(events.append)
    assert [event["event_type"] for event in events] == ["LISTENER_STARTED"]
    assert collector.listening_ports[0]["port"] == 9000
