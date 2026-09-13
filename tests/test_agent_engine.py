"""Unit tests for ZTA Agent subsystems (Installer, OfflineQueue, LocalRuleEngine, AgentCommandReceiver)."""

from datetime import datetime, timezone
import os
import pytest

from zta_windows_installer import ZTAWindowsInstaller
from zta.agent.storage.offline_queue import OfflineQueue
from zta.agent.rules.local_rule_engine import LocalRuleEngine, LocalMatch
from zta.agent.commands.command_receiver import AgentCommandReceiver, CommandValidationError
from zta.engine.events.models import ZTAAgent, ZTAEvent, ZTAProcess


def test_windows_installer_directory_and_config(tmp_path):
    """Test ZTA Windows Installer directory and configuration creation."""
    install_dir = tmp_path / "ZTA_Agent_Test"
    installer = ZTAWindowsInstaller(install_dir=str(install_dir), manager_url="http://127.0.0.1:8080")

    success = installer.install(check_privileges=False)
    assert success is True
    assert (install_dir / "config" / "zta_agent.env").exists()
    assert (install_dir / "storage" / "zta_agent_offline.db").exists()


def test_offline_queue_preserves_unsynced_events(tmp_path):
    """Test SQLite OfflineQueue enqueueing, depth, capacity warnings, and dequeuing."""
    db_file = tmp_path / "offline_queue_test.db"
    queue = OfflineQueue(db_path=str(db_file), max_size=2)

    assert queue.queue_depth() == 0

    # Enqueue low severity event
    queue.enqueue("evt-1", "process", "LOW", {"name": "cmd.exe"})
    assert queue.queue_depth() == 1

    # Enqueue high severity event
    queue.enqueue("evt-2", "process", "HIGH", {"name": "powershell.exe"})
    assert queue.queue_depth() == 2

    # Capacity threshold must not evict unsynchronized events
    queue.enqueue("evt-3", "network", "CRITICAL", {"ip": "192.168.1.1"})
    assert queue.queue_depth() == 3

    batch = queue.dequeue_batch(10)
    assert len(batch) == 3
    event_ids = [item["event_id"] for item in batch]
    assert "evt-1" in event_ids
    assert "evt-2" in event_ids
    assert "evt-3" in event_ids

    queue.mark_synced(["evt-1", "evt-2", "evt-3"])
    assert queue.queue_depth() == 0


def test_local_rule_engine_matching():
    """Test LocalRuleEngine evaluation on agent telemetry events."""
    engine = LocalRuleEngine()

    # Normal process -> No match
    normal_evt = ZTAEvent(
        event_id="e-1",
        timestamp=datetime.now(timezone.utc),
        agent=ZTAAgent(id="001", name="HOST-1"),
        process=ZTAProcess(name="notepad.exe", command_line="notepad.exe file.txt"),
    )
    assert engine.evaluate(normal_evt) is None

    # Encoded PowerShell process -> LocalMatch triggered
    ps_evt = ZTAEvent(
        event_id="e-2",
        timestamp=datetime.now(timezone.utc),
        agent=ZTAAgent(id="001", name="HOST-1"),
        process=ZTAProcess(name="powershell.exe", command_line="powershell.exe -Enc aW52b2tl..."),
    )
    match = engine.evaluate(ps_evt)
    assert isinstance(match, LocalMatch)
    assert match.rule_id == "LOC-RULE-001"
    assert match.severity == "HIGH"


def test_agent_command_receiver_dispatch():
    """Test AgentCommandReceiver validating and executing commands via dry-run."""
    receiver = AgentCommandReceiver()

    # Invalid payload -> raises CommandValidationError
    with pytest.raises(CommandValidationError):
        receiver.process_command("not-a-dict")

    # Missing action -> raises CommandValidationError
    with pytest.raises(CommandValidationError):
        receiver.process_command({"command_id": "cmd-1"})

    # Valid command -> dispatches cleanly in dry-run
    report = receiver.process_command(
        {"command_id": "cmd-100", "action": "KILL_PROCESS", "params": {"ProcessName": "calc.exe", "ProcessId":"777"}},
        dry_run=True,
    )
    assert report.command_id == "cmd-100"
    assert report.status == "PREVIEW"
    assert "kill_process.ps1" in report.output
