"""Task 5 response lifecycle tests. No disruptive Windows action is executed."""
import hashlib
import json
import threading
import time
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from zta.agent.agent_daemon import ZTAAgentDaemon
from zta.agent.commands.authorization import sign
from zta.agent.commands.command_receiver import CommandExecutionReport
from zta.api.ingestion import command_result
from zta.api.server import WebSocketHub
from zta.powershell.ps_executor import PSResult, PowerShellExecutor
from zta.powershell.quarantine import FileQuarantine
from zta.storage.database import ZTADatabase, ZTARepository


TOKEN = "task5-agent-secret"


def signed_command(command_id="task5-command", action="LOGOUT_USER", params=None):
    return sign({"command_id": command_id, "agent_id": "task5-agent", "action_type": action,
                 "params": params or {"UserName": "disposable", "SessionId": "7"},
                 "status": "DISPATCHED", "execution_source": "AGENT_ONLINE",
                 "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=2)).isoformat()}, TOKEN)


def manager(tmp_path, action="LOCK_WORKSTATION"):
    repo = ZTARepository(ZTADatabase(tmp_path / "manager.db", seed_defaults=False))
    now = datetime.now(timezone.utc)
    repo.save_command({"command_id": "manager-command", "agent_id": "task5-agent", "action_type": action,
                       "params": {}, "status": "DISPATCHED", "created_at": now.isoformat(),
                       "expires_at": (now + timedelta(minutes=2)).isoformat()})
    return SimpleNamespace(repo=repo, hub=WebSocketHub()), repo


def test_concurrent_delivery_claim_executes_only_once(tmp_path):
    agent = ZTAAgentDaemon(db_path=str(tmp_path / "agent.db"), agent_id="task5-agent", token=TOKEN)
    entered, release = threading.Event(), threading.Event()

    def execute(*args, **kwargs):
        entered.set(); release.wait(2)
        return CommandExecutionReport("task5-command", "LOGOUT_USER", "FAILED", "",
                                      error="controlled failure", verification="VERIFICATION_FAILED",
                                      verification_status="VERIFICATION_FAILED", error_code="ACCESS_DENIED")

    agent.command_receiver.process_command = MagicMock(side_effect=execute)
    command = signed_command()
    results = []
    first = threading.Thread(target=lambda: results.append(agent.execute_command(command)))
    first.start()
    deadline = time.monotonic() + 8
    claimed = False
    while time.monotonic() < deadline:
        with agent.offline_queue._get_connection() as conn:
            claimed = bool(conn.execute("SELECT 1 FROM command_journal WHERE command_id='task5-command'").fetchone())
        if claimed:
            break
        time.sleep(0.02)
    assert claimed
    second = threading.Thread(target=lambda: results.append(agent.execute_command(command)))
    second.start(); second.join(); release.set(); first.join()
    assert agent.command_receiver.process_command.call_count == 1
    assert {result["status"] for result in results} == {"FAILED", "UNKNOWN"}
    assert agent.execute_command(command)["status"] == "FAILED"


def test_restart_converts_unfinished_claim_to_unknown_without_execution(tmp_path):
    path = tmp_path / "agent.db"
    agent = ZTAAgentDaemon(db_path=str(path), agent_id="task5-agent", token=TOKEN)
    command = signed_command("interrupted")
    with agent.offline_queue._get_connection() as conn:
        conn.execute("""INSERT INTO command_journal
            (command_id,correlation_id,action,payload,timestamp,state,received_at,execution_started_at)
            VALUES (?,?,?,?,?,'EXECUTING',?,?)""",
            ("interrupted", "corr", "LOGOUT_USER", json.dumps(command),
             datetime.now(timezone.utc).isoformat(), datetime.now(timezone.utc).isoformat(),
             datetime.now(timezone.utc).isoformat()))
    restarted = ZTAAgentDaemon(db_path=str(path), agent_id="task5-agent", token=TOKEN)
    with restarted.offline_queue._get_connection() as conn:
        row = dict(conn.execute("SELECT * FROM command_journal WHERE command_id='interrupted'").fetchone())
    assert row["state"] == "UNKNOWN"
    assert json.loads(row["report"])["error_code"] == "INTERRUPTED_UNKNOWN"
    assert restarted.execute_command(command)["status"] == "UNKNOWN"


def test_result_upload_waits_for_durable_ack_and_records_upload_time(tmp_path):
    agent = ZTAAgentDaemon(db_path=str(tmp_path / "agent.db"), agent_id="task5-agent", token=TOKEN)
    agent.command_receiver.ps_executor.execute_template = MagicMock(return_value=PSResult(False, "", "denied", 5))
    agent.execute_command(signed_command("upload-retry"))
    agent.post = MagicMock(return_value=SimpleNamespace(status_code=503))
    agent.upload_results()
    with agent.offline_queue._get_connection() as conn:
        assert conn.execute("SELECT reported FROM command_journal").fetchone()[0] == 0
    agent.post.return_value = SimpleNamespace(status_code=200)
    agent.upload_results()
    with agent.offline_queue._get_connection() as conn:
        row = conn.execute("SELECT reported,result_uploaded_at FROM command_journal").fetchone()
    assert row[0] == 1 and row[1]


def test_manager_persists_unknown_result_and_duplicate_is_idempotent(tmp_path):
    handler, repo = manager(tmp_path)
    payload = {"result_id": "result-unknown", "command_id": "manager-command", "agent_id": "task5-agent",
               "action_type": "LOCK_WORKSTATION", "status": "UNKNOWN", "output": "",
               "error": "postcondition unavailable", "verification": "EXECUTION_COMPLETED_UNVERIFIED",
               "verification_status": "UNKNOWN", "executed_at": datetime.now(timezone.utc).isoformat(),
               "completed_at": datetime.now(timezone.utc).isoformat(), "correlation_id": "corr-1"}
    assert command_result(handler, payload) is True
    assert command_result(handler, payload) is False
    command = repo.get_commands()[0]
    assert command["status"] == "UNKNOWN" and command["result_id"] == "result-unknown"
    with repo.db.get_connection() as conn:
        assert conn.execute("SELECT COUNT(*) FROM command_results").fetchone()[0] == 1


def test_manager_rejects_unverified_success_and_wrong_agent(tmp_path):
    handler, _ = manager(tmp_path)
    base = {"command_id": "manager-command", "agent_id": "task5-agent", "status": "SUCCESS",
            "verification": "EXECUTION_COMPLETED_UNVERIFIED"}
    with pytest.raises(ValueError, match="cannot report SUCCESS"):
        command_result(handler, base)
    with pytest.raises(ValueError, match="wrong agent"):
        command_result(handler, {**base, "agent_id": "other", "status": "FAILED"})


def test_quarantine_moves_only_hash_verified_safe_file(tmp_path, monkeypatch):
    protected = tmp_path / "protected"
    monkeypatch.setenv("ProgramData", str(protected))
    source = tmp_path / "sample.bin"
    source.write_bytes(b"harmless task5 fixture")
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    handler = FileQuarantine(tmp_path / "quarantine")
    evidence = handler.quarantine(str(source), digest)
    assert not source.exists()
    assert (tmp_path / "quarantine" / (evidence["quarantine_id"] + ".bin")).exists()
    unsafe = protected / "system.bin"; unsafe.parent.mkdir(); unsafe.write_bytes(b"protected")
    with pytest.raises(ValueError, match="Protected"):
        FileQuarantine(tmp_path / "other").validate(str(unsafe), hashlib.sha256(b"protected").hexdigest())


def test_workstation_lock_is_truthful_when_windows_api_is_unavailable(monkeypatch):
    import zta.powershell.ps_executor as module
    executor = PowerShellExecutor()
    monkeypatch.setattr(module.os, "name", "posix")
    result = executor.execute_template("LOCK_WORKSTATION", {"UserName": "user", "SessionId": "3"})
    assert result.success is False
    assert result.verification == "UNAVAILABLE"
    assert result.error_code == "UNSUPPORTED_OS"
