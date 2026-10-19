"""Task 4 durability and evidence regressions; no endpoint action is executed."""
import json
import threading
import time
from datetime import datetime, timezone

from zta.api.background import BackgroundWorker
from zta.api.server import WebSocketHub, ZTABackgroundEngine
from zta.engine.events.wazuh_adapter import ZTAEventAdapter
from zta.storage.database import ZTADatabase, ZTARepository


def event(identifier):
    return ZTAEventAdapter.from_dict({
        "id": identifier,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "agent": {"id": "task4-agent", "name": "TASK4-HOST"},
        "event_type": "SERVICE_INSTALL",
        "user": {"name": "analyst", "session_id": 3},
    })


def engine_at(path):
    return ZTABackgroundEngine(ZTARepository(ZTADatabase(path)), WebSocketHub())


def test_rule_evaluation_distinguishes_error_no_match_and_match(tmp_path):
    engine = engine_at(tmp_path / "manager.db")
    with engine.repo.db.get_connection() as conn:
        conn.execute("UPDATE rules SET condition_json=? WHERE rule_id='RULE-0001'", (json.dumps({"not": {}}),))
    item = event("task4-outcomes")
    engine.repo.save_event(item)
    engine.process_event(item)
    with engine.repo.db.get_connection() as conn:
        rows = {r["rule_id"]: dict(r) for r in conn.execute(
            "SELECT * FROM rule_evaluations WHERE event_id=?", (item.event_id,))}
    assert rows["RULE-0001"]["outcome"] == "EVALUATION_ERROR"
    assert rows["RULE-0001"]["result"] == 0
    assert rows["RULE-0001"]["error_code"]
    assert rows["RULE-0004"]["outcome"] == "MATCH"
    assert rows["RULE-0004"]["rule_version"] == 1
    assert any(row["outcome"] == "NO_MATCH" for row in rows.values())


def test_distinct_events_do_not_collapse_into_one_alert(tmp_path):
    engine = engine_at(tmp_path / "manager.db")
    for identifier in ("task4-distinct-1", "task4-distinct-2"):
        item = event(identifier)
        engine.repo.save_event(item)
        engine.process_event(item)
    incidents = engine.repo.get_incidents(100)
    matches = engine.repo.get_rule_matches(100)
    assert len([m for m in matches if m["rule_id"] == "RULE-0004"]) == 2
    assert len([i for i in incidents if i["rule_id"] == "RULE-0004"]) == 2
    assert len({i["incident_id"] for i in incidents}) == len(incidents)


def test_background_failure_retries_automatically_and_exactly_once(tmp_path, monkeypatch):
    monkeypatch.setenv("ZTA_EVENT_RETRY_BASE_SECONDS", "0.01")
    engine = engine_at(tmp_path / "manager.db")
    original = engine.repo.save_incident
    calls = {"count": 0}

    def fail_once(*args, **kwargs):
        calls["count"] += 1
        if calls["count"] == 1:
            raise RuntimeError("temporary database boundary failure")
        return original(*args, **kwargs)

    monkeypatch.setattr(engine.repo, "save_incident", fail_once)
    item = event("task4-auto-retry")
    engine.repo.save_event(item)
    worker = BackgroundWorker(engine)
    worker.tick()
    assert engine.repo.get_recent_events()[0]["processing_state"] == "FAILED"
    time.sleep(0.02)
    worker.tick()
    row = engine.repo.get_recent_events()[0]
    assert row["processing_state"] == "COMPLETED"
    assert row["processing_attempt_count"] == 2
    assert len(engine.repo.get_rule_matches(100)) == 1
    assert len(engine.repo.get_agent_risk_history("task4-agent", 100)) == 1


def test_restart_recovers_abandoned_claim(tmp_path):
    engine = engine_at(tmp_path / "manager.db")
    item = event("task4-restart")
    engine.repo.save_event(item)
    with engine.repo.db.get_connection() as conn:
        conn.execute("UPDATE zta_events SET processing_state='PROCESSING',processing_worker_id='dead-worker' WHERE event_id=?", (item.event_id,))
    worker = BackgroundWorker(engine)
    row = engine.repo.get_recent_events()[0]
    assert row["processing_state"] == "FAILED"
    assert row["processing_next_attempt_at"]
    worker.tick()
    assert engine.repo.get_recent_events()[0]["processing_state"] == "COMPLETED"


def test_two_workers_cannot_duplicate_detection_outcome(tmp_path):
    engine = engine_at(tmp_path / "manager.db")
    item = event("task4-concurrent")
    engine.repo.save_event(item)
    workers = [BackgroundWorker(engine), BackgroundWorker(engine)]
    threads = [threading.Thread(target=worker.tick) for worker in workers]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert engine.repo.get_recent_events()[0]["processing_state"] == "COMPLETED"
    assert len(engine.repo.get_rule_matches(100)) == 1
    assert len(engine.repo.get_agent_risk_history("task4-agent", 100)) == 1
    assert len(engine.repo.get_incidents(100)) == 1
