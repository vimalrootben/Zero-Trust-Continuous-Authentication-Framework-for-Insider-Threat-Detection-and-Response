"""Unit tests for ZTA Storage Repository and REST API Server."""

from datetime import datetime, timezone
import json
import urllib.request
import threading
import time

from zta.engine.events.models import ZTAAgent, ZTAEvent
from zta.storage.database import ZTADatabase, ZTARepository
from zta.api.server import create_zta_server


def test_sqlite_repository_persistence(tmp_path):
    """Test saving and retrieving ZTA events and incidents in SQLite repository."""
    db_file = tmp_path / "test_zta.db"
    db = ZTADatabase(str(db_file))
    repo = ZTARepository(db)

    # 1. Save Event
    event = ZTAEvent(
        event_id="evt-100",
        timestamp=datetime.now(timezone.utc),
        agent=ZTAAgent(id="001", name="WIN-TEST-01"),
        event_type="PROCESS_CREATION",
        severity="HIGH",
        raw_event={"sample": "data"},
    )
    repo.save_event(event)

    events = repo.get_recent_events()
    assert len(events) == 1
    assert events[0]["event_id"] == "evt-100"
    assert events[0]["agent_name"] == "WIN-TEST-01"

    # 2. Save Incident
    incident = {
        "incident_id": "INC-001",
        "agent_id": "001",
        "agent_name": "WIN-TEST-01",
        "severity": "CRITICAL",
        "risk_score": 90,
        "trust_score": 10,
        "status": "CONTAINED",
        "trigger_reason": "High risk PowerShell activity",
        "action_taken": "ISOLATE_ENDPOINT",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    repo.save_incident(incident)

    incidents = repo.get_incidents()
    assert len(incidents) == 1
    assert incidents[0]["incident_id"] == "INC-001"
    assert incidents[0]["action_taken"] == "ISOLATE_ENDPOINT"


def test_api_server_endpoints(tmp_path):
    """Test ZTA API Server endpoints over HTTP."""
    server = create_zta_server(host="127.0.0.1", port=0, db_path=tmp_path / "api.db")
    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()

    time.sleep(0.2)  # Allow server time to bind

    try:
        # Test GET /api/zta/overview
        url = f"http://127.0.0.1:{server.server_port}/api/zta/overview"
        req = urllib.request.urlopen(urllib.request.Request(url, headers={"Authorization": "Bearer fixture-admin-token"}))
        assert req.status == 200
        data = json.loads(req.read().decode("utf-8"))
        assert data["system"] == "ZTA (Zero Trust Architecture)"
        assert data["status"] == "HEALTHY"

        # Test POST /api/zta/actions/execute
        post_url = f"http://127.0.0.1:{server.server_port}/api/zta/actions/execute"
        post_data = json.dumps({"action": "ISOLATE_ENDPOINT", "agent_id": "001"}).encode("utf-8")
        post_req = urllib.request.Request(post_url, data=post_data, headers={"Content-Type": "application/json", "Authorization": "Bearer fixture-admin-token"})
        resp = urllib.request.urlopen(post_req)
        assert resp.status == 200
        post_resp = json.loads(resp.read().decode("utf-8"))
        assert post_resp["status"] == "PREVIEW"
        assert post_resp["action"] == "ISOLATE_ENDPOINT"

    finally:
        server.shutdown()
        server.server_close()
