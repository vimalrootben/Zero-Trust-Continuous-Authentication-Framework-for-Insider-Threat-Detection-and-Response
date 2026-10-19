import json
import logging
import time
from pathlib import Path

from zta.agent.operational_logging import UTCJsonFormatter, configure_agent_logging
from zta.api.server import WebSocketHub
from zta.storage.database import ZTADatabase, ZTARepository


def repository(tmp_path):
    return ZTARepository(ZTADatabase(str(tmp_path / "task6.db"), seed_defaults=False))


def test_agent_operational_log_is_structured_durable_and_rotating(tmp_path, monkeypatch):
    path = tmp_path / "agent.jsonl"
    monkeypatch.setenv("ZTA_AGENT_LOG_MAX_BYTES", "65536")
    monkeypatch.setenv("ZTA_AGENT_LOG_BACKUPS", "2")
    assert configure_agent_logging(path) == path
    logger = logging.getLogger("zta.agent.test")
    logger.info("agent started", extra={"event_name": "agent.started", "agent_id": "endpoint-1"})
    for handler in logging.getLogger().handlers:
        if hasattr(handler, "flush"): handler.flush()
    record = json.loads(path.read_text(encoding="utf-8").splitlines()[-1])
    assert record["timestamp_utc"].endswith("Z")
    assert record["event_name"] == "agent.started"
    assert record["agent_id"] == "endpoint-1"


def test_formatter_truncates_untrusted_fields_and_serializes_exceptions():
    formatter = UTCJsonFormatter()
    record = logging.LogRecord("component", logging.ERROR, __file__, 1, "x" * 5000, (), None)
    record.correlation_id = "c" * 1000
    item = json.loads(formatter.format(record))
    assert len(item["message"]) == 4096
    assert len(item["correlation_id"]) == 512


def test_outbox_is_transactional_replayable_and_deduplicated(tmp_path):
    repo = repository(tmp_path)
    try:
        with repo.db.transaction():
            repo.enqueue_realtime_event("alert.created", {"alert_id": "a1"}, event_id="pub-a1")
            raise RuntimeError("rollback")
    except RuntimeError:
        pass
    assert repo.get_realtime_events() == []
    first = repo.enqueue_realtime_event("alert.created", {"alert_id": "a1"}, event_id="pub-a1")
    second = repo.enqueue_realtime_event("alert.created", {"alert_id": "a1"}, event_id="pub-a1")
    assert first["sequence_number"] == second["sequence_number"]
    assert len(repo.get_realtime_events(after_sequence=0)) == 1


def test_audit_filtering_and_correlation_search(tmp_path):
    repo = repository(tmp_path)
    repo.save_audit("ALERT_CREATED", "created", details={"correlation_id": "corr-1"})
    repo.save_audit("POLICY_UPDATED", "updated", details={"correlation_id": "corr-2"})
    assert [row["event_type"] for row in repo.get_audit_logs(event_type="ALERT_CREATED")] == ["ALERT_CREATED"]
    assert [row["event_type"] for row in repo.get_audit_logs(correlation_id="corr-2")] == ["POLICY_UPDATED"]


class _SlowOutput:
    def write(self, data):
        time.sleep(.25)
    def flush(self): pass


class _Client:
    def __init__(self):
        self.wfile = _SlowOutput()
        self.close_connection = False


def test_slow_websocket_client_does_not_block_broadcast(monkeypatch):
    monkeypatch.setenv("ZTA_WS_CLIENT_QUEUE_SIZE", "8")
    hub = WebSocketHub()
    client = _Client()
    hub.register_ws(client, lambda: True)
    started = time.monotonic()
    for number in range(4): hub.broadcast("alert.updated", {"number": number})
    assert time.monotonic() - started < .15
    client.close_connection = True
    hub.unregister_ws(client)


def test_dashboard_implements_sequence_recovery_and_deduplication():
    source = (Path(__file__).parents[1] / "dashboard" / "assets" / "dashboard.js").read_text(encoding="utf-8")
    assert "after_sequence=" in source
    assert "seenRealtimeEvents" in source
    assert "sequence > state.lastRealtimeSequence + 1" in source
    assert "await refresh()" in source
