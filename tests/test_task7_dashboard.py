import csv
import io
import json
import threading
import urllib.error
import urllib.request
from contextlib import contextmanager
from pathlib import Path

from zta.api.server import create_zta_server


@contextmanager
def running(path):
    server = create_zta_server(port=0, db_path=path)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", server.runtime[0]
    finally:
        server.shutdown(); thread.join(); server.server_close()


def get(base, path, token="fixture-admin-token", raw=False):
    request = urllib.request.Request(base + path, headers={"Authorization": "Bearer " + token} if token else {})
    try: response = urllib.request.urlopen(request)
    except urllib.error.HTTPError as exc: response = exc
    with response:
        body = response.read()
        return response.status, body if raw else json.loads(body)


def test_empty_analytics_and_threat_intelligence_are_truthful(tmp_path):
    with running(tmp_path / "empty.db") as (base, _):
        assert get(base, "/api/zta/overview")[1]["total_endpoints"] == 0
        threat = get(base, "/api/zta/threat-intelligence")[1]
        assert threat == {"sources": [], "indicators": [], "configured": False,
                          "message": "No threat-intelligence feed is configured."}


def test_mitre_distinguishes_configuration_enablement_and_observation(tmp_path):
    with running(tmp_path / "mitre.db") as (base, repo):
        rule = repo.create_rule({"code":"T7-RULE", "name":"Task 7", "category":"Execution",
            "severity":"HIGH", "mitre_tactic":"Execution", "mitre_technique_id":"T1059.001",
            "condition":{"field":"event_type", "op":"eq", "value":"PROCESS_CREATION"}}, actor="test")
        with repo.db.get_connection() as conn:
            conn.execute("""INSERT INTO rule_matches(match_id,rule_id,rule_code,rule_name,agent_id,agent_name,
                event_id,severity,mitre_tactic,mitre_technique_id,matched_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                ("match-t7",rule["rule_id"],"T7-RULE","Task 7","agent","Agent","event","HIGH",
                 "Execution","T1059.001","2026-10-15T00:00:00+00:00"))
        coverage = get(base, "/api/zta/analytics/mitre-coverage")[1]
        technique = next(item for item in coverage["techniques"] if item["technique_id"] == "T1059.001")
        assert technique["configured_rules"] >= 1
        assert 0 <= technique["enabled_rules"] <= technique["configured_rules"]
        assert technique["observed_matches"] == 1


def test_timeseries_is_aggregated_bounded_and_validates_range(tmp_path):
    with running(tmp_path / "time.db") as (base, _):
        status, result = get(base, "/api/zta/analytics/events-timeseries?range=24h")
        assert status == 200 and result["timezone"] == "UTC" and result["points"] == []
        assert get(base, "/api/zta/analytics/events-timeseries?range=forever")[0] == 400


def test_reports_require_audit_permission_and_csv_is_safe(tmp_path):
    with running(tmp_path / "report.db") as (base, _):
        assert get(base, "/api/zta/reports/security-summary", token="")[0] == 401
        status, body = get(base, "/api/zta/reports/security-summary?format=csv", raw=True)
        assert status == 200
        rows = list(csv.reader(io.StringIO(body.decode("utf-8-sig"))))
        assert rows[0] == ["section", "dimension", "value"]
        assert all(not cell.startswith(("=", "+", "-", "@")) for row in rows for cell in row)


def test_effective_settings_expose_no_secrets(tmp_path):
    with running(tmp_path / "settings.db") as (base, _):
        settings = get(base, "/api/zta/settings")[1]
        assert settings["read_only"] is True
        assert not any("token" in key or "password" in key for key in settings["settings"])


def test_dashboard_has_real_task7_pages_and_no_random_live_data():
    root = Path(__file__).parents[1]
    html = (root / "dashboard" / "index.html").read_text(encoding="utf-8")
    source = (root / "dashboard" / "assets" / "dashboard.js").read_text(encoding="utf-8")
    for view in ("mitre", "threat_intel", "reports", "users", "settings"):
        assert f'data-view="{view}"' in html
    assert "Math.random" not in source
    assert "/api/zta/reports/security-summary" in source
    assert "seenRealtimeEvents" in source
