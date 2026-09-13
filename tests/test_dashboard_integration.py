"""Exercise persistence, API validation, static assets, and isolated server state."""
import json
import threading
import urllib.error
import urllib.request
from contextlib import contextmanager

from zta.api.server import create_zta_server
from http_support import headers as auth_headers


@contextmanager
def running(path):
    server = create_zta_server(port=0, db_path=path)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join()
        server.server_close()


def request(base, path, payload=None):
    data = None if payload is None else json.dumps(payload).encode()
    req = urllib.request.Request(base + path, data=data, headers=auth_headers(path))
    try:
        response = urllib.request.urlopen(req)
    except urllib.error.HTTPError as exc:
        response = exc
    with response:
        return response.status, json.loads(response.read())


def test_heartbeat_persists_across_restart(tmp_path):
    db = tmp_path / 'runtime' / 'api.db'
    with running(db) as base:
        assert request(base, '/api/zta/overview')[1]['total_endpoints'] == 0
        assert request(base, '/api/v1/agents/heartbeat', {'agent_id':'abc', 'hostname':'Laptop'})[0] == 200
        assert request(base, '/api/zta/overview')[1]['total_endpoints'] == 1
    with running(db) as base:
        agent = request(base, '/api/zta/agents')[1]['agents'][0]
        assert agent['name'] == 'Laptop'
        assert agent['status'] == 'ACTIVE'
        assert agent['risk_score'] is None
    with running(tmp_path / 'other.db') as base:
        assert request(base, '/api/zta/agents')[1]['agents'] == []


def test_bulk_validation_and_persistence(tmp_path):
    with running(tmp_path / 'api.db') as base:
        alert = {'id':'event-1', 'agent':{'id':'abc','name':'Laptop'}, 'rule':{'id':100,'level':12,'description':'Test alert'}}
        assert request(base, '/api/v1/telemetry/bulk', [alert])[0] == 201
        assert request(base, '/api/zta/events')[1]['events'][0]['severity'] == 'CRITICAL'
        assert request(base, '/api/v1/telemetry/bulk', [alert])[0] == 201
        assert request(base, '/api/zta/overview')[1]['total_events'] == 1
        assert request(base, '/api/v1/telemetry/bulk', [dict(alert,id='event-2'),{}])[0] == 400
        assert request(base, '/api/zta/overview')[1]['total_events'] == 1
        assert request(base, '/api/v1/agents/heartbeat', [1])[0] == 400
        assert request(base, '/api/zta/events?limit=no')[0] == 400
        assert request(base, '/api/zta/actions/execute', {'action':'ISOLATE_ENDPOINT','agent_id':'abc','dry_run':False})[0] == 409
        offline = {'id':'offline-1', 'error':'Connection failed', 'telemetry':{'agent_id':'abc','hostname':'Laptop'}}
        assert request(base, '/api/v1/telemetry/bulk', [offline])[0] == 201


def test_dashboard_assets_and_working_directory(tmp_path):
    import os
    original = os.getcwd()
    with running(tmp_path / 'api.db') as base:
        for path in ['/', '/assets/dashboard.css', '/assets/dashboard.js']:
            with urllib.request.urlopen(base + path) as response:
                assert response.status == 200
                assert response.read()
        assert os.getcwd() == original
        try:
            urllib.request.urlopen(base + '/run_dashboard.py')
            assert False, 'Python source should not be exposed'
        except urllib.error.HTTPError as exc:
            assert exc.code == 404
