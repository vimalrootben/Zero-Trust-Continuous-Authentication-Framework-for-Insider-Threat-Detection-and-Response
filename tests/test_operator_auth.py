"""Operator authentication, authorization, and user lifecycle tests."""

import json
import socket
import threading
import urllib.error
import urllib.request

import pytest

from zta.api.server import create_zta_server


@pytest.fixture
def auth_server(tmp_path, monkeypatch):
    monkeypatch.setenv("ZTA_ADMIN_TOKEN", "fixture-admin-token")
    server = create_zta_server(port=0, db_path=tmp_path / "auth.db")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server, f"http://127.0.0.1:{server.server_port}"
    server.worker.close()
    server.shutdown()
    server.server_close()


def request(base, path, method="GET", body=None, token=None):
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(base + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as response:
            return response.status, json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}")


def create_and_login(base, username, role):
    status, created = request(base, "/api/zta/users", "POST", {"username": username, "password": "correct horse battery staple", "role": role}, "fixture-admin-token")
    assert status == 201
    assert "password" not in json.dumps(created)
    status, login = request(base, "/api/zta/auth/login", "POST", {"username": username, "password": "correct horse battery staple"})
    assert status == 200
    return login["access_token"]


def test_unauthorized_reads_writes_and_streams_fail(auth_server):
    server, base = auth_server
    assert request(base, "/api/zta/overview")[0] == 401
    assert request(base, "/api/zta/rules", "POST", {"code": "X", "name": "X"})[0] == 401
    sock = socket.create_connection(("127.0.0.1", server.server_port))
    sock.sendall(b"GET /api/zta/ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: MDEyMzQ1Njc4OWFiY2RlZg==\r\nSec-WebSocket-Version: 13\r\n\r\n")
    assert b"401" in sock.recv(1024)
    sock.close()


def test_users_sessions_permissions_and_legacy_admin(auth_server):
    _server, base = auth_server
    viewer = create_and_login(base, "read.user", "VIEWER")
    assert request(base, "/api/zta/overview", token=viewer)[0] == 200
    assert request(base, "/api/zta/rules/validate", "POST", {"condition": {}}, viewer)[0] == 403
    assert request(base, "/api/zta/users", token=viewer)[0] == 403

    admin = create_and_login(base, "local.admin", "ADMIN")
    status, session = request(base, "/api/zta/session", token=admin)
    assert status == 200
    assert session["role"] == "ADMIN" and "users:manage" in session["permissions"]
    assert request(base, "/api/zta/users", token=admin)[0] == 200
    assert request(base, "/api/zta/rules/validate", "POST", {"condition": {"field": "event_type", "op": "eq", "value": "X"}}, admin)[0] == 200
    assert request(base, "/api/zta/session", token="fixture-admin-token")[1]["role"] == "ADMIN"

    assert request(base, "/api/zta/auth/logout", "POST", {}, admin)[0] == 200
    assert request(base, "/api/zta/session", token=admin)[0] == 401


def test_stream_permission_is_role_based(auth_server):
    server, base = auth_server
    viewer = create_and_login(base, "stream.viewer", "VIEWER")
    analyst = create_and_login(base, "stream.analyst", "SOC_ANALYST")

    def handshake(token):
        sock = socket.create_connection(("127.0.0.1", server.server_port))
        protocol = "zta-token." + token
        request_data = f"GET /api/zta/ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: MDEyMzQ1Njc4OWFiY2RlZg==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: {protocol}\r\n\r\n"
        sock.sendall(request_data.encode())
        response = sock.recv(1024)
        sock.close()
        return response

    assert b"403" in handshake(viewer)
    assert b"101 Switching Protocols" in handshake(analyst)


@pytest.mark.parametrize('revoke', ['logout', 'expire', 'disable'])
def test_open_stream_stops_after_session_revocation(auth_server, revoke):
    import time
    server, base = auth_server
    token = create_and_login(base, 'revocable.analyst', 'SOC_ANALYST')
    repo, hub, _, _ = server.runtime
    with socket.create_connection(('127.0.0.1', server.server_port), timeout=3) as sock:
        sock.sendall((
            'GET /api/zta/ws HTTP/1.1\r\nHost: localhost\r\n'
            'Upgrade: websocket\r\nConnection: Upgrade\r\n'
            'Sec-WebSocket-Key: MDEyMzQ1Njc4OWFiY2RlZg==\r\n'
            'Sec-WebSocket-Version: 13\r\n'
            f'Sec-WebSocket-Protocol: zta-token.{token}\r\n\r\n'
        ).encode())
        response = b''
        while b'\r\n\r\n' not in response:
            response += sock.recv(4096)
        assert b'101 Switching Protocols' in response
        deadline = time.monotonic() + 2
        while not hub._ws_clients and time.monotonic() < deadline:
            time.sleep(.01)
        assert hub._ws_clients
        hub.broadcast('test.before', {'marker': 'authorized'})
        assert b'authorized' in sock.recv(4096)
        if revoke == 'logout':
            assert request(base, '/api/zta/auth/logout', 'POST', {}, token)[0] == 200
        else:
            with repo.db.get_connection() as conn:
                if revoke == 'expire':
                    conn.execute("UPDATE operator_sessions SET expires_at='2000-01-01T00:00:00+00:00'")
                else:
                    conn.execute("UPDATE operator_users SET enabled=0 WHERE username='revocable.analyst'")
        hub.broadcast('test.after', {'marker': 'must-not-deliver'})
        received = b''
        while True:
            part = sock.recv(4096)
            if not part:
                break
            received += part
        assert b'must-not-deliver' not in received
        assert request(base, '/api/zta/session', token=token)[0] == 401


def test_malformed_auth_requests_are_rejected_without_breaking_server(auth_server):
    _, base = auth_server
    for body in ([], 'invalid', 12):
        assert request(base, '/api/zta/auth/login', 'POST', body)[0] == 400
    create_and_login(base, 'input.viewer', 'VIEWER')
    for password in (None, {}, 'x' * 257):
        assert request(base, '/api/zta/auth/login', 'POST',
                       {'username': 'input.viewer', 'password': password})[0] == 401
    assert request(base, '/api/zta/session', token='Ã©')[0] == 401
def test_password_change_validates_current_password_and_revokes_other_sessions(auth_server):
    _server, base = auth_server
    current = create_and_login(base, "credential.user", "VIEWER")
    _, second_login = request(base, "/api/zta/auth/login", "POST", {
        "username": "credential.user", "password": "correct horse battery staple",
    })
    other_session = second_login["access_token"]

    status, result = request(base, "/api/zta/auth/password", "POST", {
        "current_password": "not the current password", "new_password": "a completely new secure password",
    }, current)
    assert status == 400 and "Current password" in result["error"]

    status, result = request(base, "/api/zta/auth/password", "POST", {
        "current_password": "correct horse battery staple", "new_password": "a completely new secure password",
    }, current)
    assert status == 200 and result["status"] == "PASSWORD_CHANGED"
    assert request(base, "/api/zta/session", token=current)[0] == 200
    assert request(base, "/api/zta/session", token=other_session)[0] == 401
    assert request(base, "/api/zta/auth/login", "POST", {
        "username": "credential.user", "password": "correct horse battery staple",
    })[0] == 401
    assert request(base, "/api/zta/auth/login", "POST", {
        "username": "credential.user", "password": "a completely new secure password",
    })[0] == 200


def test_dashboard_has_dedicated_authentication_pages():
    root = __import__("pathlib").Path(__file__).resolve().parents[1]
    html = (root / "dashboard" / "index.html").read_text(encoding="utf-8")
    script = (root / "dashboard" / "assets" / "dashboard.js").read_text(encoding="utf-8")
    assert 'id="login-page"' in html and 'id="app-shell" hidden' in html
    assert 'id="password-change"' in html and 'id="user-list"' in html
    assert "Legacy administrator token" not in html
    assert "lockDashboard();" in script and "history.replaceState" in script
