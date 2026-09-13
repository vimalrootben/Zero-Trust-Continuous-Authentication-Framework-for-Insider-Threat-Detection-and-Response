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
