"""Operator authentication and role-based permissions."""

import hashlib
import hmac
import os
import re
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone


ROLE_PERMISSIONS = {
    "ADMIN": {"read", "audit:read", "stream", "config:write", "response:write", "users:manage"},
    "SOC_ANALYST": {"read", "stream", "response:write"},
    "AUDITOR": {"read", "audit:read", "stream"},
    "VIEWER": {"read"},
}


def _now():
    return datetime.now(timezone.utc)


def _token_hash(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _password_hash(password, salt=None):
    if not isinstance(password, str) or len(password) < 12 or len(password) > 256:
        raise ValueError("Password must be between 12 and 256 characters")
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 240_000)
    return f"pbkdf2_sha256$240000${salt.hex()}${digest.hex()}"


def _verify_password(password, encoded):
    try:
        if not isinstance(password, str) or not 12 <= len(password) <= 256:
            return False
        algorithm, iterations, salt, expected = encoded.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), int(iterations))
        return hmac.compare_digest(actual.hex(), expected)
    except (AttributeError, TypeError, ValueError):
        return False


class OperatorAuth:
    def __init__(self, db):
        self.db = db

    def identity(self, token):
        legacy = os.environ.get("ZTA_ADMIN_TOKEN", "")
        if legacy and token and hmac.compare_digest(token.encode("utf-8"), legacy.encode("utf-8")):
            return {"user_id": "legacy-admin", "username": "legacy-admin", "role": "ADMIN", "permissions": sorted(ROLE_PERMISSIONS["ADMIN"]), "legacy": True}
        if not token:
            return None
        now = _now().isoformat()
        with self.db.get_connection() as conn:
            row = conn.execute(
                """SELECT u.user_id,u.username,u.role FROM operator_sessions s
                   JOIN operator_users u ON u.user_id=s.user_id
                   WHERE s.token_hash=? AND s.expires_at>? AND u.enabled=1""",
                (_token_hash(token), now),
            ).fetchone()
            if not row:
                return None
            conn.execute("UPDATE operator_sessions SET last_used_at=? WHERE token_hash=?", (now, _token_hash(token)))
            result = dict(row)
        result["permissions"] = sorted(ROLE_PERMISSIONS.get(result["role"], set()))
        result["legacy"] = False
        return result

    def login(self, username, password):
        with self.db.get_connection() as conn:
            row = conn.execute(
                "SELECT user_id,username,password_hash,role FROM operator_users WHERE username=? COLLATE NOCASE AND enabled=1",
                (str(username or "").strip(),),
            ).fetchone()
            if not row or not _verify_password(password, row["password_hash"]):
                return None
            token = secrets.token_urlsafe(32)
            created = _now()
            expires = created + timedelta(hours=8)
            conn.execute(
                "INSERT INTO operator_sessions(session_id,user_id,token_hash,created_at,expires_at,last_used_at) VALUES(?,?,?,?,?,?)",
                (secrets.token_hex(16), row["user_id"], _token_hash(token), created.isoformat(), expires.isoformat(), created.isoformat()),
            )
            conn.execute("UPDATE operator_users SET last_login_at=? WHERE user_id=?", (created.isoformat(), row["user_id"]))
        identity = {"user_id": row["user_id"], "username": row["username"], "role": row["role"], "permissions": sorted(ROLE_PERMISSIONS[row["role"]])}
        return {"access_token": token, "token_type": "Bearer", "expires_at": expires.isoformat(), "user": identity}

    def logout(self, token):
        if token:
            with self.db.get_connection() as conn:
                conn.execute("DELETE FROM operator_sessions WHERE token_hash=?", (_token_hash(token),))

    def change_password(self, user_id, current_password, new_password, current_token):
        """Changes an operator password and revokes every other active session."""
        with self.db.get_connection() as conn:
            row = conn.execute(
                "SELECT password_hash FROM operator_users WHERE user_id=? AND enabled=1", (user_id,)
            ).fetchone()
            if not row or not _verify_password(current_password, row["password_hash"]):
                raise ValueError("Current password is incorrect")
            new_hash = _password_hash(new_password)
            if _verify_password(current_password, new_hash):
                raise ValueError("New password must be different from the current password")
            conn.execute("UPDATE operator_users SET password_hash=? WHERE user_id=?", (new_hash, user_id))
            conn.execute(
                "DELETE FROM operator_sessions WHERE user_id=? AND token_hash<>?",
                (user_id, _token_hash(current_token)),
            )
        return {"status": "PASSWORD_CHANGED"}

    def create_user(self, payload, actor):
        username = str(payload.get("username", "")).strip()
        role = str(payload.get("role", "VIEWER")).upper()
        if not re.fullmatch(r"[A-Za-z0-9_.@-]{3,64}", username):
            raise ValueError("Username must be 3-64 safe characters")
        if role not in ROLE_PERMISSIONS:
            raise ValueError("Unknown role")
        now = _now().isoformat()
        user_id = "usr-" + secrets.token_hex(8)
        with self.db.get_connection() as conn:
            try:
                conn.execute(
                    "INSERT INTO operator_users(user_id,username,password_hash,role,enabled,created_at,created_by) VALUES(?,?,?,?,1,?,?)",
                    (user_id, username, _password_hash(payload.get("password")), role, now, actor),
                )
            except sqlite3.IntegrityError as exc:
                raise ValueError("Username already exists") from exc
        return {"user_id": user_id, "username": username, "role": role, "enabled": True, "permissions": sorted(ROLE_PERMISSIONS[role]), "created_at": now}

    def list_users(self):
        with self.db.get_connection() as conn:
            rows = conn.execute("SELECT user_id,username,role,enabled,created_at,created_by,last_login_at FROM operator_users ORDER BY username COLLATE NOCASE").fetchall()
        return [dict(row) for row in rows]
