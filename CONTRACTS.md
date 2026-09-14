# Contracts

## Canonical event

Required: `event_id: string`, `timestamp: ISO-8601`, `agent: {id, name, ip?}`.

Optional/defaulted: `user: {name?, domain?, session_id?}`, `process: {name?, path?, pid?, parent_name?, parent_pid?, command_line?}`, `wazuh_rule: {id, level, description, groups[]}?`, `mitre: {tactic?, technique?, technique_id?}`, `event_type` (`UNKNOWN`), `severity` (`LOW`), `source_ip?`, `destination_ip?`, `destination_port?`, `raw_event: object`.

## Agent API payloads

- `POST /api/v1/agents/heartbeat`: agent identity/version, host/OS/network, `connection_state`, `sync_state`, `queue_depth`, timestamp, and collector error. Returns acknowledgement, signed configuration, and `pending_commands[]`.
- `POST /api/v1/telemetry/bulk`: normalized telemetry batch.
- `POST /api/v1/sync/offline`: `{agent_id, batch_id, telemetry[]}`; returns `accepted_event_ids[]`. Unacknowledged items remain queued.
- `POST /api/v1/commands/result`: `{command_id, agent_id, status, executed_at?/completed_at?, output?, error?, verification?}`.
- `POST /api/v1/agents/logs`: structured operational log containing log ID, timestamp, agent/host, level, component, message, correlation ID, and metadata.
- Agent authentication: `Authorization: Bearer <per-agent-token>`. Admin writes use the admin bearer token.

## Operator API

- `POST /api/zta/auth/login`: `{username,password}` -> `{access_token,token_type,expires_at,user}`; `POST /api/zta/auth/logout` revokes the presented session.
- `GET /api/zta/session`: authenticated identity, role, and permissions.
- `GET|POST /api/zta/users`: list/create operators; creation requires `{username,password,role}` and `users:manage`.
- Read: `/api/zta/{overview,agents,events,rules,policies,incidents,commands,timeline,audit,services,logs}` plus analytics and schema endpoints.
- Write: rule/policy validate, test, CRUD and toggle; event retry; manual command/action execution.
- Live feed: WebSocket `/api/zta/ws` (alias `/ws`); browser sessions send `Sec-WebSocket-Protocol: zta-token.<access_token>`.
- Active streams recheck session validity and stream permission before delivering updates; revoked, expired or disabled identities lose access.
- Roles: `ADMIN` has all permissions; `SOC_ANALYST` has `read`, `stream`, `response:write`; `AUDITOR` has `read`, `audit:read`, `stream`; `VIEWER` has `read`.
- Missing/invalid operator credentials return 401; authenticated users lacking permission receive 403. `X-User-Role` is never trusted.

## Rule activation contract

- Required strings: `code` (1-64), `name` (1-160); optional description/MITRE strings must be strings and at most 1000 characters.
- Enums: severity `LOW|MEDIUM|HIGH|CRITICAL`; category is one of the dashboard categories plus `DEMO`; response action `MONITOR|ALERT|NOTIFY_SOC|LOGOUT_USER|LOGOFF_USER|KILL_PROCESS|ISOLATE_ENDPOINT`; logic type `CONDITION_TREE`.
- `risk_delta` is an integer from 0 through 100. `enabled` and `allow_offline` are booleans or integer `0|1`.
- Conditions allow at most 8 levels, 128 total nodes, 32 children per AND/OR group, 100 scalar membership values, 128-character field paths, and 512-character regular expressions. Ordered operands must be numeric; contains/regex operands must be strings.
- The same checks run before create, update, and activation. A rejected update performs no write; an invalid disabled legacy rule cannot be enabled.

## Schema migration and compatibility

- Migration `20260914-operator-rbac` adds `operator_users`, `operator_sessions`, and a session-expiry index. It is additive/idempotent; existing security/event data is unchanged and rollback can leave the unused tables in place.
- `ZTA_ADMIN_TOKEN` remains a legacy `ADMIN` operator credential for bootstrap/compatibility. Per-agent bearer authentication and `/api/v1` ingestion payloads are unchanged.
- Previously public operator reads/streams now require authentication; clients must supply a bearer session (or legacy admin token).
- Rule validation adds no schema migration. Existing valid persisted rules remain compatible; stored invalid rules remain readable but must be corrected before activation.

## States

- Agent connection: `RECONNECTING -> ONLINE`; failures -> `OFFLINE`; queued upload -> `SYNCING`; invalid/failed sync -> `DEGRADED`.
- Agent sync field: `SYNCING | IDLE`; manager-visible status includes `ACTIVE | SYNCING | DISCONNECTED | ISOLATED`.
- Command lifecycle: `PENDING/QUEUED -> DISPATCHED -> EXECUTING -> SUCCESS | FAILED`; executor internals may also report `RUNNING | TIMEOUT | REJECTED`, and safe actions may use `PREVIEW` or `NOT_EXECUTED`.
- Execution source: `AGENT_ONLINE | AGENT_OFFLINE`; policy modes: `ALERT_ONLY | ENFORCE`.
