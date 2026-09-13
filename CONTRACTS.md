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

- Read: `/api/zta/{overview,agents,events,rules,policies,incidents,commands,timeline,audit,services,logs}` plus analytics and schema endpoints.
- Write: rule/policy validate, test, CRUD and toggle; event retry; manual command/action execution.
- Live feed: WebSocket `/api/zta/ws` (alias `/ws`).

## States

- Agent connection: `RECONNECTING -> ONLINE`; failures -> `OFFLINE`; queued upload -> `SYNCING`; invalid/failed sync -> `DEGRADED`.
- Agent sync field: `SYNCING | IDLE`; manager-visible status includes `ACTIVE | SYNCING | DISCONNECTED | ISOLATED`.
- Command lifecycle: `PENDING/QUEUED -> DISPATCHED -> EXECUTING -> SUCCESS | FAILED`; executor internals may also report `RUNNING | TIMEOUT | REJECTED`, and safe actions may use `PREVIEW` or `NOT_EXECUTED`.
- Execution source: `AGENT_ONLINE | AGENT_OFFLINE`; policy modes: `ALERT_ONLY | ENFORCE`.
