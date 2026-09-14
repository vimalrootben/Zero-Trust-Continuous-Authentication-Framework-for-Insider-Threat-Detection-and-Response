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
- `POST /api/zta/auth/password`: `{current_password,new_password}` changes the named operator's password, preserves the current session, and revokes their other sessions. Passwords are 12-256 characters and must differ.
- `GET /api/zta/session`: authenticated identity, role, and permissions.
- `GET|POST /api/zta/users`: list/create operators; creation requires `{username,password,role}` and `users:manage`.
- Read: `/api/zta/{overview,agents,events,rules,policies,incidents,commands,timeline,audit,services,logs}` plus analytics and schema endpoints.
- Write: rule/policy validate, test, CRUD and toggle; event retry; manual command/action execution. Manual script execution accepts only existing allowlisted IDs and validated parameters, then queues a manager-signed command.
- Live port records are agent-observed heartbeat data with `agent_id`, `port`, `protocol`, `local_address`, `pid`, `process_name`, `state`, and `last_observed`.
- Live process records are agent-observed CIM data with `agent_id`, `pid`, `name`, `path`, `username`, `domain`, `created_at`, `parent_pid`, `status`, and `last_observed`.
- `KILL_PROCESS` requires signed `ProcessId`, `ProcessName`, `ProcessPath`, and `ProcessCreatedAt`; the agent supplies its own current PID as a protected boundary and verifies the target identity again immediately before termination.
- `LOGOUT_USER`/`LOGOUT_SESSION` resolves `UserName`, optional `Domain`, and optional `SessionId` against live WTS sessions. Zero matches and ambiguous username-only matches fail closed; ownership is revalidated before WTS logoff and success requires session disappearance.
- `LOCK_LOCAL_ACCOUNT` and `UNLOCK_LOCAL_ACCOUNT` use `UserName`, local `Domain`, and explicit `LogoutExistingSessions`. Prior enabled state is stored under the protected local ZTA state directory; unlock restores that state and fails without a matching rollback record.
- Database clearing is ADMIN-only and requires a strong, two-minute, actor-bound, single-use confirmation token; operational records are cleared and the operation is re-recorded in audit.
- An unresolved repeated alert preserves `first_seen`, advances `last_seen`, increments `occurrence_count`, remains `ACTIVE / NOT RESOLVED`, and retains each evidence record. Acknowledgement is not resolution.
- Rule history: `GET /api/zta/rules/{id}/versions`; `POST /api/zta/rules/{id}/rollback` with `{version: positive integer}` creates a new current version. Deleting a rule linked by any policy returns HTTP 409.
- Policy `priority` is an integer from 0 through 10000. Lower numbers are evaluated first; ties use case-insensitive `code`, then `policy_id`. Policy modes/actions/severity, risk bounds, boolean flags, strings, and optional conditions are validated on preview and mutation.
- Live feed: WebSocket `/api/zta/ws` (alias `/ws`); browser sessions send `Sec-WebSocket-Protocol: zta-token.<access_token>`.
- Active streams recheck session validity and stream permission before delivering updates; revoked, expired or disabled identities lose access.
- Roles: `ADMIN` has all permissions; `SOC_ANALYST` has `read`, `stream`, `response:write`; `AUDITOR` has `read`, `audit:read`, `stream`; `VIEWER` has `read`.
- Missing/invalid operator credentials return 401; authenticated users lacking permission receive 403. `X-User-Role` is never trusted.

## Rule activation contract

- Required strings: `code` (1-64), `name` (1-160); optional description/MITRE strings must be strings and at most 1000 characters.
- Enums: severity `LOW|MEDIUM|HIGH|CRITICAL`; category is one of the dashboard categories plus `DEMO`; response action `MONITOR|ALERT|NOTIFY_SOC|LOGOUT_USER|LOGOFF_USER|KILL_PROCESS|ISOLATE_ENDPOINT`; logic type `CONDITION_TREE`.
- `risk_delta` is an integer from 0 through 100. `enabled` and `allow_offline` are booleans or integer `0|1`.
- Conditions allow at most 8 levels, 128 total nodes, 32 children per AND/OR group, 100 scalar membership values, 128-character field paths, and 512-character regular expressions. Ordered operands must be numeric; contains/regex operands must be strings.
- Regex evaluation accepts at most 4096 input characters and has a 25 ms match timeout. Safe failures return `result: false` with `evaluation_error: REGEX_INPUT_LIMIT|REGEX_TIMEOUT`; normal supported patterns retain search semantics.
- The same checks run before create, update, and activation. A rejected update performs no write; an invalid disabled legacy rule cannot be enabled.

## Schema migration and compatibility

- Migration `20260914-operator-rbac` adds `operator_users`, `operator_sessions`, and a session-expiry index. It is additive/idempotent; existing security/event data is unchanged and rollback can leave the unused tables in place.
- `ZTA_ADMIN_TOKEN` remains a legacy `ADMIN` operator credential for bootstrap/compatibility. Per-agent bearer authentication and `/api/v1` ingestion payloads are unchanged.
- The dashboard exposes username/password login only; the legacy token is not accepted through the operator UI.
- Previously public operator reads/streams now require authentication; clients must supply a bearer session (or legacy admin token).
- Rule validation adds no schema migration. Existing valid persisted rules remain compatible; stored invalid rules remain readable but must be corrected before activation.
- Regex safety adds the `regex>=2024.11.6` runtime dependency and no schema change. On Windows, avoid excessively long environment paths because extension DLL loading remains OS-path limited.
- Migration `20260914-rule-version-history` additively creates `rule_versions`, adds `rules.current_version`, and adds nullable `rule_version` evidence fields to `rule_matches` and `incidents`. Existing rules receive version-1 snapshots; older evidence remains valid with a null version. Version history has no deleting foreign key, so retained evidence and snapshots survive rule deletion.
- Migration `20260914-policy-priority` additively adds `policies.priority`. Existing rows receive priorities 10, 20, ... in their prior effective order (linked rules first, then minimum risk and code), preserving selection behavior; new ties are resolved deterministically.
- Agent-local startup additively creates/upgrades `command_journal`; existing payload/report rows remain readable and receive empty/default metadata until their next terminal update.

## States

- Agent connection: `RECONNECTING -> ONLINE`; failures -> `OFFLINE`; queued upload -> `SYNCING`; invalid/failed sync -> `DEGRADED`.
- Agent sync field: `SYNCING | IDLE`; manager-visible status includes `ACTIVE | SYNCING | DISCONNECTED | ISOLATED`.
- Command lifecycle: `PENDING/QUEUED -> DISPATCHED -> EXECUTING -> SUCCESS | FAILED`; executor internals may also report `RUNNING | TIMEOUT | REJECTED`, and safe actions may use `PREVIEW` or `NOT_EXECUTED`.
- Execution source: `AGENT_ONLINE | AGENT_OFFLINE`; policy modes: `ALERT_ONLY | ENFORCE`.
- `DEMO_SCRIPT` remains the wire-compatible action name for the existing benign script IDs, but uses the production allowlisted-script executor. No environment-mode gate participates in authorization.
- The script allowlist remains: `DEMO_PROCESS_START`, `DEMO_FILE_CREATE`, `DEMO_FILE_MODIFY`, `DEMO_NETWORK_CONNECTION`, `DEMO_LISTENING_PORT`, `DEMO_AUTH_EVENT`, `DEMO_RULE_TRIGGER`, `DEMO_LOG_PUSH`.
- Signed-command validation order is HMAC signature, exact `agent_id`, timezone-aware `expires_at`, command identity/state, allowlisted action, and typed parameters. Validation failure never reaches an executor.
- Local `command_journal` records `command_id`, correlation ID, action, signed payload, terminal result, verification, timestamp, failure reason, serialized report, and acknowledgement state. `command_id` is the at-most-once key.
- Successful process termination and logoff require `PROCESS_NOT_ACTIVE` and `SESSION_NOT_ACTIVE`. Network isolate/unisolate currently return `UNAVAILABLE` and perform no firewall mutation.
- Offline `KILL_PROCESS`, `LOGOUT_SESSION`, and account containment are disabled until their native online handlers and verification suites pass.
- Offline evidence is ordered by local queue insertion. A manager acknowledgement for an event also acknowledges its embedded execution evidence; unacknowledged records remain locally durable.

Regex evaluation contract: input-limit and timeout errors propagate to parent AND/OR/NOT traces. A condition tree with an evaluation error does not match.
# Network containment state

- Heartbeats may include `network_state` with `enabled`, `isolated`, `firewall_state`, and `manager_connectivity`; the manager persists this as JSON for compatibility and exposes the decoded object in agent reads.
- `NETWORK_ISOLATION` remains unavailable unless `ZTA_ENABLE_NETWORK_ISOLATION=true`. Enabling it is an operator deployment decision made only after VM-console validation.
- Isolation requires `ManagerIP` and an optional validated `ManagerPort`; success requires both firewall-state and manager-reachability verification. Failure performs and verifies rollback.
- Windows-only native actions return verification `UNAVAILABLE` on other operating systems; they never report simulated success.
- The existing `DEMO_AUTH_EVENT` identifier remains allowlisted for compatibility but is unavailable because the project has no native authentication-event generator.
