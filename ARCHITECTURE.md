# Architecture

## Components

- `agent/`: endpoint daemon; collects Windows/Sysmon or JSONL telemetry, normalizes events, queues data in SQLite, heartbeats, caches signed policy, and executes allowlisted responses.
- `api/`: manager HTTP/API server, operator authentication/RBAC, agent authentication, ingestion, background processing, and WebSocket publication.
- `engine/`: canonical pipeline: correlation -> rule matching -> risk/trust update -> policy decision -> response command.
- Rule definitions pass one shared validator at API preview, repository create/update, and disabled-to-enabled activation boundaries.
- Policy definitions pass shared validation and are selected by the stable key `(priority, code, policy_id)`; the lowest priority number wins.
- Regex conditions use a timeout-capable engine with bounded pattern/input sizes; timeout and limit outcomes are recorded in evaluation traces instead of blocking workers.
- `storage/`: SQLite schema/repository for agents, events, versioned rules, policies, incidents, commands, audit, and retry state. Rule changes append immutable snapshots; rollback copies a snapshot into a new current version.
- `dashboard/`: static operator UI served by the manager; a full-page session gate prevents dashboard rendering/data loading until login, then role-aware account management and `/api/zta/ws` are enabled.
- `powershell/`: validated Windows response handlers; `ruleset/` supplies default rules/policies.
- Launchers: `zta_manager.py` starts dashboard/API ports sharing one runtime; `zta_agent.py` starts an endpoint agent.

## Data flow

1. Agent Windows/JSONL collectors (process, file, network connection, and listening port) -> `ZTAEventAdapter` -> canonical `ZTAEvent` -> durable local queue.
2. Online agent posts heartbeat and telemetry to manager; offline agent evaluates only signed, cached, offline-approved rules/policies.
3. Manager persists input, runs the unified pipeline, updates risk/trust, deterministically selects the first eligible policy, creates incidents and commands stamped with the matching rule version, then broadcasts updates.
4. Heartbeat returns signed configuration and pending commands. `AgentCommandReceiver` verifies HMAC signature, agent identity, and expiry before payload validation, then dispatches the existing PowerShell/allowlisted-script executor.
5. Every execution is claimed once in the local command journal, verified, completed durably, and reported. Duplicate command IDs return the original report without replaying the action.
6. Reconnect sync uploads ordered detection/execution evidence with correlation IDs; only explicitly acknowledged event and command records are marked synced.

## Runtime/security boundaries

- Default bindings: dashboard `127.0.0.1:8000`, agent API `127.0.0.1:8080`, shared SQLite DB.
- Admin mutations require `ZTA_ADMIN_TOKEN`; agent calls require the per-agent secret in `ZTA_AGENT_TOKENS`/`ZTA_AGENT_TOKEN`.
- Operators authenticate with username/password to receive an eight-hour opaque bearer session. Passwords use salted PBKDF2-SHA256; only token hashes are stored.
- Operators can change their own password after current-password verification; other active sessions for that user are revoked.
- Static dashboard assets remain public, but operator API reads, writes, sessions, and WebSocket streams require explicit role permissions.
- Non-loopback agent traffic must use HTTPS. Commands and cached configuration are signed and agent-bound.
- Response execution is allowlisted, parameter-validated, journaled, and verification-based. `script_executor.py`, `script_registry.py`, and `validators.py` are the canonical script path; `executor.py` is compatibility imports only.
- Allowlisted scripts have no environment/demo-mode bypass or gate. Authorization belongs to the existing signed command and signed cached-policy paths.
- Offline actions are generated only by enabled cached rules and enabled `ENFORCE` policies that both allow offline operation; the signed cache and its expiry are revalidated before execution.
- Network isolation snapshots firewall profiles and enabled outbound allow rules, disables prior allows, preserves manager/DNS reachability explicitly, verifies containment, behaves idempotently, and restores the snapshot on unisolate or failed isolation.
