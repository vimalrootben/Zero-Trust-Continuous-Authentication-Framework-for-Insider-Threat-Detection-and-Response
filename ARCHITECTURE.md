# Architecture

## Components

- `agent/`: endpoint daemon; collects Windows/Sysmon or JSONL telemetry, normalizes events, queues data in SQLite, heartbeats, caches signed policy, and executes allowlisted responses.
- `api/`: manager HTTP/API server, operator authentication/RBAC, agent authentication, ingestion, background processing, and WebSocket publication.
- `engine/`: canonical pipeline: correlation -> rule matching -> risk/trust update -> policy decision -> response command.
- `storage/`: SQLite schema/repository for agents, events, rules, policies, incidents, commands, audit, and retry state.
- `dashboard/`: static operator UI served by the manager; reads `/api/zta/*` and subscribes to `/api/zta/ws`.
- `powershell/`: validated Windows response handlers; `ruleset/` supplies default rules/policies.
- Launchers: `zta_manager.py` starts dashboard/API ports sharing one runtime; `zta_agent.py` starts an endpoint agent.

## Data flow

1. Agent collector -> `ZTAEventAdapter` -> canonical `ZTAEvent` -> durable local queue.
2. Online agent posts heartbeat and telemetry to manager; offline agent evaluates only signed, cached, offline-approved rules/policies.
3. Manager persists input, runs the unified pipeline, updates risk/trust, creates incidents and commands, then broadcasts updates.
4. Heartbeat returns signed configuration and pending commands. Agent validates identity/signature, executes an allowlisted action, journals the result, and reports it.
5. Reconnect sync uploads queued records with explicit acknowledgements; only acknowledged IDs are removed.

## Runtime/security boundaries

- Default bindings: dashboard `127.0.0.1:8000`, agent API `127.0.0.1:8080`, shared SQLite DB.
- Admin mutations require `ZTA_ADMIN_TOKEN`; agent calls require the per-agent secret in `ZTA_AGENT_TOKENS`/`ZTA_AGENT_TOKEN`.
- Operators authenticate with username/password to receive an eight-hour opaque bearer session. Passwords use salted PBKDF2-SHA256; only token hashes are stored.
- Static dashboard assets remain public, but operator API reads, writes, sessions, and WebSocket streams require explicit role permissions.
- Non-loopback agent traffic must use HTTPS. Commands and cached configuration are signed and agent-bound.
- Response execution is allowlisted, parameter-validated, journaled, and verification-based.
