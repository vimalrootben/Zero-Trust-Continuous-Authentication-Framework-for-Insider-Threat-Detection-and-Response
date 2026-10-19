# Task 2 — Windows Agent Background Worker Implementation Report

Date: 2026-10-14  
Scope: Task 2 only. Existing agent, manager transport, queue, rules, policies, response controls, and dashboard design were preserved.

## A. Baseline

- Branch: `feat/agent-execution-integration`
- Starting commit: `3365b7a docs: add disposable branch acceptance checklist`
- Pre-existing working-tree change preserved: `api/auth.py`
- Task 1 report preserved: `TASK_1_AUDIT_REPORT.md`
- Previously reported baseline: 142 passed (historical `update.txt` result).
- Actual initial attempt: the repository `.venv` referenced a removed Python 3.14 installation. System Python 3.15 initially lacked pytest and a compatible `regex` extension, producing 11 collection errors. This was an environment failure, so no starting pass count could be truthfully established.
- Environment repaired for verification with the declared `requirements.txt` dependencies under Python 3.15.
- Final full suite: **180 passed, 0 failed, 0 skipped in 152.75 seconds**.
- Final focused agent/worker/queue/ingestion suite: **49 passed, 0 failed, 0 skipped in 80.35 seconds**.
- Windows path-length restrictions required a short external pytest base-temporary directory. Runs under the long repository path otherwise produced temporary-directory/SQLite open failures.

## B. Worker status

All workers are registered in `ZTAAgentDaemon.__init__`, start automatically from `run_loop()`, and run independently under `BackgroundWorkerSupervisor`. `start()` is idempotent. Each worker uses a stop-aware configurable interval and capped exponential error backoff. Worker state is exposed in heartbeat metadata without per-loop database writes.

State contract: `STARTING`, `RUNNING`, `DEGRADED`, `RESTARTING`, `STOPPED`, `FAILED`.

Metadata: `worker_name`, `started_at`, `last_success_at`, `last_error_at`, `last_error`, `restart_count`, `current_state`.

| Worker | Source/startup | Running/error/restart | Shutdown | Test result |
|---|---|---|---|---|
| Event collector | `agent/agent_daemon.py` registers `WindowsEventCollector.poll_events()` | independent daemon thread; per-channel errors aggregated; capped backoff | shared stop event and joined thread | unit wiring/regression passed; REQUIRES REAL WINDOWS TEST |
| Process collector | registers `poll_processes()` | independent snapshot loop; inaccessible/missing fields remain null; failure does not stop other workers | stop-aware wait/join | snapshot, start/exit, PID reuse and duplicate tests passed |
| Network collector | registers `poll_network()` | independent TCP/UDP snapshot loop; process owner may remain unknown; capped backoff | stop-aware wait/join | TCP/UDP/listener lifecycle and dedupe tests passed |
| JSONL collector | alternative `telemetry-collector` when configured | preserves partial-line/checkpoint behavior | stop-aware wait/join | existing regression passed |
| Connection/heartbeat worker | registers `connection_cycle()` | heartbeat, sync and durable result upload; isolated from collectors | stop-aware wait/join | agent and ingestion regressions passed |

The supervisor records real transitions only. `WORKER_STARTING`, `WORKER_STARTED`, `WORKER_FAILED`, `WORKER_RESTARTING`, and `WORKER_STOPPED` are sent through existing structured logging. Repeated successful loops do not generate repeated state logs.

## C. Process collector

- Source: `agent/collectors.py`, `WindowsEventCollector.poll_processes()` / `_poll_process_inventory()`.
- Method: real Windows `Get-CimInstance Win32_Process`, with owner lookup, executed by non-interactive PowerShell.
- Captured fields: PID, PPID, name, executable path, command line, username, domain, session ID, creation timestamp, observation timestamp, and current status where available.
- Lifecycle: first poll establishes a durable baseline. Later snapshot differences emit `PROCESS_STARTED` and `PROCESS_EXITED`; unchanged processes emit nothing.
- PID reuse protection: snapshot identity is `PID + creation timestamp`. A reused PID with a different creation time produces one exit and one start.
- Event schema: existing canonical input is retained (`id`, UTC `timestamp`, `event_type`, `collector_type`, `process`, `user`, and raw `data`). No parallel schema was introduced.
- Queue: `ZTAAgentDaemon.collect()` normalizes through `ZTAEventAdapter`, then persists to `OfflineQueue` before upload. Original timestamps are retained.
- Failure behavior: PowerShell/CIM can return null owner/path/command values. They remain null; values are never fabricated. A full provider failure degrades only the process worker and triggers bounded restart backoff.
- Limitation: polling cannot guarantee capture of every short-lived process. Existing Sysmon/Security event collection remains the preferred event source when configured.
- Evidence: focused tests verify baseline behavior, a single start, a single exit, unchanged-snapshot deduplication, and PID reuse. Existing durable collection tests also pass.

## D. Network collector

- Source: `agent/collectors.py`, `poll_network()` / `_poll_network_connections()`.
- Method: real Windows `Get-NetTCPConnection` and `Get-NetUDPEndpoint`, plus one `Win32_Process` lookup map per network scan.
- TCP: local/remote address and port, state, owning PID, process name/path/user/domain/creation time.
- UDP: local address/port, `BOUND` state, owning PID, correlated process where available. UDP has no fabricated remote endpoint.
- Listeners: TCP `Listen` and UDP bound endpoints populate the current heartbeat snapshot with first seen, last seen, process, PID, protocol, address, port, and state.
- Stable identity: protocol, local address/port, remote address/port, PID, and process creation time.
- Lifecycle events: `CONNECTION_OPENED`, `CONNECTION_CLOSED`, `LISTENER_STARTED`, and `LISTENER_STOPPED`.
- Deduplication: initial poll establishes a checkpoint; unchanged sockets do not emit repeated opens. Snapshot disappearance emits one close/stop and the saved checkpoint is replaced.
- Correlation: process identity comes only from the OS lookup. Missing owner, process exit races, and permission failures produce null process fields rather than invented names.
- Compatibility: legacy `_poll_listening_ports()` remains for existing callers/tests; the daemon uses the complete network snapshot path.
- Evidence: tests verify TCP metadata, UDP tracking, listener start/stop, close events, correlation, and no duplicate opens.
- Native status: **REQUIRES REAL WINDOWS TEST** for provider permissions, socket churn, PID reuse races, and exact OS state comparison.

## E. Agent IP

- Source: `agent/network_identity.py`.
- Windows enumeration now uses `Get-NetIPConfiguration`, retaining real interface alias, index, description, IP family, address, state, and metric when available.
- Primary IPv4 is chosen from the OS route used toward the configured manager host, then matched to the enumerated interface. Hostname resolution remains a fallback.
- IPv6 and other active addresses remain separately reported.
- Loopback is selected only when no non-loopback route/address is available.
- VPN, Wi-Fi, Ethernet, virtual adapters, and multiple NICs are represented by their actual Windows interface aliases rather than synthetic names when the provider succeeds.
- Relevant primary IP/interface changes are detected between heartbeats and included as `network_change` metadata.
- Manager-observed IP remains the separate server-side `manager_observed_ip`; it was not conflated with local IP.
- Native route/interface correctness remains **REQUIRES REAL WINDOWS TEST**.

## F. Telemetry and manager connection

1. Collector creates a stable lifecycle event ID.
2. `ZTAEventAdapter` normalizes the existing schema.
3. `OfflineQueue.enqueue()` durably stores it in SQLite.
4. The authenticated connection worker submits bounded batches of 50 to `/api/v1/sync/offline`.
5. Manager validates the per-agent bearer token, batch size/schema, stable identity, and agent ownership.
6. `api/ingestion.py` writes events/logs transactionally and records a content-bound sync receipt.
7. The manager returns explicit accepted IDs.
8. The agent deletes only explicitly acknowledged events; failed/unacknowledged items remain queued.

Duplicate event IDs and batch receipts prevent replay duplication. Original telemetry timestamps survive normalization and offline sync. Remote cleartext transport remains prohibited; existing authentication/TLS behavior was preserved.

Heartbeat metadata now includes agent identity, host/version/platform, local network identity, isolation state, queue depth, last telemetry time, bounded process/listener inventories, truncation state, and worker-health summary. `ZTA_HEARTBEAT_INVENTORY_LIMIT` defaults to 1,000 records per inventory to prevent unbounded heartbeat payloads.

Manager storage received additive, idempotent agent columns for `worker_health_json`, `last_telemetry_at`, and `inventory_truncated`. Existing heartbeat and dashboard fields remain compatible.

## G. Operational logging

The existing structured log and offline queue are reused. Added transition events include:

- `AGENT_STARTED` / `AGENT_STOPPED`
- `WORKER_STARTING` / `WORKER_STARTED` / `WORKER_FAILED` / `WORKER_RESTARTING` / `WORKER_STOPPED`
- `MANAGER_CONNECTED` / `MANAGER_DISCONNECTED`

Logs contain bounded state metadata and exception type/details, not tokens, authorization headers, or private keys. Successful steady-state loops are not logged repeatedly. During shutdown, logs are queued locally instead of delaying shutdown with network calls.

## H. Files

Created:

- `agent/workers.py`
- `tests/test_task2_agent_workers.py`
- `TASK_2_IMPLEMENTATION_REPORT.md`

Modified for Task 2:

- `agent/agent_daemon.py`
- `agent/collectors.py`
- `agent/network_identity.py`
- `storage/database.py`
- `pyproject.toml`

Removed: none.

Unrelated pre-existing `api/auth.py` changes and `TASK_1_AUDIT_REPORT.md` were not modified as part of Task 2.

## I. Test results

- Full configured suite: **180 passed, 0 failed, 0 skipped**.
- Focused agent/worker/queue/manager-ingestion selection: **49 passed, 0 failed, 0 skipped**.
- New Task 2 tests: **4 passed**.
- Python AST parse: all project Python sources passed.
- JavaScript syntax: passed; dashboard JavaScript was not changed.
- `git diff --check`: passed.

Environment limitations:

- No disposable Windows VM was connected. All native PowerShell/CIM/network provider calls were isolated in unit tests; those results are not represented as live Windows validation.
- The repository-local `.venv` is broken because its original Python executable no longer exists.
- Windows path-length restrictions required a short external pytest temporary path.

## J. Remaining issues

| Issue | Root cause | Severity | Required next task |
|---|---|---|---|
| Native provider validation pending | no disposable Windows VM/Sysmon endpoint | P1 validation | Task 9 / Windows validation |
| Short-lived polling gaps | snapshot polling cannot observe processes/sockets entirely between scans | P2 | Task 2 documented; prefer Sysmon/ETW in future scoped work |
| Command execution can still occupy connection cycle | heartbeat carries commands synchronously | P2 | Task 3/5 |
| Reconnect policy remains interval-based | full jitter/backoff/sync hardening excluded from Task 2 | P2 | Task 3 |
| Central sensitive-log redaction remains absent | Task 2 adds bounded lifecycle logs but does not redesign log pipeline | P2 | Task 6 |
| Full analytics corrections remain outstanding | explicitly outside Task 2 | P3 | Task 7 |

## K. Task 3 readiness

The collector side is ready for Task 3: real event candidates are normalized, durably queued, batch bounded, authenticated, acknowledged selectively, and deduplicated. Worker failures do not halt heartbeat or other collectors.

Task 3 should focus only on communication reliability: separate slow command execution from the connection cadence, add reconnect jitter/backoff and explicit connection health timing, test long outages and partial acknowledgements at scale, and verify TLS/mTLS deployment. It should not revisit process/network snapshot semantics unless real Windows testing uncovers a provider-specific defect.

## L. Definition of done assessment

Worker lifecycle, process/network snapshots, PID reuse protection, TCP/UDP/listener lifecycle, correlation, IP/interface discovery, durable queuing, authenticated ingestion, deduplication, acknowledgements, heartbeat metadata, bounded polling/backoff, clean shutdown, regression coverage, and documentation are implemented and test-verified in isolation/integration.

Actual Windows provider behavior is explicitly **REQUIRES REAL WINDOWS TEST**. No fake telemetry, fake IP, dashboard redesign, rule/policy replacement, authentication bypass, or disruptive response execution was introduced.
