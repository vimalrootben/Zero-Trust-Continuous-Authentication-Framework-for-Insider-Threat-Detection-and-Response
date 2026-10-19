# Task 3 — Agent–Manager Communication Implementation Report

Date: 2026-10-14  
Scope: Task 3 only. Existing collectors, detection rules, policies, response allowlists, RBAC, WebSocket authorization, and dashboard design were preserved.

## A. Repository status

- Branch: `feat/agent-execution-integration`
- Starting commit: `3365b7a docs: add disposable branch acceptance checklist`
- The working tree already contained Task 2 implementation files, Task 1/2 reports, and an unrelated user modification to `api/auth.py`. Those were preserved.
- Task 1 finding used: communication was authenticated and durable but heartbeat, reconnect, upload, and command handling were consolidated; manager liveness used a hardcoded threshold and local/observed IPs had to remain separate.
- Task 2 finding used: collectors and durable queue handoff were operational, while heartbeat/upload separation, reconnect jitter/backoff, slow command isolation, and deployment TLS testing remained for Task 3.

## B. Baseline

- Historical `update.txt` baseline: 142 passed.
- Actual Task 3 starting baseline: **180 passed, 0 failed, 0 skipped in 153.98 seconds**.
- Final focused communication/liveness/queue suite: **104 passed, 0 failed, 0 skipped in 85.53 seconds**.
- Final complete suite: **188 passed, 0 failed, 0 skipped in 155.46 seconds**.
- A short external pytest base-temporary directory was necessary because the repository path exceeds practical Windows path limits for some temporary SQLite test paths.

## C. Connection lifecycle

Relevant files:

- `agent/connection.py`
- `agent/agent_daemon.py`
- `agent/workers.py`
- `api/server.py`
- `storage/database.py`

`ConnectionStateMachine` defines `STARTING`, `CONNECTING`, `ONLINE`, `DEGRADED`, `OFFLINE`, `RECONNECTING`, `SYNCING`, `STOPPING`, and `STOPPED`, with explicit allowed transitions and durable transition metadata in Agent SQLite state. A restarted process always begins at `STARTING`; it never restores a stale prior `ONLINE` value as current evidence.

Normal evidence-driven flow:

`STARTING → CONNECTING → ONLINE` or `SYNCING`  
`ONLINE/DEGRADED → OFFLINE → RECONNECTING → SYNCING/ONLINE`  
`any active state → STOPPING → STOPPED`

Authentication remains the provisioned per-agent bearer token. The Manager selects the credential by payload Agent ID and uses constant-time comparison, so credentials cannot authorize a different identity. No unauthenticated fallback was added.

Remote cleartext HTTP remains rejected. HTTPS uses Requests' certificate validation by default. `ZTA_CA_BUNDLE` can select an approved CA bundle. mTLS can be configured using both `ZTA_CLIENT_CERT` and `ZTA_CLIENT_KEY`; specifying only one fails closed. `verify=False` is never used.

The project has no renewable Agent session/token endpoint. A rejected static provisioned credential therefore remains visible as an authentication failure and is retried only through capped worker backoff; Task 3 does not invent an insecure reauthentication mechanism.

## D. Background communication workers

The Task 2 supervisor now runs these communication functions independently:

| Worker | Responsibility | Failure behavior |
|---|---|---|
| `heartbeat-worker` | periodic authenticated heartbeat/configuration retrieval | exception drives exponential backoff and jitter |
| `telemetry-upload-worker` | claim/upload/acknowledge telemetry and upload durable command results | independent bounded retry; does not block heartbeat |
| `command-worker` | execute heartbeat-delivered signed commands | bounded queue; execution does not occupy heartbeat worker |

Intervals, maximum reconnect delay, jitter, upload interval, request timeout, command queue size, and telemetry batch size are configurable. The supervisor uses cancellation-aware waits, prevents duplicate starts, and joins workers during shutdown.

Reconnect delay doubles after consecutive failures, is capped by `ZTA_RECONNECT_MAX_DELAY` (default 300 seconds), and applies bounded jitter using `ZTA_RECONNECT_JITTER` (default 20%). A deterministic test verifies delays `2, 4, 4` for a one-second interval and four-second cap.

## E. Heartbeat

Agent heartbeat is independent of dashboard access, collector activity, and telemetry upload. It includes:

- Agent ID, hostname, version and platform
- `heartbeat_timestamp`/legacy `timestamp`
- route-selected local IP and interface metadata
- reported connection state
- worker health
- last collected telemetry timestamp
- pending and quarantined telemetry counts
- oldest pending age
- isolation state
- bounded current inventories retained for existing dashboard compatibility

Manager route: authenticated `POST /api/v1/agents/heartbeat`.

The Manager records separate values:

- `agent_reported_time`: untrusted Agent clock evidence
- `manager_received_time`/`last_seen`: authoritative server receipt time
- `reported_connection_state`: Agent's progress report
- `connection_state`: Manager-authoritative live state

The Manager does not trust a client-supplied `ONLINE`, `OFFLINE`, or future timestamp for liveness. A valid current heartbeat becomes `SYNCING` when pending telemetry exists, otherwise `ONLINE`. Future Agent timestamps cannot extend liveness.

## F. Manager liveness monitor

`ZTA_HEARTBEAT_DEGRADED_SECONDS` defaults to 45 seconds and `ZTA_HEARTBEAT_OFFLINE_SECONDS` defaults to 120 seconds. Repository status evaluation uses the Manager receipt timestamp only:

- younger than degraded threshold: active (`ONLINE`/`SYNCING`)
- between thresholds: `DEGRADED`
- at/after offline threshold: `OFFLINE`

The existing Manager background worker evaluates persisted heartbeats without dashboard traffic. It conditionally persists only real transitions, writes audit evidence, and broadcasts `agent.degraded` or `agent.offline`. Conditional state comparison prevents duplicate transition events and supports recovery after Manager restart.

An authenticated new heartbeat restores the authoritative state. Multiple listeners share one Manager runtime and worker; SQLite serialization plus conditional transitions avoid duplicate updates in the supported deployment architecture. Multi-process distributed leadership is not claimed.

## G. Offline operation and durable queue

Collectors remain independent of communication workers. Manager outage changes connection evidence but does not stop Windows event, process, network, JSONL, or other existing collection paths.

The existing SQLite `offline_events` table received additive fields:

- `status`
- `attempt_count`
- `last_attempt_at`
- `next_attempt_at`
- `last_error`
- `error_class`

An index supports pending selection by status, retry time, and insertion order. Eligible rows are atomically claimed as `IN_FLIGHT` using `BEGIN IMMEDIATE`. Agent restart recovers orphaned `IN_FLIGHT` rows as `RETRY_PENDING`. Original event IDs, payloads, and timestamps are unchanged.

Error classifications stored with rows are `TRANSIENT`, `AUTHENTICATION`, `VALIDATION`, `STORAGE`, `SECURITY`, or `PERMANENT` where applicable. Validation/security/permanent failures enter observable `PERMANENT_ERROR`. Authentication failures remain retryable initially for credential recovery but enter permanent error after three claimed attempts. Permanent errors remain stored and are reported separately; they are not silently deleted.

The pre-existing queue capacity behavior remains conservative: reaching the configured warning threshold never authorizes silent deletion of unsynchronized security evidence. Disk-full, corruption, and unrecoverable SQLite errors surface as `OfflineQueueError`.

## H. Synchronization and idempotency

Upload flow:

1. atomically claim a configurable batch (1–500; default 50)
2. compute a stable content-based batch ID
3. submit through authenticated `/api/v1/sync/offline`
4. Manager validates Agent ownership and payload
5. Manager transactionally commits events/logs/offline evidence
6. Manager stores a content-bound sync receipt
7. Manager returns explicit accepted event IDs
8. Agent deletes only explicitly accepted IDs and returns unacknowledged IDs to retry

HTTP success alone is insufficient. Missing/malformed acknowledgements are validation failures. HTTP 429/5xx and transport failures remain retryable. A non-retryable 4xx response is quarantined. Partial acknowledgement deletes only the accepted subset.

The controlled lost-acknowledgement test commits an event at the Manager, raises a client-side connection error before the response is observed, retries after reconnect, receives the stored batch receipt, drains the Agent row, and confirms exactly one `zta_events` record. This demonstrates at-least-once delivery with idempotent effects rather than claiming impossible network exactly-once delivery.

Manager uniqueness and existing pipeline identifiers prevent duplicate telemetry, rule evaluations, alerts, policy evaluations, and response commands on replay. Existing offline evidence import continues to preserve occurrence and synchronization timestamps, rule/policy linkage, audits, risk history, and response results.

## I. Offline logs and cache

Structured Agent logs continue to use the same durable queue and sync endpoint. Log IDs deduplicate Manager persistence, and original timestamps, identity, severity, component, correlation ID, and metadata survive reconnect.

Connection/sync lifecycle events are emitted through bounded state-change logging and Python structured operational logging; steady-state success does not create an unbounded per-loop log storm. Credentials, bearer tokens, certificate material, and private keys are never included.

The existing signed offline rule/policy cache was not replaced. HMAC integrity, Agent binding, expiration, versioned definitions, `allow_offline`, ENFORCE mode checks, action allowlists, exact targets, and prohibition of destructive offline execution remain intact.

## J. Command compatibility

Manager commands retain unique IDs, Agent binding, expiry, HMAC signatures, allowlisted actions, and durable status. Heartbeat delivery now puts commands into a bounded command queue when background workers are running. The command worker executes and uploads results independently so slow OS work does not delay subsequent heartbeats.

The durable command journal still prevents duplicate execution. If an Agent restarts after execution begins but before a terminal report is stored, it fails closed with unknown outcome instead of replaying the action. Manager command acknowledgement remains distinct from `EXECUTING`, verified `SUCCESS`, or `FAILED` result states. No destructive action was executed in Task 3 tests.

## K. Dashboard and WebSocket

Dashboard endpoint status comes from `ZTARepository.get_agents()`, which evaluates Manager receipt time and never browser activity. Existing overview/endpoints/detail API consumers remain unchanged.

The Manager broadcasts real `agent.reconnecting`, `agent.syncing`, `agent.online`, `agent.degraded`, and `agent.offline` transitions through the shared WebSocket hub. Duplicate unchanged heartbeat notifications are suppressed. Existing WebSocket authorization revalidation after logout, session expiry, and account disable was preserved and remains covered by the full regression suite.

Manager-observed source IP remains separate from Agent local IP. `X-Forwarded-For` remains trusted only when the direct peer is in `ZTA_TRUSTED_PROXIES`.

## L. Test evidence

Commands used (with short external base temp due Windows path length):

```powershell
python -m pytest -q -p no:cacheprovider --basetemp C:\zta-task3-baseline-20261014
python -m pytest -q -p no:cacheprovider --basetemp C:\zta-task3-focused-final tests\test_task3_communication.py tests\test_agent_daemon.py tests\test_background_completion.py tests\test_real_logic_regressions.py tests\test_task2_agent_workers.py
python -m pytest -q -p no:cacheprovider --basetemp C:\zta-task3-full-final
```

Results:

- Starting full suite: 180 passed
- Focused final suite: 104 passed
- Final full suite: 188 passed
- Failed: 0
- Skipped: 0

Safe scenarios covered:

- valid and invalid Agent authentication
- authoritative Manager receipt timestamps and clock skew
- degraded/offline/recovered endpoint liveness
- collectors and communication worker isolation
- exponential capped backoff
- queue claim/retry/permanent error and restart recovery
- authenticated batch upload and partial acknowledgements
- lost acknowledgement after durable commit
- duplicate event idempotency
- offline log/evidence synchronization
- command journal replay prevention and asynchronous delivery
- CA verification/mTLS request configuration
- WebSocket authorization regressions

No real Windows process action, containment action, user logout, or other disruptive response was executed.

## M. Changed files

Created for Task 3:

- `agent/connection.py`
- `tests/test_task3_communication.py`
- `TASK_3_IMPLEMENTATION_REPORT.md`

Modified for Task 3:

- `agent/agent_daemon.py`
- `agent/workers.py`
- `agent/storage/offline_queue.py`
- `api/server.py`
- `api/background.py`
- `storage/database.py`
- `pyproject.toml`

Removed: none.

Additive migrations:

- Agent queue lifecycle/retry/error columns and pending index
- Manager Agent fields: reported connection state, Agent-reported time, Manager receipt time

## N. Remaining issues

| Severity | Issue/root cause | Dependency |
|---|---|---|
| P1 validation | Actual Windows network loss, service restart, DNS changes, VPN/Wi-Fi/Ethernet transitions were not available | REQUIRES REAL WINDOWS TEST |
| P1 validation | TLS termination, CA rotation, certificate expiry, and mutual-TLS handshake require deployed certificates | REQUIRES DEPLOYMENT TEST |
| P2 | Static Agent bearer credentials have no repository-defined renewal endpoint; Task 3 cannot securely invent one | future credential lifecycle design |
| P2 | Supported Manager topology is one shared runtime; distributed multi-process leadership is not implemented | deployment architecture task if horizontal scaling is required |
| P2 | Queue capacity is a non-loss warning threshold; operational disk monitoring remains deployment responsibility | monitoring/operations |
| P3 | Full analytics/time-range corrections remain out of scope | Task 7 |

## O. Task 4 readiness

The Manager receives authenticated, idempotent, timestamp-preserving telemetry and wakes the existing durable background processor. Offline evidence replay cannot duplicate a previously committed event or cause retrospective destructive execution. This establishes a reliable input boundary for Task 4.

Task 4 can focus on verifying and repairing the existing automatic Rule Engine → Risk/Trust Engine → Alert Engine → Policy Engine chain, including atomic failure/retry behavior and mode selection. It should not replace the connection, queue, receipt, or worker lifecycle implemented here.

## P. Deployment qualification

Automated unit/integration behavior is verified. Actual native endpoint connectivity, Windows service recovery, multi-adapter transitions, real certificate chains, reverse-proxy TLS, mTLS handshakes, and production network interruption remain:

**REQUIRES REAL WINDOWS / DEPLOYMENT TEST**.
