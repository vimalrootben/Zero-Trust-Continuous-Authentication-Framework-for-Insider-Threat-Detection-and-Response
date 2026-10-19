# Task 1 — Zero Trust EDR Architecture Audit

Audit date: 2026-10-14 (America/Los_Angeles)  
Scope: repository and safe local verification only; no production rules/policies, telemetry, alerts, or response actions were changed or generated.

## 1. Executive conclusion

The repository contains a coherent, automatically started manager pipeline and a durable polling agent, but it does **not** implement every component named in the requested architecture as an independent worker. The strongest verified path is authenticated heartbeat/offline-batch ingestion through SQLite staging, background rule/risk/trust/policy evaluation, alert persistence, heartbeat-carried command dispatch, durable result upload, WebSocket notification, and dashboard refresh. This path is extensively represented in tests, but the current machine could not execute the suite because its checked-in `.venv` points to a removed Python 3.14 installation and the only available Python is 3.15 without compatible dependencies.

The largest functional gaps are endpoint collection breadth and fidelity: there is no dedicated UDP collector, network-close handling, full connection snapshot, USB collector, or separate registry/service/file/authentication worker. Those event types are derived from a single Windows Event Log poller and depend on Windows audit/Sysmon configuration. Process inventory is a live heartbeat snapshot, whereas historical process creation/termination events travel through the event pipeline. IP/interface discovery uses hostname resolution plus a UDP route probe and gives synthetic adapter names; it cannot reliably identify the actual adapter or VPN. `LOCK_WORKSTATION` and `QUARANTINE_FILE` are absent. Dashboard time-series range parameters are accepted but ignored.

Status vocabulary in this report is limited to `VERIFIED`, `IMPLEMENTED_NOT_RUNTIME_VERIFIED`, `PARTIAL`, `BROKEN`, `MISSING`, and `REQUIRES_REAL_WINDOWS_TEST`.

## 2. Git and verification baseline

- Current branch: `feat/agent-execution-integration`.
- HEAD: `3365b7a docs: add disposable branch acceptance checklist`.
- Working tree at audit start: modified `api/auth.py` (pre-existing user work adding user enable/disable, password reset, and session revocation methods). It was preserved.
- Merged local branches: `main`, `chore/git-workflow-records`, `feat/permission-access`, `fix/rule-activation-validation`, `fix/regex-evaluation-cost`, `feat/operator-auth-pages`, `feat/policy-priority-selection`, `feat/rule-version-rollback`, and the current branch.
- Unmerged local branches: none reported by `git branch --no-merged`.
- `update.txt`'s four named branches are ancestors of the current branch, but its 142-pass result is historical evidence, not this environment's result.
- Test configuration: `pyproject.toml` explicitly lists 13 pytest modules. No lint/type-check or CI configuration was found.
- `git diff --check`: passed.
- `node --check dashboard/assets/dashboard.js`: passed.
- Python compile attempt: inconclusive. Python 3.15 attempted to create bytecode in inaccessible/stale cache paths and reported filesystem `FileNotFoundError`s, not Python syntax errors.
- Pytest: **not runnable to completion**. `.venv/Scripts/python.exe` references missing `C:\Users\vegeta\...\python.exe`. System Python 3.15 has no pytest. Reusing pure-Python packages from `.venv` reached collection but produced 11 collection errors because the Python 3.14 `regex` binary extension is incompatible with Python 3.15. A fresh venv also failed in `ensurepip` because the available 3.15 pip payload is incomplete.
- Therefore the current confirmed baseline is **not 142 passed**. It is 11 collection errors caused by interpreter/dependency incompatibility; this is an environment restriction, not evidence of 11 code defects.
- No destructive Windows response was executed. No real Windows/Sysmon endpoint or disposable containment VM was available.

## 3. Existing architecture and startup

Manager startup is `python -m zta` → `dashboard.run_dashboard.main()` → one or two `ZTAHTTPServer` instances. `create_zta_server()` creates one shared runtime (database, repository, WebSocket hub, engine, authentication, background worker); the second listener reuses it. Only the owning server starts `BackgroundWorker`. HTTP server threads are started in `run_dashboard.py`; `server_close()` closes the shared worker for its owner.

Agent startup is `python -m agent` / `zta-agent` → `agent.agent_daemon.main()` → `ZTAAgentDaemon(...)` → `run()`. Construction synchronously initializes configuration values, identity, SQLite `OfflineQueue`/`AgentState`, command receiver, empty local rule engine, and either `WindowsEventCollector` or explicitly configured `JsonlCollector`. `run()` starts exactly one `zta-collectors` daemon thread, while its main thread performs heartbeat, command/result processing, queue synchronization, and interval waiting. Shutdown sets `stop_event`, calls collector `close()` if present, and joins the collector with a timeout.

Actual sequence differs from the expected diagram: the manager connection/heartbeat occurs in the main loop after the collector thread starts; heartbeat, reconnect, upload, cache refresh, offline sync, and command listening are not separate workers. This is valid consolidation but makes a stalled main loop affect all communication functions.

## 4. Background components

### Agent

| Module/component | Source / entry and execution | Input → output → next | Error, retry, shutdown | Status |
|---|---|---|---|---|
| Agent daemon | `agent/agent_daemon.py`; `main()` → `ZTAAgentDaemon.run()`; main thread + collector thread | env/CLI → configured daemon | main-loop `try/finally`; stop event and join | IMPLEMENTED_NOT_RUNTIME_VERIFIED |
| Windows Event Log collector | `agent/collectors.py`; `WindowsEventCollector.poll()` from `collection_loop`; synchronous subprocess polling | five Windows channels → normalized raw dict → `collect()` | per-channel aggregation; next tight polling cycle; no `close()` implementation | REQUIRES_REAL_WINDOWS_TEST |
| Process collection | same poller: Sysmon 1/5 and Security 4688; `_poll_process_inventory()` | event history plus CIM snapshot → queue/heartbeat | subprocess timeouts; errors degrade collector | PARTIAL |
| Network collection | Sysmon 3 plus `_poll_listening_ports()` | connection events/new TCP listeners → queue; listener snapshot → heartbeat | checkpoint dedupe; no close-event model | PARTIAL |
| File collection | Sysmon 2/11/15/23 mapping in `WindowsEventCollector` | event log record → canonical event | relies entirely on Sysmon | REQUIRES_REAL_WINDOWS_TEST |
| Authentication collection | Security 4624/4625 mapping | Security log → canonical event | relies on audit policy/access | REQUIRES_REAL_WINDOWS_TEST |
| Registry collection | Sysmon 12/13 mapping | event record → canonical event | no dedicated semantics beyond raw data | PARTIAL |
| Service collection | System 7045 mapping only | install event → canonical event | no service state/inventory worker | PARTIAL |
| USB collector | none | none | none | MISSING |
| Heartbeat / connection / reconnect | `agent_daemon.py`; `send_heartbeat()` in main loop | system telemetry → `/api/v1/agents/heartbeat`; response → cache/commands | request timeout; state OFFLINE then next interval retry | IMPLEMENTED_NOT_RUNTIME_VERIFIED |
| Telemetry/offline queue upload | `collect()`, `sync_offline_queue()` | every event first persisted locally → `/api/v1/sync/offline` batches of 50 | stable IDs, receipts, selective acknowledgement; retained on failure | IMPLEMENTED_NOT_RUNTIME_VERIFIED |
| Operational log push | `emit_log()` / `upload via offline sync` | structured log → logs API or local queue | retry through offline queue; ID-based dedupe | IMPLEMENTED_NOT_RUNTIME_VERIFIED |
| Rule/policy cache | heartbeat `configuration` → `configure()` | signed definitions → local SQLite/local engines | HMAC and expiry verification; refreshed each successful heartbeat | IMPLEMENTED_NOT_RUNTIME_VERIFIED |
| Command listener | heartbeat response loop, not a socket listener | signed pending commands → `execute_command()` | validation, durable journal, no replay of unknown outcomes | IMPLEMENTED_NOT_RUNTIME_VERIFIED |
| Response executor | `command_receiver.py`, `ps_executor.py` | allowlisted action/params → PowerShell/WTS → durable report | validation, timeout, post-action markers; journaled shutdown survival | REQUIRES_REAL_WINDOWS_TEST |

There are no distinct collectors/workers for file, registry, service, authentication, USB, telemetry upload, reconnect, cache, or command listening. They are mappings or methods inside the two actual agent loops.

### Manager

| Module/component | Source / entry and execution | Input → output → next | Error, retry, shutdown | Status |
|---|---|---|---|---|
| Telemetry receiver/stager | `api/server.py` + `api/ingestion.py`; HTTP POST | bearer-authenticated batch → `zta_events(PENDING)` | transaction rollback, 500/400 response, receipt idempotency | IMPLEMENTED_NOT_RUNTIME_VERIFIED |
| Event/rule/risk/alert/policy processor | `api/background.py` → `engine/pipeline.py`; one daemon thread | pending event → evaluations/risk/trust/match/incident/policy/command | per-event FAILED state; explicit retry API; 1 s wake | IMPLEMENTED_NOT_RUNTIME_VERIFIED |
| Command dispatcher | heartbeat route in `api/server.py` | queued DB commands → signed heartbeat response | expiry monitor; remains durable | IMPLEMENTED_NOT_RUNTIME_VERIFIED |
| Response result handler | `api/ingestion.command_result()` | authenticated result → command/incident/policy/audit | identity/state/verification checks; conflicting terminal result rejected | IMPLEMENTED_NOT_RUNTIME_VERIFIED |
| Heartbeat monitor | heartbeat route + `BackgroundWorker.tick()` | heartbeat/state → agents; stale age → offline | 120 s computed status; periodic persistence/broadcast | IMPLEMENTED_NOT_RUNTIME_VERIFIED |
| Offline sync processor | `api/ingestion.ingest/import_offline` | signed cached evidence → DB | atomic batch receipts and replay checks | IMPLEMENTED_NOT_RUNTIME_VERIFIED |
| WebSocket broadcaster | `api/server.py:WebSocketHub` | committed domain events → authorized WS/SSE clients | dead-client removal; auth recheck is covered by source/tests | IMPLEMENTED_NOT_RUNTIME_VERIFIED |
| Analytics | GET handlers in `api/server.py` | SQLite/repository → JSON | synchronous query per request | PARTIAL |
| Audit logger | `ZTARepository.save_audit()` called inline | domain transitions → `audit_log` | same SQLite transactions where used | IMPLEMENTED_NOT_RUNTIME_VERIFIED |

## 5. Process flow

Historical flow: Windows Sysmon event 1/5 or Security 4688 → `WindowsEventCollector.poll()` → `ZTAEventAdapter` → durable `offline_events` → authenticated offline-sync API → `zta_events` → background pipeline → rule evaluation/risk/trust → `rule_matches`/`incidents`/policy → dashboard REST + WebSocket.

Current-process flow is separate: `Get-CimInstance Win32_Process` → `process_inventory` heartbeat field → `agent_processes` table replacement → `/api/zta/processes` → dashboard table. It is not historical telemetry and does not itself run rules.

PID, PPID, name, path, owner/domain, creation time are present in inventory. Canonical process events preserve PID, PPID, name, path, username/domain, command line, and creation timestamp where the source record provides them. Termination is typed (`PROCESS_TERMINATION`) but there is no lifecycle reconciler joining creation to termination. Network/process correlation is field-based through PID/raw data and generic correlation rules; there is no explicit durable process-to-connection foreign key. Status: **PARTIAL**, real Windows verification required.

## 6. Network flow

Sysmon event 3 provides historical outbound connection events through the canonical event path. A separate PowerShell query emits only newly observed TCP listeners and sends a current listener snapshot in heartbeats. It captures local address/port, PID, process name, state, protocol, and timestamp for listeners. Canonical `ZTAEvent` preserves source IP, destination IP, destination port, and process, but lacks first-class local port, protocol, and connection-state fields (they remain only in raw data).

Missing: UDP endpoints, general TCP connection snapshots, explicit connection-close events, remote endpoint data for listener snapshots, and a stable connection identity independent of first-seen timestamp. Existing listeners are checkpoint-deduplicated; disappearance updates the snapshot but emits no close event. Manager receipt is implemented through offline sync and heartbeat inventory. Status: **PARTIAL**.

## 7. Agent IP

`network_identity.py` uses `socket.getaddrinfo(hostname)` and a UDP connect probe toward the manager host (or `1.1.1.1`) to discover the routed IPv4. IPv6 is the first non-loopback hostname-resolved address. Adapter names are synthetic (`Primary Adapter`, `IPv6 Adapter`), not OS interface identities; interface status is always `UP`. Multiple addresses are listed, but VPN preference, metrics, scopes, and route/interface index are not captured. Heartbeats refresh local fields after reconnect. The manager separately writes the socket peer as `manager_observed_ip`, honoring `X-Forwarded-For` only from configured trusted proxies. Both values persist and are exposed to the dashboard; they must not be conflated. Status: local IP **PARTIAL**; observed IP **IMPLEMENTED_NOT_RUNTIME_VERIFIED**.

## 8. Agent–manager communication map

| Sender → receiver | Protocol/channel | Authentication/schema | Persistence/retry/status |
|---|---|---|---|
| Agent → manager heartbeat | HTTP(S) POST `/api/v1/agents/heartbeat` | per-agent bearer; telemetry dict | agents/inventories; next interval retry; pending signed commands returned |
| Agent → manager telemetry | HTTP(S) POST `/api/v1/sync/offline` (bulk endpoint also exists) | bearer; `{agent_id,batch_id,telemetry[]}` | events/logs/receipts; selective ack and durable retry |
| Agent → manager logs | POST `/api/v1/agents/logs` or offline batch | bearer; structured log | `agent_logs`; queue on failure |
| Manager → agent command | heartbeat response | HMAC signed, bound to agent/action/expiry | command status DISPATCHED; redispatched safely via journal semantics |
| Agent → manager response | POST `/api/v1/commands/result` | bearer; command/agent/status/evidence | command, incident, policy, audit; journal retries until 200 |
| Dashboard ↔ manager | HTTP JSON + WebSocket `/api/zta/ws` | operator bearer/session with RBAC | read/write DB plus live refresh |

Remote cleartext agent communication is refused; localhost HTTP is allowed. TLS termination/client certificates are deployment concerns and were not verified.

## 9. Offline/reconnect

States ONLINE, OFFLINE, RECONNECTING, SYNCING, and DEGRADED are used. Collectors continue in their own thread while offline. Events and logs persist in local SQLite with stable IDs and original normalized timestamps. Reconnect is periodic heartbeat work, not a separate worker. Sync batches are content-addressed and manager receipts prevent duplicate application; only explicitly accepted IDs are deleted. Offline evidence retains local evaluation timestamps and the manager does not retrospectively create destructive actions. Queue capacity is bounded at 10,000 with priority behavior. Runtime status: **IMPLEMENTED_NOT_RUNTIME_VERIFIED**; native interruption, TLS, and long-disconnect tests remain required.

## 10. Rule → risk → alert → policy

`BackgroundWorker` automatically reads `PENDING` events and calls `engine.pipeline.process`; no dashboard button is required. Active DB rules are evaluated with `ConditionEvaluator` (AND/OR/NOT), including bounded regex inputs/timeouts and propagated evaluation errors. Matches update risk and trust, create an incident, evaluate ordered policies, and conditionally queue responses for ENFORCE mode. ALERT_ONLY and MONITOR do not dispatch destructive actions. Rule activation is validated by repository/API code. This is **IMPLEMENTED_NOT_RUNTIME_VERIFIED** here; historical documentation reports targeted regression coverage but is not substituted for a current run.

## 11. Response engine

Implemented aliases/actions include `LOGOUT_USER`/`LOGOFF_USER`, `KILL_PROCESS`, `ISOLATE_ENDPOINT`/`DISABLE_NETWORK`, `UNISOLATE_ENDPOINT`, and local-account lock/unlock. Network isolation is intentionally disabled unless `ZTA_ENABLE_NETWORK_ISOLATION=true`. Exact process identity and session verification are required. `LOCK_WORKSTATION` is **MISSING**. `QUARANTINE_FILE` is **MISSING**. The requested names `NETWORK_ISOLATE`/`NETWORK_UNISOLATE` are not accepted aliases; equivalent endpoint actions use different identifiers. Real execution is **REQUIRES_REAL_WINDOWS_TEST**.

## 12. Log push

Agent logs contain timestamp, agent ID, hostname, level, component, event type, message, correlation ID, and metadata. They queue offline and are inserted with `INSERT OR IGNORE` by log ID. `/api/zta/logs` reads them and the dashboard fetches that endpoint. No explicit sensitive-data redaction function was found before persistence/upload; callers control message/metadata. Status: end-to-end **IMPLEMENTED_NOT_RUNTIME_VERIFIED**; sensitive-data filtering **MISSING**.

## 13. WebSocket

Pipeline, heartbeat, offline sync, command, response, rule, risk, policy, and alert transitions broadcast through the shared hub after transaction commit. The dashboard opens `/api/zta/ws` and triggers refreshes. Source and tests indicate access is rechecked for logout, expiry, and disabled accounts, and dead connections are removed. Current runtime was not started, so status is **IMPLEMENTED_NOT_RUNTIME_VERIFIED**.

## 14. Dashboard analytics and chart sources

| UI metric/chart | Endpoint → DB/query | Range/timezone/empty state | Status |
|---|---|---|---|
| Total/online/offline endpoints | `/api/zta/overview`; `agents`, heartbeat-age derivation | current snapshot; UTC stored, browser-local display | IMPLEMENTED_NOT_RUNTIME_VERIFIED |
| Critical/open alerts | overview; counts from `incidents` | all time/current status | IMPLEMENTED_NOT_RUNTIME_VERIFIED |
| Fleet risk | overview; latest `risk_history` per active agent | current; empty = 0 | IMPLEMENTED_NOT_RUNTIME_VERIFIED |
| Rule matches/policy triggers | overview; counts from `rule_matches`/`policy_evaluations` | all time | IMPLEMENTED_NOT_RUNTIME_VERIFIED |
| Process activity | `/api/zta/processes`; `agent_processes` | live heartbeat snapshot; explicit empty row | IMPLEMENTED_NOT_RUNTIME_VERIFIED |
| Network/listeners | `/api/zta/listening-ports`; `agent_listening_ports` | live TCP-listener snapshot; explicit empty row | PARTIAL |
| Alert evolution/tactics charts | dashboard fetches up to 10,000 events/incidents and groups client-side | browser local rendering; explicit empty cards | PARTIAL |
| Events time series API | `/api/zta/analytics/events-timeseries`; last 100 `zta_events` | accepts `range` but does not filter or bucket by it | BROKEN |
| MITRE coverage API | rules table definitions, not observed matches | all rules; “Unknown” bucket | PARTIAL |

No `Math.random`, `mockData`, `fakeData`, or `sampleData` production use was found in dashboard assets. Form defaults and empty-state fallbacks are not telemetry fabrication. A seeded demo ruleset exists and is explicitly marked; it was not changed.

## 15. Security and performance findings

- Good controls: per-agent bearer authentication, signed commands/configuration, remote HTTPS requirement, trusted-proxy gating, bounded ingest size, durable idempotency, allowlisted PowerShell, exact targets, terminal verification, and WebSocket authorization rechecks.
- Sensitive log metadata has no centralized redaction.
- `WindowsEventCollector.collection_loop` has no explicit sleep; it immediately repeats after five `wevtutil` calls and two PowerShell inventory calls. Subprocess duration may throttle it, but idle/high-speed failures can cause costly polling/log churn.
- One agent main loop serializes heartbeat, cache rebuild, command execution, result upload, and sync. A slow response action can delay heartbeats and synchronization.
- SQLite uses thread-local connections/transactions, but the agent cache and offline queue share one file across repository and queue schemas; concurrency needs stress testing.
- Manager processing is one worker with batches of 50. This avoids duplicates but is a throughput bottleneck; failed events remain visible and do not block later rows.
- WebSocket hub prunes failed clients and is shared across listeners; runtime leak/load testing remains outstanding.
- Analytics performs repeated synchronous SQLite queries per refresh; events/charts load up to 10,000 rows and update on live events, creating scale risk.
- Agent queue is bounded; WebSocket client queues/hub buffering require load verification from implementation details.

## 16. Complete connection matrix

| Component | Source | Started? | Input → output / next | Error handling / tests | Status |
|---|---|---|---|---|---|
| Agent daemon | `agent/agent_daemon.py` | CLI/service entry | config → all agent loops | finally cleanup; agent tests exist | IMPLEMENTED_NOT_RUNTIME_VERIFIED |
| Event collector | `agent/collectors.py` | collector thread | Windows logs → adapter | aggregate errors/checkpoints | REQUIRES_REAL_WINDOWS_TEST |
| Process inventory/events | collectors + adapter | yes within collector | CIM/Sysmon → heartbeat/event DB | subprocess timeout | PARTIAL |
| Network/listeners | collectors + adapter | yes within collector | Sysmon/TCP listeners → DB | dedupe checkpoints | PARTIAL |
| File/auth/registry/service | collector mappings | yes if source enabled | event channels → event DB | prerequisite-dependent | REQUIRES_REAL_WINDOWS_TEST |
| USB | none | no | none | none | MISSING |
| IP identity | `agent/network_identity.py` | heartbeat call | sockets → heartbeat | fallbacks suppress errors | PARTIAL |
| Offline queue | `agent/storage/offline_queue.py` | constructor | events/logs → SQLite | bounded/durable | IMPLEMENTED_NOT_RUNTIME_VERIFIED |
| Heartbeat/reconnect | daemon main loop | yes | telemetry ↔ manager | timeout/retry states | IMPLEMENTED_NOT_RUNTIME_VERIFIED |
| Cache worker | daemon heartbeat method | yes, consolidated | signed config → local DB | signature/expiry | IMPLEMENTED_NOT_RUNTIME_VERIFIED |
| Command listener | daemon heartbeat method | yes, consolidated | commands → receiver | validation/journal | IMPLEMENTED_NOT_RUNTIME_VERIFIED |
| PowerShell executor | `powershell/ps_executor.py` | on command | allowlist → result | timeout/verification | REQUIRES_REAL_WINDOWS_TEST |
| Telemetry receiver | `api/server.py`, `api/ingestion.py` | HTTP servers | batch → staged DB | transactions/receipts | IMPLEMENTED_NOT_RUNTIME_VERIFIED |
| Background processor | `api/background.py` | one owning server | pending rows → pipeline | FAILED state/retry | IMPLEMENTED_NOT_RUNTIME_VERIFIED |
| Rule engine | `conditions.py`, `pipeline.py` | via processor | event → evaluations/matches | bounded evaluation | IMPLEMENTED_NOT_RUNTIME_VERIFIED |
| Risk/trust engines | `engine/risk`, `engine/trust` | via pipeline/tick | match/history → score | decay guarded by incidents | IMPLEMENTED_NOT_RUNTIME_VERIFIED |
| Alert engine | `pipeline.py` | via pipeline | match → incident | transactional | IMPLEMENTED_NOT_RUNTIME_VERIFIED |
| Policy engine | `engine/policy/engine.py` | via pipeline | context → decision | validation/evidence | IMPLEMENTED_NOT_RUNTIME_VERIFIED |
| Dispatcher | heartbeat route | request-driven | queued → signed command | expiry/durable state | IMPLEMENTED_NOT_RUNTIME_VERIFIED |
| Result handler | `api/ingestion.py` | request-driven | report → state/audit | conflict/verification checks | IMPLEMENTED_NOT_RUNTIME_VERIFIED |
| Heartbeat monitor | server + background tick | request + periodic | timestamps → status | stale cutoff | IMPLEMENTED_NOT_RUNTIME_VERIFIED |
| Offline sync | ingestion | request-driven | evidence → DB | authenticated/idempotent | IMPLEMENTED_NOT_RUNTIME_VERIFIED |
| Audit/log storage | `storage/database.py` | inline | records → SQLite/API | transaction/ID dedupe | IMPLEMENTED_NOT_RUNTIME_VERIFIED |
| WebSocket hub | `api/server.py` | shared runtime | domain events → UI | auth/dead-client cleanup | IMPLEMENTED_NOT_RUNTIME_VERIFIED |
| Analytics/dashboard | server + `dashboard.js` | HTTP/UI | DB JSON → cards/charts | empty states | PARTIAL |

## 17. Prioritized issues

### ZTA-001 — P1 — Network collector

- File/root cause: `agent/collectors.py`; only Sysmon connection-start events and TCP listeners are collected.
- Evidence: `_poll_listening_ports()` uses `Get-NetTCPConnection -State Listen`; no UDP query or close transition exists.
- Fix: add bounded TCP/UDP snapshot reconciliation with stable identities, opened/closed transitions, local/remote endpoints, state, PID, process metadata, and durable checkpoints.
- Dependencies/tests: Task 2; unit snapshot-diff tests and disposable Windows/Sysmon tests.

### ZTA-002 — P1 — Response coverage

- Files/root cause: `agent/commands/command_receiver.py`, `powershell/ps_executor.py`; action allowlist lacks `LOCK_WORKSTATION` and `QUARANTINE_FILE`, and requested network names differ.
- Fix: do not add until Task 5; define contracts, authorization, rollback/verification, and aliases.
- Tests: dry-run validation plus disposable Windows tests.

### ZTA-003 — P1 — USB collection

- File/root cause: no module or event mapping.
- Fix: Task 2 should explicitly decide whether USB is in scope, then implement Windows device/event-channel collection and schema mapping.
- Tests: fixture parsing and real device attach/remove validation.

### ZTA-004 — P2 — Collector polling pressure

- File/root cause: `agent/agent_daemon.py:collection_loop`; no wait/backoff between complete polls or failures.
- Fix: configurable stop-aware interval and exponential error backoff, with duration/health metrics.
- Tests: call-frequency, shutdown latency, and failure-backoff tests.

### ZTA-005 — P2 — Communication serialization

- File/root cause: agent main loop performs heartbeat, commands, result upload, and sync serially; response execution can block heartbeat.
- Fix: Task 3/5 split bounded communication scheduling from execution while retaining journal exactly-once semantics.
- Tests: slow-command heartbeat continuity and shutdown tests.

### ZTA-006 — P2 — IP/interface fidelity

- File/root cause: `agent/network_identity.py`; hostname resolution and synthetic labels cannot bind route-selected address to a real adapter/VPN.
- Fix: Task 3/7 use Windows adapter/route APIs and persist interface index/name/metric; continue showing manager-observed IP separately.
- Tests: multi-NIC/VPN/IPv6 and reconnect address-change tests.

### ZTA-007 — P2 — Central log redaction

- Files/root cause: `emit_log()` and `save_agent_log()` persist arbitrary message/metadata.
- Fix: Task 6 add a contract-level sanitizer and size bounds before local persistence and manager ingestion.
- Tests: tokens, passwords, authorization headers, nested metadata, oversize input.

### ZTA-008 — P3 — Analytics range is ignored

- File/root cause: `api/server.py` events-timeseries reads the latest 100 rows regardless of `range` and returns unbucketed count=1 points.
- Fix: Task 7 validate range, filter in UTC SQL, bucket consistently, and disclose timezone.
- Tests: boundary timestamps, DST/browser display, empty and large datasets.

### ZTA-009 — P3 — Network/process semantics in UI

- Root cause: dashboard mixes current inventory with historical event charts without an explicit lifecycle/correlation model.
- Fix: Task 7 label snapshot versus historical data and use the corrected Task 2 schema.
- Tests: stopped process, closed connection, empty/offline agent.

### ZTA-010 — P4 — Documentation drift

- Files: README/docs/update; historical Wazuh/native descriptions and prior pass counts can be mistaken for current evidence.
- Fix: after Tasks 2–9, update only verified deployment claims and current test commands.

### ZTA-011 — P4 — Broken developer test environment

- Root cause: repository-local `.venv` embeds a removed Python 3.14 path; host Python 3.15 lacks a functional pip/compatible regex wheel.
- Fix: recreate with a supported Python 3.11–3.14 interpreter outside tracked artifacts and document reproducible bootstrap.
- Tests: full suite, compilation, JS syntax, diff check.

No P0 issue was proven by this static/runtime-limited audit. That is not a claim that production security is fully validated.

## 18. Implementation plan and dependencies

1. **Task 2 — collectors and worker reliability (next):** add stop-aware scheduling/backoff; implement complete process/network snapshot/event semantics, including UDP and close/termination reconciliation; decide and implement USB scope; normalize all required fields; preserve the existing event/queue contracts. Do not change rules/policies or dashboard design. Add fixture-based tests first, then a Windows validation checklist.
2. **Task 3 — communication/IP/offline:** separate heartbeat/reconnect/sync scheduling from potentially slow execution; implement exact Windows route/interface identity; test selective acknowledgements, reconnect address changes, and long outages.
3. **Task 4 — detection chain:** only after collector schemas stabilize, extend rule/policy field contracts as necessary and regression-test automatic processing, regex limits, modes, and idempotency.
4. **Task 5 — response:** complete action contract/aliases and implement only safely verifiable actions; preserve fail-closed journal behavior; real Windows validation is mandatory.
5. **Task 6 — logs/audit/WebSocket:** centralized redaction/limits, lifecycle event coverage, and load/leak/revocation tests.
6. **Task 7 — dashboard/IP/analytics:** connect corrected snapshot/history schemas; implement real UTC range filtering/bucketing and clear local-vs-observed IP labels without redesign.
7. **Task 8 — controlled triggers/integration tests:** use isolated fixtures/disposable endpoint; never seed production data.
8. **Task 9 — regression/security/Windows validation:** clean supported Python environment, full pytest/compile/JS/diff checks, TLS network, service restart, multi-NIC/VPN, Sysmon/audit, and disruptive actions only in a disposable VM.

## 19. Exact recommended Task 2 scope

Task 2 should be limited to `agent/collectors.py`, agent collector scheduling/lifecycle in `agent/agent_daemon.py`, event normalization/model fields required by real process/network telemetry, checkpoint storage, and focused tests/documentation. It should:

1. Add a configurable, stop-aware poll interval and capped exponential failure backoff.
2. Preserve Sysmon/Security creation and termination events while adding deterministic lifecycle tests.
3. Replace listener-only network observation with bounded TCP and UDP snapshots; emit opened/closed/listening transitions with local IP/port, remote IP/port, PID, process, protocol, state, and original observation time.
4. Prevent duplicate unchanged snapshot events using stable connection identities and persisted checkpoints.
5. Clearly separate current process/network inventory from historical event records.
6. Add USB attach/remove collection only if the product contract confirms it is required; otherwise document it as intentionally unsupported rather than implying coverage.
7. Keep every event durably queued before checkpoint advancement and preserve original timestamps during sync.
8. Add unit/fixture tests for parsing, dedupe, close/termination, error backoff, clean shutdown, and queue handoff; mark native provider behavior pending until a disposable Windows endpoint is available.

Task 2 must not modify production detection rules/policies, add demo alerts, redesign dashboard pages, or execute containment actions.

## 20. Real Windows validation still required

- Scheduled Task/SYSTEM startup and shutdown; channel permissions and missing-channel behavior.
- Sysmon process create/terminate, network connect, registry, file, and configured Security audit events.
- TCP/UDP/listener open/close and PID/process association under churn.
- Multi-adapter, VPN, IPv4/IPv6, proxy/NAT, DHCP/address change, and manager-observed IP.
- Offline collection across reboot/power interruption, queue capacity, reconnect, selective acknowledgement, and no duplicates.
- WTS logout ownership/disappearance, exact process termination, account actions, and opt-in isolation/unisolation from a VM console.
- TLS termination/certificate policy, command expiry/replay, WebSocket revocation, sustained load, SQLite contention, and resource/leak behavior.

## 21. Audit boundaries

This report verifies repository structure, code wiring, Git state, JavaScript syntax, and diff cleanliness. It does not claim that source existence proves runtime execution. Current Python environment failures are recorded separately from product defects. No Tasks 2–9 implementation was performed.
