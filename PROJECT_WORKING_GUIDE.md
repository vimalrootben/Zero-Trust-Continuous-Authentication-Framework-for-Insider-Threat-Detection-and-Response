# Zero Trust EDR — Project Working Guide

> Verified against the repository source, tests, CLI help, and local Graphify index on 2026-10-16. “Implemented” means code exists; “tested” means covered by repository tests or an observed local check; “deployment-dependent” requires a suitably privileged Windows endpoint or production infrastructure. No credentials or live database contents are included here.

## 1. Project overview

Zero Trust EDR is a Python-based endpoint detection and response platform. A Windows endpoint agent collects host state and security telemetry, buffers it locally, and submits it to a manager. The manager authenticates agents and operators, stores normalized data in SQLite, evaluates rules and policies, calculates risk, creates alerts/incidents, queues response commands, streams updates, and serves a browser dashboard.

Its objectives are continuous endpoint visibility, explainable detection, risk-aware policy decisions, safe response orchestration, and an auditable SOC workflow. It addresses intermittent connectivity with an offline queue, separates agent tokens from operator sessions, and defaults policy actions to the non-disruptive `ALERT_ONLY` mode.

This repository is a local/reference implementation, not a turnkey enterprise deployment. Production TLS termination, certificate issuance, resilient multi-node storage, central secret management, and validated native Windows rollout remain deployment responsibilities.

## 2. Features and capabilities

The following 24 capability groups are present in source:

| # | Capability | Actual behavior and limits | Status |
|---|---|---|---|
| 1 | Operator authentication | Login, logout, session lookup, password change, salted password hashing, expiring/revocable sessions | Implemented and tested |
| 2 | Role-based access control | `ADMIN`, `SOC_ANALYST`, `AUDITOR`, and `VIEWER` permissions are enforced by backend route guards | Implemented and tested |
| 3 | User administration | Admin-only user listing/creation and account updates through the dashboard/API | Implemented; use a provisioned admin |
| 4 | Endpoint registration/state | Agents are recorded with status, last-seen, risk, host metadata, and details | Implemented |
| 5 | Heartbeats | Agent sends periodic health/identity data; manager updates endpoint state and returns work | Implemented and tested |
| 6 | Telemetry ingestion | Authenticated bulk/offline event submission with normalization and validation | Implemented and tested |
| 7 | Offline reliability | Agent queues telemetry in local SQLite and syncs batches with receipts/checkpoints | Implemented and tested |
| 8 | Windows collection | Processes, sessions, listening ports, network identity, event logs, and supported security channels | Implemented; real collection is Windows/privilege dependent |
| 9 | Rules engine | Nested condition evaluation, schema validation, test endpoint, versions, evaluations, matches, severity/action metadata | Implemented and tested |
| 10 | Rules administration | List, add, edit, enable/disable, and delete through protected API/dashboard controls | Implemented and tested |
| 11 | Policy engine | Conditions, priority, enforcement mode, response action, validation/test, evaluations | Implemented and tested |
| 12 | Policy administration | List, add, edit, enable/disable, and delete; new policy defaults safely to `ALERT_ONLY` | Implemented and tested |
| 13 | Risk scoring | Per-agent risk history, weighted event contribution, configurable thresholds, and time decay | Implemented and tested |
| 14 | Alerts | Detection output is exposed as alert records with detail/update operations | Implemented |
| 15 | Incidents | Incident list/detail and status-related update flow | Implemented |
| 16 | Response orchestration | Response actions/scripts become commands, with allow-listing, signing, result tracking, retries, and audit records | Implemented; disruptive live actions not verified here |
| 17 | Real-time dashboard | WebSocket/realtime outbox plus polling-backed dashboard data refresh | Implemented and tested at API level |
| 18 | Analytics | Overview, time series, risk distribution, alert data, and MITRE coverage endpoints/views | Implemented |
| 19 | Reports | Security-summary data and report listing/export behavior used by the dashboard | Implemented |
| 20 | Threat intelligence view | Displays intelligence data returned by the manager; no bundled external commercial feed | Implemented UI/API, data-source dependent |
| 21 | Audit logging | Authentication, configuration, administration, and response activity are recorded in SQLite | Implemented and tested |
| 22 | Service health | Background worker state, logs, service status, schema metadata, and synchronization status | Implemented |
| 23 | Agent installation | PowerShell installer creates a venv/configuration and a SYSTEM scheduled task | Implemented; real host installation is deployment-dependent |
| 24 | Dashboard navigation | URL/history-aware single-page sections for operational and administrative pages | Implemented; browser availability affects live UI verification |

Users cannot bypass backend permissions by hiding/showing dashboard controls, run arbitrary response commands outside the server allow-list, assume cleartext remote agent transport is accepted, or treat an empty threat-intelligence view as an active external feed. Non-admin roles cannot mutate configuration or manage users. Some host telemetry requires elevation and enabled Windows audit/Sysmon channels.

## 3. Project architecture

### Components

- **Dashboard:** `dashboard/index.html`, `dashboard/assets/dashboard.js`, and CSS implement a vanilla JavaScript single-page SOC console. `dashboard/run_dashboard.py` starts the local system.
- **Manager/API:** `api/server.py` builds the manager with Python’s threaded standard-library HTTP server, REST handlers, RBAC checks, and a WebSocket hub. It is not currently a FastAPI runtime.
- **Authentication:** `api/auth.py` manages operator users/sessions and role permissions. Agent requests use separately configured agent tokens.
- **Persistence:** `storage/database.py` provides `ZTADatabase` schema/bootstrap logic and `ZTARepository` queries. SQLite WAL and a serialized background writer support concurrent reads and durable writes.
- **Background processing:** `api/background.py` drains queued persistence/detection work and publishes realtime records.
- **Endpoint agent:** `agent/agent_daemon.py` coordinates registration/heartbeat, collection, upload, command polling/execution, and retry. `agent/storage/offline_queue.py` supplies durable local buffering; `agent/network_identity.py` resolves network identity.
- **Detection:** `engine/` contains condition evaluation, event processing, risk scoring, policy selection, alert/incident behavior, and response planning.
- **Response:** `response/` contains command models/allow-listing, signed command validation, orchestration, execution adapters, and safety controls.
- **Installation/native references:** `install-zta-agent.ps1`, configuration templates, and `src/` support Windows deployment/native integration.

### Relationships

```text
Windows endpoint
  collectors -> Agent daemon -> local offline SQLite queue
                         | HTTPS/agent token
                         v
Manager ingestion API -> background writer -> SQLite WAL database
        |                       |                    |
        +-> detection/risk/policy engines            +-> audit/history
                             |                       |
                             +-> alerts/incidents    |
                             +-> response commands <-+
                                      |
Dashboard <- REST + WebSocket hub <---+---- operator authentication/RBAC
```

The dashboard and agent ingestion interfaces can use different ports (`8000` and `8080` by default) while sharing the same repository and database. Static Graphify edges describe code structure; HTTP, WebSocket, privilege, and TLS behavior must be checked at runtime.

## 4. Complete workflow

1. **Agent:** The daemon loads protected configuration, identifies its endpoint, initializes the offline queue, and starts collection/heartbeat loops.
2. **Manager connection:** Agent requests carry the configured agent identity/token. Remote cleartext transport is rejected; production should use trusted TLS and, when configured, client certificates.
3. **API ingestion:** Heartbeats update status. Telemetry is validated, normalized, deduplicated/batched, and accepted through `/api/v1/*` ingestion routes.
4. **Database:** The background persistence worker serializes writes into SQLite WAL tables. Sync receipts make offline batch submission idempotent.
5. **Detection:** The pipeline evaluates enabled rule condition trees and stores evaluation traces and matches. Risk contributions update the endpoint’s current score/history.
6. **Policy:** Enabled policies are considered by priority/conditions. Safe/default operation is `ALERT_ONLY`; stronger modes must be explicitly configured and permitted.
7. **Alerts/incidents:** Matching activity becomes dashboard-visible alerts and, where configured, incident records.
8. **Dashboard:** An authenticated operator reads REST data and realtime updates. Navigation selects one view and updates browser history.
9. **Admin/SOC actions:** Permitted users edit rules/policies/users or request allowed response actions. Commands are recorded for the target agent.
10. **Agent response:** The agent retrieves commands, verifies their constraints/signature, executes only supported actions, and posts results. Do not live-test disruptive actions on production endpoints.
11. **Audit:** Configuration, access, and response activity is persisted in `audit_log`; command results and evaluation history preserve operational evidence.

## 5. Dashboard user guide

Open `http://127.0.0.1:8000` after startup. Sign in with a securely provisioned operator account; do not copy credentials into source or documentation. Buttons hidden in the UI are convenience controls—the API is the authorization boundary.

| Page | Purpose and available actions | Required permission / expected result |
|---|---|---|
| Login | Authenticate, establish an operator session; password-change/logout are supported | Valid active user; failure returns an auth error without data |
| Overview | Counts, risk posture, recent operational data, service summary | `read`; refresh shows current SQLite/API state |
| Agents/Endpoints | Search/list agents, open endpoint details, inspect processes, sessions, ports, logs and status | `read`; detail requests return records for selected agent |
| Events | Filter/list telemetry and open event detail/timeline | `read`; result reflects ingested normalized events |
| Alerts | Review detection alerts and update supported alert state | `read`; mutations require the applicable response/config permission |
| Incidents | List/open incidents and apply supported updates | `read`, with write permission for changes |
| Timeline | Correlate event activity chronologically | `read`; filters change retrieved series |
| Rules | List rules; Add, Edit, validate/test, enable/disable, and Delete with confirmation | Reads need `read`; mutations need `config:write` (Admin) and create version/audit data |
| Policies | List policies; Add New Policy, Edit, validate/test, enable/disable, and Delete with confirmation | Reads need `read`; mutations need `config:write`; default enforcement is `ALERT_ONLY` |
| Analytics | View event trends, risk distribution, alert metrics, and MITRE coverage | `read`; charts reflect API aggregates |
| Reports | View/export supported security summary/report data | `read`; output is generated from stored records |
| Threat Intelligence | Inspect manager-provided intelligence data | `read`; may be empty without a configured data source |
| Audit Logs | Filter/review administrative and security activity | `audit:read` (Admin or Auditor) |
| Response Actions | Submit an allowed endpoint action or approved script | `response:write` (Admin or SOC Analyst); produces a tracked command, not guaranteed immediate execution |
| Settings | View effective configuration and supported risk/response options | `read`; configuration mutations require `config:write`; environment-owned settings may be read-only |
| User Management | List/create/update operator accounts and roles | `users:manage` (Admin) |
| System/Services | View background services, synchronization, logs, schema/health data | Generally `read`; sensitive operations remain protected |

The browser Back/Forward buttons restore known dashboard routes. Closing/cancelling a dialog should remove its overlay before opening another. If navigation appears blocked, check the browser console and network panel for an earlier JavaScript/API error, then hard-refresh after confirming the manager is reachable.

## 6. Admin operations

### Rules

Use **Rules → Add Rule** or **Edit**. Supply the schema-required name, condition tree, severity/action fields, and enabled state; run validation/test when offered, then save. The backend validates the payload, persists the rule, records versions/evaluations as applicable, and refreshes the list. Enable/Disable changes active evaluation without deleting the definition. Delete is supported by the item route and should always use the confirmation dialog.

### Policies

Use **Policies → Add New Policy** or **Edit Policy**. Set priority, conditions, response action, and enforcement mode. Leave `ALERT_ONLY` unless a deliberately approved response posture exists. Validation/test occurs before persistence. Enable/Disable controls evaluation eligibility; Delete removes the selected definition only after confirmation.

### Users, thresholds, and response settings

Only Admin has `config:write` and `users:manage`. Create named users with the least-privileged role, rotate initial passwords, and disable/update accounts through supported controls. Roles are:

- `ADMIN`: `read`, `audit:read`, `stream`, `config:write`, `response:write`, `users:manage`.
- `SOC_ANALYST`: `read`, `stream`, `response:write`.
- `AUDITOR`: `read`, `audit:read`, `stream`.
- `VIEWER`: `read` only.

Risk decay can be configured with `ZTA_RISK_DECAY_PER_MINUTE`; other effective settings are visible through `/api/zta/settings`. Environment-backed values require a controlled restart to change. Administrative mutations use SQLite transactions and generate audit records. The database-clear API is deliberately guarded by a short-lived confirmation flow; it is destructive and is outside normal operation.

## 7. Installation and execution

### Requirements

- Python 3.11 or newer.
- SQLite 3.35 or newer (Python’s bundled SQLite is normally used).
- Windows PowerShell 5.1+ for installer/Windows response operations.
- Python dependencies from `requirements.txt`: notably `requests` and `regex`; test extras include `pytest` and `pytest-asyncio`.
- Node.js is optional for JavaScript syntax checks; the dashboard itself is served by Python.

### Local manager/dashboard

From the repository root:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python dashboard/run_dashboard.py --port 8000 --api-port 8080 --db zta_runtime.db
```

Equivalent packaged entry point:

```powershell
python -m zta --port 8000 --api-port 8080 --db zta_runtime.db
```

The CLI help verifies defaults of dashboard port `8000`, ingestion port `8080`, and database `zta_runtime.db`. Open `http://127.0.0.1:8000`. The WebSocket endpoint is `/api/zta/ws` on the dashboard manager interface.

### Configuration

Important environment settings include `ZTA_DB_PATH`, `ZTA_ADMIN_TOKEN`, `ZTA_AGENT_TOKENS` (JSON mapping), `ZTA_RISK_DECAY_PER_MINUTE`, and documented TLS settings such as the CA bundle/client certificate/key. Keep secrets in protected environment/configuration files (the installer uses a protected environment file); never commit them. The local loopback setup may use HTTP, but non-loopback agents should use trusted HTTPS.

### Start an agent manually

```powershell
python -m agent.agent_daemon --manager-url http://127.0.0.1:8080 --agent-id agent-local-01 --token '<provisioned-agent-token>' --db storage/zta_agent_offline.db
```

The verified CLI also accepts `--config` and `--interval`. Prefer a protected config file over a command-line token because command lines may be observable.

### Install on Windows

Run the repository installer from an elevated PowerShell session with an HTTPS manager URL and provisioned identity/token/configuration according to its help/documentation:

```powershell
.\install-zta-agent.ps1 -ManagerUrl 'https://manager.example:8080' -AgentId 'agent-win-01'
```

The installer builds the runtime/venv, protects configuration, and registers the `ZTA Endpoint Agent` scheduled task under SYSTEM. Verify arguments supported by the local script before deployment. Sysmon and Windows audit channels must be installed/enabled separately when required.

### Stop safely

- Foreground local server/agent: press `Ctrl+C` once and allow shutdown/queue checkpointing to complete.
- Installed agent: stop the `ZTA Endpoint Agent` scheduled task through Task Scheduler or the corresponding PowerShell scheduled-task command; do not kill SQLite files or delete the queue.
- Back up the database only after a clean stop or by using a SQLite-safe backup method. Never remove or reset `zta_runtime.db` to troubleshoot startup.

## 8. Security and detection

Operator sessions and agent tokens are distinct. Passwords are salted/hashed, sessions expire and can be revoked, route handlers re-check permissions, and security-relevant changes are audited. Admin-only configuration/user routes are not made safe merely by UI hiding. Remote deployments require TLS; optional client certificates strengthen agent transport when provisioned.

The detection engine evaluates structured, nested conditions against normalized event context and records explainable traces. Enabled rules can emit matches with severity/action metadata. Policy evaluation applies ordered conditions and enforcement modes. Risk scoring accumulates event contributions per endpoint and decays over time; thresholds influence posture/response decisions.

Insider-threat visibility comes from authentication failures/successes, process creation, PowerShell activity, network/listening-port state, sessions, and other Windows event channels supported by collectors. Coverage depends on endpoint permissions and audit policy.

Response is intentionally constrained: commands/actions are allow-listed, represented as tracked records, can be signed/verified, and return results. `ALERT_ONLY` is the safe default. Isolation, process termination, or similar disruptive actions should be validated only in a disposable authorized lab; they were not executed for this guide.

## 9. Database and API

### Important SQLite tables

| Area | Tables |
|---|---|
| Endpoints | `agents`, `agent_processes`, `agent_sessions`, `agent_listening_ports`, `agent_logs` |
| Telemetry/detection | `zta_events`, `rules`, `rule_versions`, `rule_evaluations`, `rule_matches` |
| Policy/risk | `policies`, `policy_evaluations`, `risk_history` |
| Operations | `incidents`, `commands`, `command_results`, `realtime_outbox` |
| Security | `operator_users`, `operator_sessions`, `audit_log` |
| Reliability/metadata | `sync_history`, `sync_receipts`, `background_services`, `schema_migrations` |

Agents relate to telemetry and inventory by `agent_id`; rule matches/evaluations reference events and rules; policy evaluations preserve decisions; commands/results relate response requests to endpoints; audit entries identify actor/action context. JSON columns retain structured details where a fixed relational shape is unsuitable.

### Main API groups

- **Authentication/operators:** `/api/zta/auth/login`, `/logout`, `/password`, `/api/zta/session`, `/api/zta/users`.
- **Dashboard reads:** `/api/zta/overview`, `/agents`, `/events`, `/alerts`, `/incidents`, `/timeline`, `/audit`, `/settings`, `/services`, `/background-services`, `/logs`, `/schema`.
- **Rules/policies:** `/api/zta/rules`, `/rules/{id}`, `/rules/schema`, `/rules/validate`, `/rules/test`; corresponding `/api/zta/policies`, item, validate, and test routes.
- **Endpoint detail:** `/api/zta/processes`, `/sessions`, `/listening-ports` and agent detail routes.
- **Analytics/reporting:** `/api/zta/analytics/*`, `/reports`, `/reports/security-summary`, `/threat-intelligence`.
- **Response:** `/api/zta/actions`, `/actions/execute`, `/scripts`, `/scripts/execute`, `/commands`.
- **Agent ingestion:** `/api/v1/agents/heartbeat`, `/telemetry/bulk`, `/sync/offline`, `/commands`, `/commands/result`, `/agents/logs`.
- **Realtime:** `/api/zta/realtime-events` and `/api/zta/ws`.

Exact HTTP methods and validation are defined in `api/server.py`; callers should not infer write access from a route name. The repository layer, not direct dashboard SQL, owns data storage/retrieval.

## 10. Testing and troubleshooting

### Verification commands

```powershell
python -m pytest -q
python -m pytest tests/test_api_crud.py tests/test_auth.py tests/test_rbac_enforcement.py -q
node --check dashboard/assets/dashboard.js
.\graphify.cmd query "manager agent database detection dashboard architecture" --budget 1000
```

Use the existing browser test setup when available to sign in, switch every sidebar route, exercise non-destructive Rules/Policies CRUD, reload, and confirm persistence. Use a disposable uniquely named rule/policy and remove only that test record. Keep policies at `ALERT_ONLY`. Verify non-admin mutations receive `403`, and inspect browser Console/Network for errors. Do not claim live browser, native agent, or disruptive response success unless those checks actually ran.

### Health checks

- Open `/api/zta/background-services` with an authorized session to inspect worker state.
- Check `/api/zta/agents` for heartbeat/last-seen changes.
- Inspect `logs/zta-agent.jsonl` and manager console/log API for errors; redact tokens and sensitive telemetry before sharing.
- Confirm the agent manager URL/port and token mapping agree, system time is reasonable, and TLS CA/client certificate paths are readable.
- Inspect `storage/zta_agent_offline.db` only with SQLite-safe read operations; a growing queue suggests connectivity/authentication failure.

### Common problems

| Symptom | Check / remedy |
|---|---|
| Dashboard cannot load data | Confirm both ports are listening, session is valid, and API calls are not `401/403`; restart cleanly after configuration changes |
| Login fails | Verify the provisioned active operator, password, session expiry, and server clock; do not expose credential files |
| Agent stays offline | Check URL, DNS/TLS trust, agent token mapping, firewall, heartbeat interval, and agent log |
| Remote HTTP rejected | Use HTTPS with a trusted CA; cleartext is intended only for loopback development |
| Events absent | Check Windows channel/audit configuration, collector privileges, queue growth, ingestion response, and background worker health |
| Rules/policies do not fire | Confirm enabled state, condition schema/field names, priority, validation/test output, and evaluation trace tables |
| Actions remain queued | Confirm agent heartbeat, role permission, action allow-list/signature, agent command polling, and command result |
| SQLite busy/corrupt concern | Stop cleanly, preserve the file, inspect WAL/background service state, and use SQLite integrity/backup tools; never reset production data |
| Browser section/modal overlap | Close dialogs, check console errors, verify current route, then reload; reproduce in browser automation before changing source |
| Windows path-related test failure | Enable Windows long-path support or shorten the checkout path; do not alter runtime logic to mask environment limits |

## 11. Project status

### Working/verified from source and tests

- Integrated manager/dashboard startup, SQLite schema/repository, WAL-backed persistence, and background processing.
- Auth/session lifecycle, backend RBAC, audit recording, agent authentication, telemetry/offline sync, detection/risk/policy logic, and command-result tracking.
- Dashboard data APIs and Rules/Policies CRUD contracts, including validation, enable/disable, delete, and SQLite persistence tests.
- Repository test history observed during this work: 215 tests passed; two installer/quarantine tests were blocked by Windows checkout path-length behavior rather than an identified application regression. A focused 46-test API/navigation/security suite passed. Treat these figures as a point-in-time result, not a substitute for rerunning tests after changes.

### Partial, unverified, or deployment-dependent

- Full native Windows scheduled-task installation, privileged event-channel collection, Sysmon coverage, mTLS issuance, and real endpoint command execution require an authorized Windows lab and were not executed for this guide.
- Browser automation has previously verified focused Rules/Policies navigation, but Chromium loopback access was intermittent in this environment; comprehensive live UI status is therefore not asserted here.
- Threat-intelligence usefulness depends on supplied data; production high availability, external SIEM integrations, centralized secret storage, and a production reverse proxy are not provided as complete turnkey subsystems.
- Documentation outside this guide may refer generically to FastAPI or older role names; current runtime source uses the threaded standard-library server and the four roles documented above.

### Known limitations and recommended improvements

1. Add a repeatable CI browser suite for all dashboard routes, modal exclusivity, CRUD persistence, history navigation, and console-error failure.
2. Run installer/agent/response integration tests on a short-path, disposable Windows VM with Sysmon and audited event channels.
3. Put the manager behind hardened TLS, automate certificate/secret rotation, and document production backup/restore drills.
4. Add a non-destructive end-to-end fixture that proves Agent → ingestion → detection → alert → dashboard → audit while forcing `ALERT_ONLY`.
5. Align older documentation terminology with the current server implementation and RBAC constants.

### Graphify status

The existing Graphify setup was used first and preserved. Before this guide, the index contained **1,155 nodes, 2,546 edges, and 78 communities** and successfully located the dashboard, server, authentication, repository, agent, engine, response, and test paths. The project refresh script is run as the final documentation step; its final result is recorded below after regeneration.

- Latest refresh: **PASS — 1,155 nodes, 2,546 edges, 78 communities; 102 files reused, 1 code file re-extracted, reports and call-flow HTML regenerated.**
- Validation queries: manager/agent/database/detection/dashboard architecture; startup/dependencies; API/RBAC/CRUD.
