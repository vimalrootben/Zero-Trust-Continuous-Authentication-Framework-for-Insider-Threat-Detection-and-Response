# Task 4 — Real-Time Detection Pipeline Implementation Report

Date: 2026-10-14  
Scope: Task 4 only; the Windows response executor and dashboard design were not changed.

## A. Repository status

- Branch: `feat/agent-execution-integration`
- Commit reviewed: `3365b7aebc0827b6d780f70e6451a13613e6d7a0`
- Working tree was already dirty from Tasks 1–3 and an unrelated `api/auth.py` modification. Those changes were preserved.
- Reviewed: `README.md`, `ARCHITECTURE.md`, `CONTRACTS.md`, `update.txt`, Tasks 1–3 reports, schema/repository, ingestion, background worker, condition/risk/trust/policy/response engines, dispatcher, RBAC, dashboard APIs, and tests.

## B. Baseline

- Historical Task 3 result: 188 passed.
- Independent starting command: `python -m pytest -q --basetemp C:\zta-task4-baseline-20261014`
- Starting result: **188 passed, 0 failed, 0 skipped** in 161.10s.
- Final command: `python -m pytest -q --basetemp C:\zta-task4-full-final-2`
- Final result: **193 passed, 0 failed, 0 skipped** in 162.01s.

## C. Pipeline connection matrix

| Component | Source/function | Input | Durable output | Next component | Test evidence | Status |
|---|---|---|---|---|---|---|
| Authenticated ingestion | `api/ingestion.py:ingest` | Authenticated online/offline telemetry batch | `zta_events`, `sync_receipts` | Background worker | ingestion, offline replay, duplicate upload tests | Connected |
| Event persistence | `storage/database.py:save_event` | Normalized `ZTAEvent` | Stable event ID, normalized/original JSON, timestamps, `PENDING` | Work claim | Task 3 replay and Task 4 worker tests | Durable/idempotent |
| Work scheduling | `api/background.py:BackgroundWorker.tick` | Pending or due failed event | `PROCESSING` claim, attempt count, owner, timestamps | Pipeline | automatic retry, restart, concurrent-worker tests | Repaired |
| Rule evaluation | `engine/pipeline.py:process` | Persisted normalized event and rule snapshot | `rule_evaluations` with outcome/error/version | Match persistence | outcomes/version test; condition regressions | Automatic |
| Match evidence | `engine/pipeline.py`, `save_rule_match` | Successful evaluator trace only | `rule_matches` | Risk engine | distinct-event and duplicate replay tests | Connected |
| Risk | `ZTARiskEngine.apply_delta`, `save_risk_event` | Actual correlation/rule delta | `risk_history` | Trust/alert | boundary and idempotency regressions | Connected |
| Alert | `engine/pipeline.py`, `save_incident` | Match, risk, trust, event evidence | `incidents` | Policy engine | alert evidence/dedup tests | Connected |
| Policy | `ZTAPolicyEngine.evaluate_single_policy` | Detection context and ordered enabled policies | `policy_evaluations` | Response decision | ALERT_ONLY/ENFORCE/priority tests | Connected |
| Response decision | `engine/response/command_builder.py:build_command` | Selected ENFORCE decision and current target evidence | Allowlisted deterministic `commands` row | Existing heartbeat dispatcher | safety, freshness, duplicate-command tests | Connected |
| Dispatch | `api/server.py` heartbeat path | Queued authorized command | `DISPATCHED` state and audit | Existing agent receiver | Task 3 and background completion tests | Preserved |
| Audit/realtime | Repository audit methods and `WebSocketHub` | Transactional pipeline facts | `audit_log`; buffered broadcasts after commit | Dashboard/API clients | shared WebSocket and rollback tests | Connected |

## D. Rule engine

- Every durably accepted manager event remains eligible for background evaluation without dashboard activity.
- Enabled rules are read inside the event transaction; SQLite's immediate transaction provides one consistent rule/version view for the event. Disabled rules are skipped.
- Existing rule mutation validation, AND/OR/NOT, field/operator validation, tree limits, regex length/input limit, timeout, and the NOT/error regression remain intact.
- Evaluation evidence now separates `MATCH`, `NO_MATCH`, and `EVALUATION_ERROR`. An evaluator exception or regex safety failure cannot become a match.
- `rule_evaluations` now records `rule_version` and an `error_code`; matches continue to store the complete evaluator trace and version.

## E. Risk engine

- Existing additive/clamped 0–100 formula was retained; no score was invented to force an alert.
- Existing levels remain LOW 0–29, MEDIUM 30–59, HIGH 60–84, CRITICAL 85–100.
- The enclosing event transaction rolls back risk, match, alert, policy, command, and audit writes together. Stable event/match IDs and completed-state checks prevent retry double-counting.
- Existing background decay and critical-incident suppression were preserved.

## F. Alert engine

- Alerts are generated automatically only after a real successful rule evaluation and risk calculation.
- Alert identity now includes the stable `event_id` and `rule_id`. A telemetry retry resolves to the same logical alert, while two genuinely different event IDs no longer collapse merely because their fields look alike.
- Existing status model, authorized management endpoints, evidence expansion, timestamps, audit history, and response status updates were preserved.

## G. Policy engine

- Enabled policies are automatically evaluated in deterministic priority/code/ID order against the actual detection context.
- Disabled, ineligible, malformed, or nonmatching policies do not trigger.
- `ALERT_ONLY` records real evaluation/audit evidence and never creates a destructive command.
- `ENFORCE` reaches command construction only for the selected matching policy. Existing allowlisted action, target-field, freshness, dry-run validation, offline, and duplicate-ID gates remain mandatory.
- Conflict behavior is conservative: the first deterministic matching policy is selected; later matches are recorded `NOT_SELECTED`. This never combines policies or escalates an ambiguous response.

## H. Response decisions

- Command IDs remain deterministic from alert and policy identities.
- Commands are created in the same database transaction as their rule/risk/alert/policy evidence and corresponding `COMMAND_CREATED` audit record.
- Only existing allowlisted response templates are accepted. Arbitrary PowerShell is not accepted.
- A queued/dispatched command is not reported as a successful Windows action; terminal success still requires the authenticated agent result and existing verification rules.
- No destructive endpoint action was run.

## I. Background reliability

- Events are durably claimed as `PROCESSING` with worker ID, start time, and incremented attempt count.
- Failures are persisted as `FAILED` with class/message, failure time, and an automatic retry deadline. Due failures use capped exponential backoff (base configurable by `ZTA_EVENT_RETRY_BASE_SECONDS`, cap 300s).
- Retry count is bounded by `ZTA_EVENT_MAX_ATTEMPTS` (default 5). Exhausted events remain failed with no next-attempt timestamp and a dead-letter audit event.
- A new manager worker recovers abandoned `PROCESSING` claims after restart.
- Manual authorized retry remains available and resets the attempt budget.
- SQLite transactional claims plus stable IDs prevent two workers from duplicating matches, risk increments, alerts, policy decisions, or commands.
- Offline replay retains original event time and manager `synced_at`. Existing response freshness/offline gates prevent stale manager-side destructive dispatch.

## J. Audit and WebSocket

- The persisted chain is event → rule evaluation/version → match → risk → alert → policy evaluation → optional command → audit.
- Existing buffered WebSocket broadcasts are committed only after the database transaction succeeds; rollback discards them.
- Existing event contracts (`rule.evaluated`, `rule.matched`, `risk.updated`, `alert.created`, `policy.evaluated`, `policy.triggered`, and command/response events) were preserved.
- WebSocket authentication and session/RBAC behavior were not weakened.

## K. Database

- Additive migration: `20261014-detection-reliability`.
- `zta_events` additions: `processing_attempt_count`, `processing_started_at`, `processing_next_attempt_at`, `processing_last_error_at`, `processing_worker_id`.
- `rule_evaluations` additions: `outcome`, `error_code`, `rule_version`.
- Added `idx_rule_evaluations_event(event_id, outcome)`.
- No schema reset, destructive migration, or production-data deletion was performed.

## L. Test results

- Starting full suite: 188 passed.
- New Task 4 tests: `python -m pytest -q tests/test_task4_detection_pipeline.py --basetemp C:\zta-task4-newtests-2` → 5 passed.
- Focused Task 4/pipeline/RBAC/Task 3 set → 82 passed.
- Final full suite → **193 passed, 0 failed, 0 skipped**.
- Python source syntax and dashboard JavaScript syntax were checked. One repository test file contains a pre-existing UTF-8 BOM, so the generic AST sweep requires `utf-8-sig`; pytest imports it successfully.
- The test suite uses controlled normalized telemetry and mocked/non-executing response providers. **REQUIRES REAL WINDOWS TEST** for native ETW/WMI capture, service deployment, mTLS infrastructure, endpoint action execution, and response-result verification.
- No standalone load benchmark was claimed. The five-event Task 4 focused suite completed in 1.89s; this is test duration, not a production throughput measurement.

## M. Task 4 changed files

Created:

- `tests/test_task4_detection_pipeline.py`
- `TASK_4_IMPLEMENTATION_REPORT.md`

Modified for Task 4:

- `api/background.py`
- `api/ingestion.py`
- `api/server.py`
- `engine/pipeline.py`
- `storage/database.py`
- `tests/http_support.py`
- `pyproject.toml`

No file was removed. Earlier Task 1–3 files and the unrelated `api/auth.py` edit remain untouched by Task 4.

## N. Remaining issues

1. **P1 — Real Windows qualification required.** Root cause: CI uses safe fixtures and mocked execution. Run a signed Windows agent/manager deployment with real credentials, ETW/WMI telemetry, restart/reconnect, and non-destructive response verification.
2. **P2 — SQLite scale ceiling.** `BEGIN IMMEDIATE` deliberately serializes detection commits for correctness. Measure realistic multi-agent throughput before choosing a server database or external queue; no second broker was added in Task 4.
3. **P2 — Imported offline evidence uses authenticated cached configuration.** It is integrity-checked and not reauthorized as a new manager destructive decision. Broader cryptographic attestation and cross-version reconciliation should be deployment-qualified.
4. **P3 — Formal performance telemetry.** Queue depth is queryable and service health is persisted, but production latency/throughput histograms are not yet implemented.

## O. Task 5 readiness

- Existing dispatcher: manager heartbeat returns signed, allowlisted queued commands.
- Existing agent handlers: template-based PowerShell and registered script execution remain in place.
- Target validation: timestamp freshness, exact process identity fields, user/session data, action allowlist, and dry-run provider validation are enforced before queuing.
- Result verification: authenticated result transitions and action-specific verification remain implemented.
- Task 5 must perform real Windows integration testing and response-result verification. Task 4 did not rewrite or execute the Windows response layer.
