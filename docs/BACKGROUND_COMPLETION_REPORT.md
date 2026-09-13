BLUEPRINT REVIEW:
Read the root implementation blueprint and existing data-flow documentation before editing. Preserved the separate Python Zero Trust layer, existing native Wazuh source, models, rules/policies and dashboard. The source snapshot reports Wazuh 5.1.0 alpha0 and has no Git metadata. Native baseline, installed decoding content and matching indexer/dashboard versions remain unverified.

EXISTING ARCHITECTURE FOUND:
Python HTTP manager in api/server.py; SQLite repositories in storage/database.py; canonical event, correlation, risk, trust, policy and response modules in engine/; agent heartbeat/local queue/command receiver in agent/; allowlisted scripts and WTS verification in powershell/; existing HTML/CSS/JavaScript dashboard. The two HTTP listeners previously constructed independent engines/hubs. They now share one worker/runtime.

EXISTING RULES:
The runtime database contains RULE-0001 through RULE-0015. Their identities, definitions, flags and stored content were preserved. Rule-ID matching no longer bypasses configured conditions. Some supplied rule names overstate their conditions; the existing IOC rule contains a documentation/example address. This work does not certify detection-content quality or replace it.

EXISTING POLICIES:
Preserved POL-001, POL-002, POL-003, POL-004 and POL-LOGOUT-001. The logout policy links to RULE-0004, with ENFORCE and allow_offline enabled; that rule itself has offline approval disabled. No real installation policy was created or modified for tests.

ALREADY IMPLEMENTED:
Canonical events, adapter, condition trees, correlation, risk/trust calculations, SQLite CRUD, rules/policy management UI, offline queue, response templates, WTS ownership/disappearance checks and basic WebSocket broadcasting existed.

PARTIALLY IMPLEMENTED:
Previously request-bound processing, unauthenticated heartbeats, structural-only command checks, in-memory risk, partial retry deduplication, local severity-driven logout, missing full result linkage and display assumptions. Connected or corrected these paths. Native deployment and Windows behavior still require external validation.

MISSING:
A verified native Wazuh/indexer ingestion contract; actual Windows validation; verified network isolation/reachability. The code refuses unverified isolation execution. Production TLS/credentials/Sysmon/audit-channel provisioning must be supplied by deployment. This report does not mark those requirements complete.

BACKGROUND SERVICES:
Added a managed SQLite-backed event worker, restart recovery for pending events, transactional processing, heartbeat expiry, command expiry and persisted risk decay. Worker health reflects failure/staleness; failed events remain stored with a reason and administrator-only retry. A single shared runtime serves both existing ports.

AGENT ONLINE MODE:
Authenticated heartbeat, real source collection, durable telemetry submission, signed command polling and journaled result upload. Remote communication requires certificate-verified HTTPS. Initial state is RECONNECTING until actual communication.

AGENT OFFLINE MODE:
Collector thread continues independently of heartbeat/reconnect. Missing/expired configuration prevents enforcement while collection continues. Actual Windows channels or an explicitly configured real JSONL feed supply events.

HEARTBEAT:
Server receipt time determines freshness. Stale SYNCING/RECONNECTING endpoints become OFFLINE rather than remaining indefinitely active. Version, queue/sync state and collector errors are available in endpoint details.

RECONNECT:
Background retry authenticates, refreshes signed definitions, uploads the durable queue, retries pending results and reports the current state. Reconnection does not depend on an open browser.

OFFLINE QUEUE:
Reused existing SQLite queue; no capacity-based loss of unsynchronized events. Collector checkpoints advance after durable storage. Added cache/checkpoint and command-journal tables in the agent's existing database. Disk failure and source-log overwrite remain deployment/retention concerns.

SYNC:
Stable event identities, atomic batch receipts, conflict detection and transactional evidence import prevent repeated effects on retry. Original offline timestamps/source and manager synced_at are retained. Only explicitly acknowledged queue IDs are removed. Historical sync does not issue retrospective destructive actions.

RULE ENGINE:
Database definitions run in the background. Every enabled rule evaluated produces a real trace and evaluation record, including false/error results; last_evaluated is updated from actual execution. Existing standalone local defaults remain available for their existing unit tests but are not used by the production daemon.

AND/OR/NOT LOGIC:
Reused the shared evaluator, preserving every branch's actual result. Added normalized/raw data context needed by existing field paths. An incoming rule identifier cannot force a condition tree to match.

RULE MATCHES:
Stable per-event/per-rule identities, real trace, event/agent linkage, severity, MITRE and alert/policy associations. Removed fabricated confidence defaults. Rule counts derive from stored matches.

RISK ENGINE:
Restores persisted risk before each unit of work. Risk changes are committed with the event pipeline, preventing replay inflation and partial-write divergence. Existing correlation windows are reconstructed from committed events (bounded to the latest 1,000 preceding events). Decay is persisted/audited and does not automatically decay unresolved critical incidents to safety. Very high-volume correlation beyond that bound requires capacity tuning.

ALERT ENGINE:
Reuses incidents as the existing alert model. Alerts are stored after matches/risk and before policy evaluation. Forensic detail queries are scoped to the selected alert, rather than leaking unrelated matches/evaluations from the same rule/policy.

POLICY ENGINE:
Every policy receives a recorded eligibility/condition result. Linked-rule priority and deterministic first matching policy remain the selection semantics; other matching policies are shown as NOT_SELECTED. Disabled/unlinked/offline-unapproved policies cannot enforce. Recommendations keep their actual proposed action.

ALERT_ONLY:
Records recommendation and evaluation; creates no destructive command.

ENFORCE:
Selected allowlisted actions create structured commands only with valid targets and fresh event evidence. Unsupported providers or missing/future/stale targets produce visible BLOCKED reasons.

LOGOUT POLICY:
Uses the preserved policy repository and rule link. No severity-based hardcoded logout remains in the daemon. Offline execution additionally requires the rule's offline approval, which is not enabled for the existing logout-linked rule in the installation database.

LOGOUT RESPONSE:
Exact username/WTS session ID from actual event context; no analyst/session-1 fallback. Command signatures bind agent, target, action, policy linkage and expiration. Results update command, alert, policy status and audit.

POWERSHELL EXECUTOR:
Predefined allowlist retained. No dashboard/rule/policy raw script path. Process termination now requires an exact PID/name and checks process exit. Isolation remains explicitly unavailable rather than claiming containment.

LOGOUT VERIFICATION:
Reuses real WTS ownership validation and post-logoff session enumeration. SUCCESS requires SESSION_NOT_ACTIVE. WTS errors, disconnected-but-present sessions and failed script execution cannot become success. Linux tests mock Windows APIs and are not live validation.

COMMAND DISPATCHER:
Heartbeat delivery signs commands for the authenticated target; queued/dispatched/executing/terminal/expired states persist. Retries use a durable agent journal and do not execute a command twice. An interrupted unknown outcome fails closed rather than replaying the action. Invalid result identities, missing verification and conflicting terminal results are rejected.

RESPONSE ENGINE:
Separated command construction from policy selection and PowerShell execution in the existing response package. Manual commands require authenticated administrator access and allowlisted parameters. Preview remains nonexecuting.

WEBSOCKET:
Real event/state/result broadcasts share one hub across both listeners. Event-pipeline notifications are buffered until transaction commit. Client framing/close/ping handling is bounded. Dashboard refreshes again if updates arrive during an in-flight request.

MANAGER DASHBOARD:
Existing CSS, navigation, cards, tables and theme preserved. Added evidence fields, a collapsible backend-status view and authentication using the existing role control. No fabricated verification, forced mode or success fallback remains in the forensic chain.

OVERVIEW:
Uses persisted event/agent/alert/rule/policy/response counts and operational metadata. Queue depth is reported by authenticated endpoints. Health depends on actual worker status.

ENDPOINTS:
Real heartbeat age, connection/sync state, queue depth, risk/UNASSESSED, active alerts, agent version and collector errors. Network isolation is not asserted without an implemented verified provider.

RULES:
Existing page preserved; actual conditions and evaluation history are shown alongside matches, links and counters. Unknown confidence is left unknown.

POLICIES:
Existing page preserved; actual mode/action/conditions and evaluation evidence available, including non-triggered and non-selected decisions, response history and failure reasons.

ALERTS:
Existing details now fetch the complete alert-specific event/rule/risk/policy/command/result/audit chain. Endpoint verification and source/sync metadata are shown from stored evidence.

TIMELINE:
Existing page retains telemetry, matches, policy evaluations, commands and audit timestamps. Audit includes rule evaluation, risk changes, alert/policy decisions, dispatch/execution/results, offline actions, sync and expiry. A newly created command is not mislabeled as already dispatched.

AUDIT LOG:
Real operations and identifiers recorded, including actual failures, original offline timestamps and result statuses. Test fixtures never populate installation audit data.

BACKGROUND STATUS:
Actual worker heartbeat/status and activity timestamps; initial STOPPED, runtime RUNNING/DEGRADED/FAILED, and STALE after heartbeat expiry. Errors remain visible in persisted event/service details.

REAL DATA CONNECTED:
Authenticated telemetry -> durable processing -> database-defined rules -> risk -> existing alerts -> policies -> signed responses -> journaled agent results -> forensic data and WebSocket. Offline evidence imports without retrospective command execution. Real Windows/native deployment remains unverified.

FAKE/DEMO PRODUCTION LOGIC FOUND:
Hardcoded analyst/session/PID targets; severity-driven offline logout; rule-ID condition bypass; default successful result acceptance; unverified forensic UI defaults; fabricated confidence; service rows initially claiming RUNNING; simulated admin identity; independent per-port engines/hubs; repeated pipeline effects on retry. Existing seeded detection content also includes an example IOC address, which is preserved and explicitly disclosed.

FAKE/DEMO PRODUCTION LOGIC REMOVED:
Removed or replaced the above execution/state/evidence placeholders and bypasses. Tests retain legitimate fixtures and explicitly label simulated Windows execution. No real database rules/policies were replaced with test content.

FILES CREATED:
See the file manifest below.

FILES MODIFIED:
See the file manifest below. Existing native source and dashboard CSS are unchanged.

DATABASE MIGRATIONS:
Versioned additive migration 20260910-background-evidence; processing/error/serialized-event columns, condition evidence, command execution/sync metadata, endpoint version/collector-error metadata, rule_evaluations, sync_receipts and schema_migrations. Agent state and command journal are additive. Legacy events are not automatically enforced. Migration runs at application startup; installation databases are not populated by tests.

TESTS PASSED:
See the final verification entry below. Coverage includes existing regression/CRUD tests plus authenticated background flow, non-match, ALERT_ONLY, exact targets, authorization expiry/tamper, replay, offline evidence, selective acknowledgement, migration preservation, rollback/retry, startup recovery, collector checkpoints and cross-port WebSocket delivery. JavaScript syntax and Python compilation were also checked.

TESTS FAILED:
No unresolved failures in the final verification run. Earlier failures exposed old fixture assumptions and a shutdown cleanup error; these were corrected and the suite rerun.

REQUIRES REAL WINDOWS TEST:
Yes: actual Windows channels, Sysmon/audit configuration, SYSTEM task startup, session ownership and disappearance after real logout, process termination, real offline enforcement, restart interruption and reconnect across a TLS network. Follow WINDOWS_VALIDATION.md. Verified network isolation and native Wazuh/indexer integration remain unfinished; no fake success is reported.

File manifest (relative to project root):

- Modified: README.md
- Modified: agent/agent_daemon.py
- Created: agent/collectors.py
- Created: agent/commands/authorization.py
- Modified: agent/commands/command_receiver.py
- Created: agent/state.py
- Created: api/background.py
- Created: api/ingestion.py
- Modified: api/server.py
- Modified: dashboard/assets/dashboard.js
- Modified: dashboard/index.html
- Modified: dashboard/run_dashboard.py
- Created: docs/WINDOWS_VALIDATION.md
- Modified: engine/events/models.py
- Created: engine/events/serialization.py
- Modified: engine/events/wazuh_adapter.py
- Created: engine/pipeline.py
- Modified: engine/policy/engine.py
- Created: engine/response/command_builder.py
- Modified: install-zta-agent.ps1
- Modified: powershell/ps_executor.py
- Modified: powershell/scripts/kill_process.ps1
- Modified: pyproject.toml
- Modified: storage/database.py
- Created: tests/conftest.py
- Created: tests/http_support.py
- Modified: tests/test_agent_daemon.py
- Modified: tests/test_agent_engine.py
- Created: tests/test_background_completion.py
- Modified: tests/test_dashboard_integration.py
- Modified: tests/test_powershell_executor.py
- Modified: tests/test_rules_policies_management.py
- Modified: tests/test_zta_end_to_end_scenarios.py
- Modified: zta_windows_installer.py
- Created: docs/BACKGROUND_COMPLETION_REPORT.md

Final verification: 99 pytest tests passed in 21.22 seconds in the isolated workspace; no unresolved failures. All Windows actions in tests use explicitly controlled fixtures. JavaScript syntax and Python compilation checks passed. Final validation from /home/ben/Projects/wazuh-main also passed: 99 tests in 21.42 seconds, plus JavaScript syntax validation. The migration was run twice on a temporary copy of the actual zta_runtime.db and preserved all existing rules, policies and incidents. All 35 applied files matched the reviewed manifest before this verification-only report update. Production database files remain untouched; the migration runs on next manager startup. File backups are in .backups/background-completion-20260910T171613Z/.
