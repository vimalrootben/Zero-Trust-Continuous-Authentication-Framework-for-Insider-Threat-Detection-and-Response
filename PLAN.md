# Plan

## In progress - Verified native response pipeline

- Delivery stays on `feat/agent-execution-integration` by explicit operator instruction; no new branch and no work on `main`.
- Phase 1: prove the single telemetry -> normalization -> rule -> policy -> signed receiver -> native dispatcher -> verification -> durable evidence -> acknowledgement path.
- Phase 2 (completed): PID-reuse-safe process termination plus native process inventory/execution evidence in the live dashboard.
- Phase 3: complete exact WTS session resolution/logoff and live session inventory.
- Phase 4: add separate reversible local-account lock/unlock actions with protected-account checks.
- Phase 5: keep network isolation disabled until transactional firewall state, rollback, reachability, restart recovery, and console-only VM tests pass.
- Phase 6: keep offline process kill/logout disabled until their native online verification phases pass, then preserve at-most-once acknowledgement semantics.
- Acceptance: every exposed action performs a verified native operation or returns explicit `UNAVAILABLE`; no simulated success path.

## Completed - Initial agent execution integration

- Removed the environment-mode gate and consolidated script execution without changing either allowlist.
- Connected signed online commands and signed cached-policy offline decisions to one receiver/executor/journal path.
- Connected process, file, network connection, and listening-port telemetry to rules, risk, policy, execution, and acknowledged reconnect sync.
- Retired network isolation execution for this scope; requests now fail closed with a clear `UNAVAILABLE` verification result.
- Added the existing-flow manual script control, live port telemetry/dashboard, narrow self-PID exclusion, active-alert coalescing, and token-confirmed ADMIN database clearing.
- Acceptance: manager and offline commands execute at most once after all existing authorization checks; verified durable evidence synchronizes only after acknowledgement; full regressions pass.

## Completed - Deterministic policy selection

- Added validated policy priorities, a migration preserving legacy order, stable tie-breaking, and dashboard priority controls/details.
- Acceptance: overlapping policies consistently select by priority, code, then ID; migration and full regression tests pass.

## Completed - Operator authentication pages

- Added a dedicated responsive login page, hard dashboard session gate, admin operator-management page, self-service password change, and logout-to-login behavior.
- Acceptance: unauthenticated UI cannot render/load dashboard data; user creation remains permission-gated; password change revokes other sessions; focused and full regressions pass.

## Completed - Recoverable rule changes

- Added immutable definition versions, append-only rollback, linked-policy deletion protection, and rule-version evidence on matches/incidents.
- Acceptance: rollback restores prior behavior without changing IDs; linked-rule deletion returns 409; focused rule-management tests pass.

## Completed - Bounded regex evaluation

- Limited regex pattern and input sizes and enforced a 25 ms timeout using the timeout-capable `regex` engine.
- Acceptance: expensive patterns terminate with traceable safe-false results; normal regex matches and all 132 tests pass.

## Completed - Safe rule activation

- Enforced rule field types, enums, risk bounds, operand types, and condition-tree complexity before create, update, or activation.
- Acceptance: invalid rules are rejected without persistence; valid seeded/existing workflows pass all 129 tests.

## Completed - Authenticated permission access

- Added operator creation, password login, expiring sessions, role permissions, protected reads/writes/streams, and authenticated dashboard session flow.
- Acceptance: unauthorized access returns 401; insufficient permissions return 403; permitted workflows and unchanged agent authentication pass the 116-test suite.

Sequential merge review (2026-09-14): verify each existing branch in ancestry order, preserve both Git histories, and record results in update.txt. Permissions, rule-toggle and regex error-propagation fixes complete; analytics time-range correction and Windows deployment verification remain pending.

## P0 - Establish a clean baseline

- Make the repository and test temp directory writable to the development account.
- Pin/support a tested Python version (project requires 3.11+; current machine uses 3.14.7) and remove the Requests character-detection warning.
- Acceptance: all 113 tests execute with no setup errors; failures, if any, are assertion failures with reproducible logs.

## P1 - Validate Windows endpoint operation

- Install/enable Sysmon and run the agent with Security event-log permission, or explicitly configure JSONL-only collection.
- Acceptance: heartbeat shows no `collector_error`, queue drains to zero, agent becomes `ACTIVE`, and a benign event appears in the dashboard.

## P1 - Security and response smoke test

- Exercise signed config, online/offline ingestion, command dispatch, allowlist rejection, result verification, reconnect, and idempotency.
- Acceptance: authorized test command completes once; tampered/retargeted command is rejected; only acknowledged offline records are deleted; audit trail is complete.

## P2 - Deployment readiness

- Replace local demo secrets, configure HTTPS for remote endpoints, define DB backup/retention, and install manager/agent as managed services.
- Acceptance: restart preserves state, health/telemetry recover automatically, secrets are not committed/logged, and rollback steps are documented.

## Working rule

Before each task read these four files. After material work, update `PLAN.md` priorities and `STATUS.md`; update architecture/contracts only when their facts change.

## Git delivery rule

- Continue this execution-hardening sequence on `feat/agent-execution-integration`; do not create another branch or modify `main` unless the operator later changes this instruction.
- Keep commits focused; review follow-ups by commit reference and `git diff`, not pasted files.
- Record the relevant test command/result before merge. Documentation-only changes require at least `git diff --check`.
- Merge only reviewed, passing changes; retain branch history with a non-fast-forward merge.
- Any storage/API schema change must include its migration, rollback/upgrade behavior, and compatibility note in `CONTRACTS.md` and `STATUS.md`.
