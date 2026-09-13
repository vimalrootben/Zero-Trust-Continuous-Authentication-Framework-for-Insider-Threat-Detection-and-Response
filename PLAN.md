# Plan

## Completed - Bounded regex evaluation

- Limited regex pattern and input sizes and enforced a 25 ms timeout using the timeout-capable `regex` engine.
- Acceptance: expensive patterns terminate with traceable safe-false results; normal regex matches and all 132 tests pass.

## Completed - Safe rule activation

- Enforced rule field types, enums, risk bounds, operand types, and condition-tree complexity before create, update, or activation.
- Acceptance: invalid rules are rejected without persistence; valid seeded/existing workflows pass all 129 tests.

## Completed - Authenticated permission access

- Added operator creation, password login, expiring sessions, role permissions, protected reads/writes/streams, and authenticated dashboard session flow.
- Acceptance: unauthorized access returns 401; insufficient permissions return 403; permitted workflows and unchanged agent authentication pass the 116-test suite.

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

- Start each bounded change from `main` on a dedicated branch (`fix/`, `feat/`, `docs/`, or `chore/`).
- Keep commits focused; review follow-ups by commit reference and `git diff`, not pasted files.
- Record the relevant test command/result before merge. Documentation-only changes require at least `git diff --check`.
- Merge only reviewed, passing changes; retain branch history with a non-fast-forward merge.
- Any storage/API schema change must include its migration, rollback/upgrade behavior, and compatibility note in `CONTRACTS.md` and `STATUS.md`.
