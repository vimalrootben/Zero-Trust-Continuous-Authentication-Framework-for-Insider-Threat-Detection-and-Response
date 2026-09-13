# Plan

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
