# Execution Integration Progress (Temporary)

Branch: `feat/agent-execution-integration`

Status markers: `[ ]` pending, `[-]` in progress, `[x]` complete.

## Baseline and analysis

- [x] Create one dedicated branch for the complete integration.
- [x] Trace existing command signing, receipt, validation, execution, reporting, and deduplication.
- [x] Trace offline cached-policy evaluation, execution, queuing, and reconnect acknowledgement.
- [x] Trace process, file, and network collectors into the canonical event/risk/policy pipeline.
- [x] Identify references to `executor.py` before retiring the duplicate implementation.
- [x] Locate every `DEMO_MODE_ENABLED` and production-path demo classification reference.

## Production command path

- [x] Remove the `DEMO_MODE_ENABLED` gate from `script_executor.py`, `validators.py`, and configuration/environment references.
- [x] Preserve the existing allowlisted script IDs and PowerShell template allowlist.
- [x] Make manager-signed commands flow through `AgentCommandReceiver` exactly once.
- [x] Enforce signature, `agent_id`, expiry, payload validation, then execution in that order.
- [x] Treat `DEMO_SCRIPT` as a normal allowlisted production action without weakening controls.
- [x] Consolidate execution on `script_executor.py`, `script_registry.py`, and `validators.py`.
- [x] Remove or explicitly retire duplicate `executor.py` after reference analysis.

## Offline enforcement and telemetry

- [x] Route disconnected execution through the existing signed cached-policy path.
- [x] Enforce `allow_offline`, policy action, and policy expiry; reject arbitrary offline commands.
- [x] Connect process collection to event -> rule -> risk -> policy -> command execution.
- [x] Connect file monitoring to the same path and preserve offline queuing.
- [x] Connect network connections/listening ports to the same path and preserve offline storage.

## Execution, verification, and evidence

- [x] Verify intended state after each PowerShell execution while preserving process/session checks.
- [x] Record execution success/failure and verification result in reports.
- [x] Implement `NETWORK_ISOLATION`: isolation, manager reachability, verification, idempotency, rollback/unisolate, and timeout/failure handling.
- [x] Durably journal command ID, correlation ID, action, result, verification, timestamp, and failure reason.
- [x] Prevent duplicate execution of the same signed command.
- [x] Queue offline detection/execution evidence and sync in order on reconnect.
- [x] Mark only manager-acknowledged evidence as synced while preserving correlation.

## Verification and documentation

- [x] Add manager-sign -> receive -> validate -> execute -> verify -> journal end-to-end test.
- [x] Add offline event -> signed policy -> execute once -> reconnect -> acknowledged sync test.
- [x] Add duplicate-command rejection test.
- [x] Run focused tests after each bounded change and the full regression suite at completion (`172 passed in 78.89s`).
- [x] Update `ARCHITECTURE.md`, `CONTRACTS.md`, `PLAN.md`, and `STATUS.md` after material changes.
- [x] Remove production-path demo terminology. Retain this temporary tracker through review, then delete it before merge.
