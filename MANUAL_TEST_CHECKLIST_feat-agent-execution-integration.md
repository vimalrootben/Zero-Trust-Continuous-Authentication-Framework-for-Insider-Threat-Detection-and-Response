# Disposable Manual Test Checklist — feat/agent-execution-integration

Delete this file after acceptance testing is complete. Run all endpoint-destructive sections from an elevated PowerShell terminal on a disposable Windows VM with console access. Never use a production account, process, session, or endpoint.

## Test record

- Tester: ____________________
- Date/time: ____________________
- Commit: `ffda7d9` or later: ____________________
- VM snapshot/checkpoint: ____________________
- Manager address and port: ____________________
- Agent ID: ____________________
- Disposable local username: ____________________

## 0. Preconditions and recovery

- [ ] Confirm branch: `git branch --show-current` prints `feat/agent-execution-integration`.
- [ ] Confirm clean source state: `git status --short` has no unexpected changes.
- [ ] Take a VM snapshot and confirm the VM console remains accessible without networking.
- [ ] Confirm Sysmon is installed: `Get-Service Sysmon64,Sysmon -ErrorAction SilentlyContinue` shows one running service.
- [ ] Create a disposable non-admin local account and record its password securely.
- [ ] Confirm the manager URL, manager IP/hostname, and manager TCP port are correct.
- [ ] Keep this emergency unisolate command ready in a second elevated console:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\powershell\scripts\network_isolation.ps1 -Action UNISOLATE -ManagerIP '<MANAGER_IP_OR_HOST>' -ManagerPort <MANAGER_PORT>
```

- [ ] Start the manager in terminal 1 using the project environment/configuration:

```powershell
C:\Users\vegeta\zta-venv\Scripts\python.exe .\zta_manager.py
```

- [ ] Start the agent as Administrator in terminal 2 with its real agent ID/token and manager URL:

```powershell
C:\Users\vegeta\zta-venv\Scripts\python.exe .\zta_agent.py --manager-url http://127.0.0.1:8080 --agent-id <AGENT_ID> --token <AGENT_TOKEN>
```

- [ ] Open `http://127.0.0.1:8000`, sign in, and verify the agent becomes ACTIVE.
- [ ] Record starting database backup/snapshot location: ____________________

## 1. Live telemetry and dashboard

- [ ] Processes displays real PID, name, path, user/domain, creation time, parent PID, and status.
- [ ] Sessions displays real WTS session ID, user/domain, state, and observation time.
- [ ] Listening/open ports displays real port, protocol, local address, PID, process, state, and observation time.
- [ ] Network state displays enabled/isolated/firewall/manager-connectivity values from the agent heartbeat.
- [ ] Execution history displays command, target, start time, result, verification, and failure reason.
- [ ] Alerts and audit records update without refreshing after a real new event.
- [ ] Stop and restart a benign process; confirm inventory changes on the next heartbeat.
- [ ] Open a temporary listener, confirm it appears, close it, and confirm it disappears after the next snapshot.

## 2. Manager-signed manual allowlisted script

- [ ] In Manual Script Execution, select the real agent and an existing benign allowlisted script.
- [ ] Submit valid parameters; record command ID and correlation ID: ____________________
- [ ] Confirm manager status proceeds through queued/dispatched to a terminal result.
- [ ] Confirm the agent journal contains the same command ID, action, verification, timestamp, and result.
- [ ] Confirm execution history reports the real verification marker.
- [ ] Resubmit/replay the exact signed command ID and confirm the underlying action executes only once.
- [ ] Attempt an unknown script ID and confirm it is rejected before execution.
- [ ] Attempt invalid/injection-style parameters and confirm validation rejects them.
- [ ] Confirm `DEMO_AUTH_EVENT` returns `UNAVAILABLE`, not simulated success.

## 3. Signed-command validation order

- [ ] Tamper with a signed command payload and confirm signature rejection with no journaled execution side effect.
- [ ] Send a validly signed command for a different agent ID and confirm rejection.
- [ ] Send an expired validly signed command and confirm rejection.
- [ ] Send an allowlisted action with invalid payload fields and confirm rejection.
- [ ] Send a valid command and confirm it reaches the single canonical dispatcher and produces durable evidence.

## 4. Agent self-detection exclusion

- [ ] Observe the known legitimate agent process during several collection intervals.
- [ ] Confirm the agent's own PID/activity is not classified as a threat.
- [ ] Start a separate child/neighbor test process that matches an enabled test rule.
- [ ] Confirm the narrow self exclusion does not suppress that separate process or its evidence.

## 5. Process termination

- [ ] Start a disposable process such as `Start-Process powershell.exe -ArgumentList '-NoProfile','-Command','Start-Sleep 600' -PassThru` and record PID/path/creation time.
- [ ] Trigger/dispatch `KILL_PROCESS` through the manager-signed flow using that exact identity.
- [ ] Confirm verification is `PROCESS_NOT_ACTIVE`, the PID is absent, and audit/evidence is durable.
- [ ] Nonexistent PID: confirm failure and no unrelated process is affected.
- [ ] PID reuse/stale creation time: confirm fail-closed identity mismatch.
- [ ] Wrong executable path/name: confirm fail-closed identity mismatch.
- [ ] Protected agent/system/security process: confirm refusal without attempting termination.
- [ ] Let the disposable process exit during handling; confirm a safe terminal result and no other PID is killed.

## 6. Exact Windows session logout

- [ ] Sign in the disposable non-admin account and record its WTS session ID.
- [ ] Dispatch logout with exact username/domain/session ID; confirm ownership revalidation, logout, `SESSION_NOT_ACTIVE`, and audit evidence.
- [ ] Username only with exactly one matching session: confirm successful exact resolution.
- [ ] Unknown username: confirm zero-match failure.
- [ ] Create two sessions for the same disposable username if the test VM supports it; username-only request must fail as ambiguous.
- [ ] Supply a session ID belonging to another account; confirm ownership mismatch and no logout.

## 7. Local account containment

- [ ] Confirm the disposable account is enabled and record its starting state.
- [ ] Dispatch `LOCK_LOCAL_ACCOUNT`; confirm the real account becomes disabled and verification reports `LOCAL_ACCOUNT_DISABLED`.
- [ ] Confirm existing sessions are not implicitly logged out unless a separate explicit logout policy/action was requested.
- [ ] Dispatch `UNLOCK_LOCAL_ACCOUNT`; confirm the saved prior state is restored and verification reports enabled/restored state.
- [ ] Repeat lock/unlock and confirm reversible, predictable behavior.
- [ ] Attempt Administrator, SYSTEM, service, agent account, and machine-account targets; confirm refusal.
- [ ] Attempt a domain identity; confirm the local-only action fails closed.

## 8. Offline safe enforcement and synchronization

- [ ] Cache a currently signed, unexpired rule and ENFORCE policy that both allow offline execution of one benign allowlisted script.
- [ ] Disconnect the agent from the manager and confirm agent state becomes OFFLINE.
- [ ] Generate the matching local event and confirm policy/action executes exactly once.
- [ ] Confirm detection and execution evidence remain in the local durable queue/journal.
- [ ] Replay the same command/event identity and confirm no duplicate execution.
- [ ] Test expired cache, `allow_offline=false`, ALERT_ONLY, wrong action, and arbitrary command; each must fail closed.
- [ ] Confirm offline process kill, logout, and account containment remain disabled.
- [ ] Reconnect the manager and confirm evidence synchronizes in order with correlation preserved.
- [ ] Confirm only acknowledged records are marked synced/removed; simulate a failed acknowledgement and verify records remain queued.
- [ ] Reconnect/retry again and confirm no duplicate manager execution or evidence loss.

## 9. Repeated alerts and status

- [ ] Generate the exact same continuing detection at least three times.
- [ ] Confirm only one active alert/incident exists for the fingerprint.
- [ ] Confirm `first_seen` remains unchanged, `last_seen` advances, and occurrence count increments.
- [ ] Confirm each underlying event/rule/risk/audit evidence record remains present.
- [ ] Confirm the alert displays ACTIVE / NOT RESOLVED while detections continue.
- [ ] Acknowledge it as SOC; confirm acknowledgement does not mark it resolved.
- [ ] Stop generating the detection and verify transition follows the existing resolution logic.

## 10. Admin-only Clear DB

- [ ] As a SOC analyst, request/execute database clear and confirm HTTP/UI authorization rejection.
- [ ] As ADMIN, request a confirmation token and confirm it is strong, actor-bound, short-lived, and not static.
- [ ] Try an invalid token and confirm rejection with no deletion.
- [ ] Use the valid token once and confirm the intended operational tables clear.
- [ ] Reuse the token and confirm rejection.
- [ ] Obtain another token, let it expire, and confirm rejection.
- [ ] Confirm the successful clear operation is re-recorded in the audit mechanism.

## 11. Network isolation — VM console only

Leave `ZTA_ENABLE_NETWORK_ISOLATION` unset/false first.

- [ ] Request isolation and confirm `UNAVAILABLE` with no firewall mutation.
- [ ] From the VM console, set `ZTA_ENABLE_NETWORK_ISOLATION=true` for the agent test process and restart it.
- [ ] Dispatch isolation with the exact manager host/IP and port.
- [ ] Confirm uniquely named `ZTA-Isolation-*` rules exist, all profiles use outbound block, and manager connectivity still works.
- [ ] Confirm IPv4/IPv6 manager addresses, DNS, DHCPv4, and DHCPv6 allowances are present as applicable.
- [ ] Confirm state/rollback JSON exists under `%ProgramData%\ZTA` and dashboard shows isolated/firewall/connectivity state.
- [ ] Repeat isolate and confirm idempotent `ALREADY_ISOLATED` success without duplicate rules.
- [ ] Restart the agent and confirm recovery/state reporting remains consistent.
- [ ] Dispatch unisolate and confirm prior profile/rule state is restored, ZTA rules/state are removed, and verification succeeds.
- [ ] Repeat unisolate and confirm idempotent `ALREADY_UNISOLATED` success.
- [ ] Force a safe validation/reachability failure in a restored VM snapshot; confirm automatic rollback and rollback verification.
- [ ] Test the emergency local unisolate command from section 0.

Do not enable isolation on a remotely accessed machine or without a verified VM console and snapshot.

## 12. Final evidence and cleanup

- [ ] Confirm every real execution has command ID, correlation ID, action, result, verification, timestamp, and failure reason where applicable.
- [ ] Confirm dashboard, command journal, manager commands, incident chain, and audit records agree.
- [ ] Run the automated suite:

```powershell
C:\Users\vegeta\zta-venv\Scripts\python.exe -B -m pytest -q -p no:cacheprovider --basetemp C:\Users\vegeta\zta-manual-acceptance-temp tests
```

- [ ] Expected baseline: `176 passed` (or a documented higher passing count after later commits).
- [ ] Confirm firewall is unisolated and the disposable account is restored or deleted.
- [ ] Stop manager/agent test processes and confirm ports 8000/8080 are closed if no longer needed.
- [ ] Save screenshots/logs/command IDs needed for acceptance.
- [ ] Delete this checklist after sign-off: `MANUAL_TEST_CHECKLIST_feat-agent-execution-integration.md`.

## Sign-off

- [ ] PASS — all required checks completed.
- [ ] CONDITIONAL PASS — exceptions documented below.
- [ ] FAIL — rollback to the last phase checkpoint.

Exceptions/evidence locations:

______________________________________________________________________________

______________________________________________________________________________
