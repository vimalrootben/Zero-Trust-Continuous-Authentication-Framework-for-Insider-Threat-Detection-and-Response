# Controlled Windows validation — not yet executed

Status: **REQUIRES REAL WINDOWS AGENT TEST**. Linux tests mock the action executor
only in the test suite. No live logout success has been asserted.

1. Use an owned disposable Windows VM with a non-administrator interactive test
   account, VM console access and no unsaved work. Install Sysmon and enable the
   relevant audit channels. Provision a unique agent credential and trusted TLS.
2. Install with `install-zta-agent.ps1`; confirm the SYSTEM scheduled task runs,
   authenticated heartbeats arrive, and endpoint collector errors are empty.
3. Generate benign process, network, file and authentication activity. Confirm
   the preserved source XML, timestamps and record IDs, and inspect true/false
   condition traces. Confirm a normal event creates no rule-match alert.
4. Review the existing rule and policy conditions. Do not substitute a made-up
   rule ID. Capture an actual triggering event with the intended account's exact
   WTS session ID. Missing/ambiguous session identity must block logout.
5. First set the selected existing policy to ALERT_ONLY in the controlled test
   database; verify a recommendation is recorded with no dispatched command.
6. With ENFORCE approved for the VM, verify rule -> match -> risk -> alert ->
   policy -> signed command -> target endpoint -> actual logout. Confirm WTS
   enumeration no longer contains that session before manager SUCCESS. Export
   the alert-specific evidence and associated audit, including original times.
7. Repeat wrong username/session, expired authorization and failed WTS query
   cases; they must report failure and never fabricated success.
8. Disconnect manager connectivity. Confirm collection/checkpoints/queue growth
   continue. Without valid offline approval/cache, no local action may execute.
9. To test offline logout, explicitly approve the existing linked rule and policy
   for offline execution **in this test environment**. Capture real local match,
   policy, command result and audit; verify the target session actually disappears.
10. Restore connectivity. Verify signed configuration refresh, queue drain,
    AGENT_OFFLINE provenance, original timestamps, verification and synced_at.
    Retry the same batch and confirm every record count remains unchanged.
11. Restart the agent during a controlled action test. An interrupted unknown
    action outcome must never cause the same command to execute twice. Confirm
    retained results upload after connectivity returns.
12. Keep one dashboard open on port 8000 while the agent uses the other listener;
    confirm real event/state/result updates. Close all dashboard tabs and repeat
    detection to establish that processing remains independent of the UI.

Record the Windows build, Python version, Sysmon version/configuration, channel
permissions, service account, source event, policy/rule versions, actual WTS
session ID, command ID and exported manager chain. Redact secrets. Do not mark
these steps passed until observed on the real VM.
