# ZTA Telemetry Data Flow Specification

This document maps the complete data lifecycle of endpoint events through the **ZTA (Zero Trust Architecture)** system.

---

## 1. End-to-End Pipeline Overview

```
 ┌─────────────────────────────────────────────────────────────┐
 │                      WINDOWS ENDPOINT                       │
 │  • Windows Security / PowerShell Events                     │
 │  • Sysmon Telemetry (Process, Registry, Network, File)     │
 └──────────────────────────────┬──────────────────────────────┘
                                │
                                ▼
 ┌─────────────────────────────────────────────────────────────┐
 │                      ZTA AGENT                              │
 │  • Process: zta-agent (service: ZTA Agent Service)          │
 │  • Collects logs, syscheck data, and active response state  │
 └──────────────────────────────┬──────────────────────────────┘
                                │ encrypted transport (port 1514)
                                ▼
 ┌─────────────────────────────────────────────────────────────┐
 │                 ZTA MANAGER & ANALYSIS ENGINE               │
 │  • Process: zta-analysisd / remoted                        │
 │  • Decoders: XML decoders parse raw event data              │
 │  • Ruleset: Detection rules assign level & MITRE tags       │
 └──────────────────────────────┬──────────────────────────────┘
                                │ alert stream (alerts.json / socket)
                                ▼
 ┌─────────────────────────────────────────────────────────────┐
 │                      ZTA ENGINE                             │
 │  1. ZTAEventAdapter                                         │
 │     └── Normalizes raw alert JSON into canonical ZTAEvent   │
 │  2. Behavioral Correlation Engine                           │
 │     └── Evaluates multi-event sequences within time windows │
 │  3. Dynamic Risk Engine                                     │
 │     └── Calculates 0-100 score + applies decay algorithms   │
 │  4. Continuous Trust Engine                                 │
 │  5. Adaptive Policy Engine                                  │
 │     └── Triggers isolation / active response actions        │
 └──────────────────────────────┬──────────────────────────────┘
                                │
                                ▼
 ┌─────────────────────────────────────────────────────────────┐
 │                   ZTA DASHBOARD MODULE                      │
 │  • Displays Endpoints, Risk/Trust scores, Incidents & UI    │
 └─────────────────────────────────────────────────────────────┘
```

---

## 2. Sample Pipeline Mapping (Sysmon Encoded PowerShell)

### Step 1: Endpoint Event Generation
- **Source**: Microsoft-Windows-Sysmon/Operational
- **Event ID**: 1 (Process Creation)
- **Image**: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- **CommandLine**: `powershell.exe -e aW52b2tlLWV4cHJlc3Npb24...`

### Step 2: ZTA Manager Decoding & Rule Matching
- **Decoder**: `sysmon_event1`
- **Rule ID**: `184666` (PowerShell Encoded Command Detected)
- **MITRE Tactic**: `Execution` (Technique: `T1059.001`)

### Step 3: ZTA Event Adapter Normalization
The `ZTAEventAdapter` extracts standard fields into a canonical `ZTAEvent` object:
```json
{
  "event_id": "zta-evt-982341",
  "timestamp": "2026-08-29T22:15:00Z",
  "agent": {
    "id": "001",
    "name": "WIN-TEST-01",
    "ip": "192.168.1.105"
  },
  "user": {
    "name": "testuser"
  },
  "event_type": "PROCESS_CREATION",
  "severity": "HIGH",
  "wazuh_rule": {
    "id": 184666,
    "level": 10,
    "description": "PowerShell with encoded command line"
  },
  "mitre": {
    "tactic": "Execution",
    "technique": "T1059.001"
  },
  "process": {
    "name": "powershell.exe",
    "command_line": "powershell.exe -e aW52b2tlLWV4cHJlc3Npb24...",
    "parent": "cmd.exe"
  },
  "raw_event": { ... }
}
```

### Step 4: Engine Evaluation & State Mutation
1. **Correlation Engine**: Evaluates if this PowerShell event is preceded by failed logins or followed by abnormal outbound network connections.
2. **Risk Engine**: Adds `+20` risk score delta for `WIN-TEST-01`. Risk score transitions from `10` -> `30`.
3. **Trust Engine**: Re-evaluates endpoint trust: `Trust` drops from `90` -> `70`. Rationale: *"PowerShell encoded execution detected"*.
4. **Policy Engine**: Risk level `30` matches `MONITOR / ALERT` policy state (below isolation threshold of `85`).
5. **Timeline / Incident Store**: Appends entry to the timeline for forensic traceability.
