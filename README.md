# Zero Trust Architecture (ZTA) Platform

A lightweight, high-performance Zero Trust Endpoint Detection & Response (EDR) platform derived from Wazuh architecture. The repository has been streamlined from over 6,500 upstream files down to **98 focused files** (~98.5% reduction), eliminating unused C/C++ daemons, legacy wrappers, and redundant workflows while preserving **100% of the active Python ZTA runtime, detection rules, adaptive policies, SQLite persistence, PowerShell response scripts, web dashboard, and test suites**.

---

## Repository Structure

```text
.
├── agent/                         # Endpoint Agent Subsystem
│   ├── commands/                  # Command authorization & receiver
│   │   ├── __init__.py
│   │   ├── authorization.py       # HMAC validation & token authorization
│   │   └── command_receiver.py    # Command loop & execution dispatch
│   ├── execution/                 # Safe script execution engine
│   │   ├── __init__.py
│   │   ├── execution_result.py    # Structured result dataclass
│   │   ├── executor.py            # Consolidated demo script executor
│   │   ├── script_executor.py     # Controlled execution handler
│   │   ├── script_registry.py     # Allowlisted benign test scripts
│   │   └── validators.py          # Input & parameter sanitizers
│   ├── rules/                     # Local agent-side detection
│   │   ├── __init__.py
│   │   └── local_rule_engine.py   # Offline rule matching engine
│   ├── storage/                   # Agent local persistence
│   │   ├── __init__.py
│   │   └── offline_queue.py       # SQLite offline event queue & journal
│   ├── __init__.py
│   ├── __main__.py                # python -m agent entry point
│   ├── agent_daemon.py            # Background agent loop & heartbeats
│   ├── collectors.py              # Windows wevtutil / Sysmon event collectors
│   ├── network_identity.py        # Hostname & IP detection
│   └── state.py                   # Agent lifecycle & sync state machine
├── api/                           # Manager REST & Ingestion API
│   ├── __init__.py
│   ├── __main__.py                # python -m api entry point
│   ├── background.py              # Background worker thread & service monitor
│   ├── ingestion.py               # Bulk telemetry ingestion & durable staging
│   └── server.py                  # HTTP/WebSocket API server routes
├── dashboard/                     # Web User Interface
│   ├── assets/
│   │   ├── dashboard.css          # Glassmorphism dark/light design system
│   │   └── dashboard.js           # Real-time SPA, charts, modal controls
│   ├── __init__.py
│   ├── index.html                 # Single-page application HTML
│   └── run_dashboard.py           # Standalone dashboard server launcher
├── docs/                          # Architecture & Verification Documentation
│   ├── BACKGROUND_COMPLETION_REPORT.md  # Detailed verification report
│   ├── BASELINE.md                # System baseline documentation
│   ├── INSTALLATION.md            # Deployment & setup procedures
│   ├── README.md                  # Documentation index
│   ├── WAZUH_DATA_FLOW.md         # Event pipeline mapping
│   ├── WINDOWS_VALIDATION.md      # Windows endpoint validation guide
│   └── ZTA_DATA_FLOW.md           # End-to-end data flow specifications
├── engine/                        # Core Processing & Decision Pipeline
│   ├── correlation/               # Real-time event correlation
│   │   ├── __init__.py
│   │   └── engine.py              # Multi-event sliding window correlator
│   ├── events/                    # Event models & condition evaluators
│   │   ├── __init__.py
│   │   ├── conditions.py          # Tree condition evaluator (AND/OR/NOT)
│   │   ├── models.py              # TelemetryEvent dataclass & schema
│   │   ├── serialization.py       # JSON/dict event parsers
│   │   └── wazuh_adapter.py       # Wazuh alerts/Sysmon adapter
│   ├── policy/                    # Adaptive policy enforcement
│   │   ├── __init__.py
│   │   └── engine.py              # Risk-based policy evaluator
│   ├── response/                  # Active response orchestrator
│   │   ├── __init__.py
│   │   ├── command_builder.py     # Signed command payload builder
│   │   └── engine.py              # Response action decision engine
│   ├── risk/                      # Dynamic risk score engine
│   │   ├── __init__.py
│   │   └── engine.py              # Agent risk score & decay calculator
│   ├── trust/                     # Zero Trust score engine
│   │   ├── __init__.py
│   │   └── engine.py              # Dynamic trust score evaluator
│   ├── __init__.py
│   └── pipeline.py                # Unified manager processing pipeline
├── etc/                           # Configuration Templates
│   └── zta.conf                   # Default daemon & manager configuration
├── manager/                       # Manager Orchestration
│   ├── __init__.py
│   └── __main__.py                # python -m manager entry point
├── powershell/                    # Windows Active Response System
│   ├── scripts/                   # Production PowerShell response scripts
│   │   ├── kill_process.ps1       # Process termination with ownership checks
│   │   ├── logoff_user.ps1        # WTS session termination & verification
│   │   └── network_isolation.ps1  # Endpoint isolation script
│   ├── __init__.py
│   ├── ps_executor.py             # Script runner with output capture
│   └── windows_sessions.py        # WTS query & session identity validation
├── ruleset/                       # Detection & Test Content
│   └── demo_rules.json            # MITRE ATT&CK & benign demo rule definitions
├── scripts/                       # Verification & Demo Framework
│   └── demo/
│       ├── cleanup_demo.py        # Demo artifact cleanup
│       ├── trigger_file_test.py   # Safe file modify/create trigger
│       ├── trigger_full_pipeline_test.py # End-to-end pipeline test trigger
│       ├── trigger_listening_port_test.py # Safe socket listener trigger
│       ├── trigger_network_test.py # Safe network connection trigger
│       └── trigger_process_test.py # Safe benign process trigger
├── storage/                       # Relational Database Storage
│   ├── __init__.py
│   └── database.py                # SQLite schema, migrations & repository
├── tests/                         # Automated Pytest Suite (113 tests)
│   ├── conftest.py                # Shared fixtures & test database setup
│   ├── http_support.py            # Ephemeral HTTP server test fixtures
│   ├── test_adapter.py            # Wazuh adapter & event parsing tests
│   ├── test_agent_daemon.py       # Agent lifecycle & collector tests
│   ├── test_agent_engine.py       # Agent execution & installer tests
│   ├── test_background_completion.py # Pipeline completion & evidence tests
│   ├── test_dashboard_integration.py # Dashboard API & WebSocket tests
│   ├── test_demo_framework_and_analytics.py # Safe execution & analytics tests
│   ├── test_full_pipeline.py      # End-to-end event evaluation tests
│   ├── test_powershell_executor.py # PowerShell active response tests
│   ├── test_real_logic_regressions.py # Regression & logic safety tests
│   ├── test_rules_policies_management.py # Rule/policy CRUD & condition tests
│   ├── test_storage_api.py        # Database migration & storage tests
│   └── test_zta_end_to_end_scenarios.py # Multi-agent incident scenarios
├── README.md                      # Primary project guide (this file)
├── __init__.py
├── __main__.py                    # python -m zta entry point
├── install-unified-manager.sh     # Linux unified manager install script
├── install-zta-agent.ps1          # Windows agent PowerShell installer
├── install-zta.sh                 # Fast installation shell script
├── pyproject.toml                 # Project metadata & pytest configuration
├── requirements.txt               # Python package dependencies
├── zta.py                         # Root launcher script
├── zta_agent.py                   # Agent CLI runner
├── zta_manager.py                 # Manager CLI runner
└── zta_windows_installer.py       # Windows agent installation helper
```

---

## Quick Start

### 1. Requirements
- Python 3.11+
- SQLite 3.35+
- Node.js (optional, for dashboard JavaScript validation)
- PowerShell 5.1+ (for Windows agent active responses)

### 2. Install & Start Manager

```bash
# Set up virtual environment and install dependencies
bash install-zta.sh

# Run the unified manager (starts dashboard and agent API)
.venv/bin/python -m zta --port 8000 --api-port 8080 --db zta_runtime.db
```

- **Dashboard UI**: `http://127.0.0.1:8000`
- **Agent API & Ingestion**: `http://127.0.0.1:8080`
- **WebSocket Feed**: `ws://127.0.0.1:8000/api/zta/ws`

Both services share the underlying background worker, SQLite database, and real-time WebSocket hub.

### 3. Environment Variables

Configure manager security credentials in the service environment:

- `ZTA_ADMIN_TOKEN`: Administrator bearer token for rule/policy mutations and manual command dispatches.
- `ZTA_AGENT_TOKENS`: JSON string mapping each provisioned Agent ID to its secret token (e.g. `{"agent-01": "secret-token-123"}`).
- `ZTA_RISK_DECAY_PER_MINUTE`: Decay rate per minute for accumulated risk scores (default: `1.0`).
- `DEMO_MODE_ENABLED`: Enable benign controlled test script executions (`true`/`false`).

---

## Windows Agent Deployment

Run the automated agent installer from an Administrator PowerShell prompt on the target Windows endpoint:

```powershell
.\install-zta-agent.ps1 -ManagerUrl 'https://YOUR-MANAGER:8080' -AgentId 'agent-win-01'
```

The script configures a dedicated Python virtual environment, secures ACLs for `SYSTEM` and `Administrators`, prompts securely for the agent authentication token, and registers a persistent Windows Scheduled Task (`ZTA Endpoint Agent`) executing as `SYSTEM`.

Alternatively, start the agent daemon manually:

```powershell
python -m zta.agent.agent_daemon --config 'C:\Program Files\ZTA Agent\config\zta_agent.env'
```

### Event Collection
The Windows agent collector monitors native event channels via `wevtutil`:
- **Microsoft-Windows-Sysmon/Operational**
- **Security** (4624 Logon, 4625 Failed Logon, 4688 Process Creation, etc.)
- **Microsoft-Windows-PowerShell/Operational** (4104 Script Block Execution)
- **System** and **Application**

Events are stored durably in the agent's local SQLite database before checkpoint advancement, ensuring zero telemetry loss during network disconnects.

---

## Zero Trust Processing Pipeline

```text
Telemetry Event
  │
  ▼
Durable SQLite Storage (Ingestion Stage)
  │
  ▼
Background Worker Dispatcher
  │
  ├──► Condition Tree Evaluator (AND / OR / NOT)
  │      └── Matched Detection Rule
  │
  ├──► Dynamic Risk & Trust Engine
  │      ├── Risk Score Increment & Natural Decay
  │      └── Trust Score Calculation
  │
  ├──► Adaptive Policy Evaluator
  │      ├── Linked-Rule Priority / Risk-Range Check
  │      └── Action Decision (MONITOR / ENFORCE / ALERT_ONLY)
  │
  └──► Response Orchestration
         ├── Predefined Allowlisted Command Builder
         ├── HMAC Signing & Identity Validation
         ├── Dispatch to Endpoint Agent
         └── Execution & Verification (Post-Action Status Check)
```

---

## Active Response Security Controls

1. **User Session Logoff (`LOGOFF_USER`)**:
   - Requires actual username and valid Windows Terminal Services (WTS) Session ID.
   - Verifies session ownership before calling `logoff.exe`.
   - Post-execution verification queries WTS sessions to confirm `SESSION_NOT_ACTIVE`.
2. **Process Termination (`KILL_PROCESS`)**:
   - Requires exact matching Process ID (PID) and executable name.
   - Validates process ownership and monitors exit.
   - Verified only upon confirmation of `PROCESS_NOT_ACTIVE`.
3. **Network Isolation (`NETWORK_ISOLATION`)**:
   - Applies firewall containment rules while preserving manager connectivity for ongoing command and control.
4. **Command Allowlist & Security**:
   - Arbitrary PowerShell commands are strictly rejected.
   - All dispatches must match registered command IDs and carry valid HMAC authorizations within a 5-minute validity window.

---

## Offline Protection & Reconnect Sync

- **Signed Policy Cache**: Agents cache active rules and policies locally during periodic heartbeats.
- **Offline Enforcement**: Permitted only for rules and policies explicitly marked `allow_offline=true` in `ENFORCE` mode.
- **Durable Offline Queue**: Telemetry generated during disconnects is journaled in the local SQLite queue (`storage/offline_queue.py`).
- **Atomic Reconnect Sync**: Upon reconnection, cached events and execution receipts are uploaded in atomic batches to `POST /api/v1/sync/offline`. Confirmed batches are acknowledged and purged cleanly without duplicate alert triggers.

---

## REST API Reference

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/v1/agents/heartbeat` | `POST` | Agent heartbeat, signed policy distribution, and pending command retrieval |
| `/api/v1/telemetry/bulk` | `POST` | Authenticated bulk telemetry ingestion with durable acceptance |
| `/api/v1/sync/offline` | `POST` | Atomic batch upload for offline event queues and execution receipts |
| `/api/v1/commands/result` | `POST` | Endpoint execution results with verification status |
| `/api/zta/commands` | `POST` | Administrator manual command dispatch to target agents |
| `/api/zta/rules` | `GET`, `POST` | Query or register detection and correlation rules |
| `/api/zta/policies` | `GET`, `POST`| Query or register adaptive zero trust policies |
| `/api/zta/incidents/{id}` | `GET` | Retrieve complete forensic chain for an incident |
| `/api/zta/background-services` | `GET` | Real-time health, heartbeats, and worker states |
| `/api/zta/ws` | `GET` | WebSocket live stream of events, alerts, commands, and metrics |

---

## Verification & Testing

The platform includes an automated regression test suite covering all engines, agents, PowerShell handlers, and dashboard APIs:

```bash
# Run complete test suite (113 tests)
PYTHONPATH=. .venv/bin/pytest -q

# Validate Dashboard JavaScript syntax
node --check dashboard/assets/dashboard.js

# Compile all Python source files
python3 -m compileall -q . -x '\.venv'
```

For detailed background completion reports and Windows endpoint verification procedures, refer to:
- [docs/BACKGROUND_COMPLETION_REPORT.md](docs/BACKGROUND_COMPLETION_REPORT.md)
- [docs/WINDOWS_VALIDATION.md](docs/WINDOWS_VALIDATION.md)
- [docs/ZTA_DATA_FLOW.md](docs/ZTA_DATA_FLOW.md)
