================================================================================
ZERO TRUST EDR (ENDPOINT DETECTION & RESPONSE)
Continuous Authentication & Insider Threat Detection Platform
================================================================================

1. EXECUTIVE OVERVIEW
--------------------------------------------------------------------------------
Zero Trust EDR is an enterprise-grade, open-architecture Endpoint Detection and 
Response (EDR) platform designed around the fundamental principles of Zero Trust 
Security ("Never Trust, Always Verify").

Unlike traditional EDR solutions that rely solely on perimeter controls or periodic 
authentication, Zero Trust EDR continuously collects host telemetry, evaluates 
behavioral risk in real-time, maps activity to the MITRE ATT&CK framework, and 
dynamically enforces security policies—ranging from standard user notifications to 
full network isolation and automated process termination.

Core Philosophy:
- Continuous Verification: Authenticate endpoints, users, and sessions continuously 
  via mutual TLS (mTLS) and dynamic risk scoring.
- Least Privilege & Dynamic Policy: Adjust host capabilities and security 
  restrictions dynamically based on risk level changes (LOW, MEDIUM, HIGH, CRITICAL).
- Resilient Local Execution: Agent operates autonomously even during network disconnects, 
  caching telemetry locally in SQLite and maintaining local rule enforcement.
- Cryptographic Integrity: All manager-to-agent commands are digitally signed 
  (RSA/HMAC), preventing command spoofing or unauthorized execution.


2. ARCHITECTURE & COMPONENT DETAILS
--------------------------------------------------------------------------------
The platform consists of three main architectural tiers: Agent, Manager, and Dashboard.

  +-------------------------------------------------------------------------+
  |                               DASHBOARD                                 |
  |                React 18 + TypeScript + Vite + Tailwind CSS              |
  +------------------------------------+------------------------------------+
                                       | HTTP REST / WebSockets
                                       v
  +-------------------------------------------------------------------------+
  |                                 MANAGER                                 |
  |                      FastAPI + PostgreSQL + Redis                       |
  |                                                                         |
  |  +-------------------+  +-------------------+  +---------------------+  |
  |  |    Rules Engine   |  |    Risk Engine    |  |    Policy Engine    |  |
  |  +-------------------+  +-------------------+  +---------------------+  |
  |  |   Threat Intel    |  |  MITRE ATT&CK     |  | Command Dispatcher  |  |
  |  +-------------------+  +-------------------+  +---------------------+  |
  +------------------------------------+------------------------------------+
                                       | mTLS (HTTPS / WSS)
                                       v
  +-------------------------------------------------------------------------+
  |                                  AGENT                                  |
  |                    Windows Service / Python 3.12 Core                   |
  |                                                                         |
  |  +-------------------+  +-------------------+  +---------------------+  |
  |  |  8x Collectors    |  |  Offline Queue    |  |   Response Engine   |  |
  |  +-------------------+  +-------------------+  +---------------------+  |
  |  |  Self-Protection  |  | Local Rule Engine |  | PowerShell Executor |  |
  |  +-------------------+  +-------------------+  +---------------------+  |
  +-------------------------------------------------------------------------+

2.1 AGENT COMPONENT (/agent)
The agent runs as a native Windows service or standalone process on target endpoint 
machines.

* Collectors Layer (agent/collectors):
  - process_collector.py: Monitors process creation, termination, command lines, 
    parent-child relationships, hashes, and PE metadata.
  - service_collector.py: Tracks Windows Services creation, state changes, executable 
    paths, and startup types.
  - registry_collector.py: Monitors sensitive registry paths (Run keys, Winlogon, 
    Image File Execution Options, Services).
  - network_collector.py: Captures active socket connections, listening ports, remote 
    IPs, and domain resolutions.
  - usb_collector.py: Detects USB storage device insertions, removals, volume labels, 
    and device IDs.
  - file_collector.py: Monitors file creation, deletion, modifications in system and 
    user directories.
  - log_collector.py: Reads Windows Event Logs (Security, System, PowerShell logs).
  - login_collector.py: Monitors user authentication events, interactive logins, lock/unlock.

* Storage & Offline Queue (agent/storage):
  - offline_queue.py & local_db.py: Uses SQLite to buffer telemetry when offline, 
    ensuring 100% telemetry retention. Automatically syncs when connection is restored.

* Secure Transport (agent/communication):
  - transport.py: Handles HTTPS/mTLS connection setup, TLS 1.3 encryption, and client 
    certificate verification.
  - registration.py: Performs host onboarding, CSR/certificate exchange.
  - heartbeat.py: Sends structured heartbeat pings with host metrics every 30s.

* Response Engine (agent/responses):
  - kill_process.py: Terminates malicious processes by PID or process name.
  - network_isolation.py & firewall_rules.py: Blocks inbound/outbound traffic via Firewall.
  - logoff_user.py & lock_workstation.py: Locks session or logs off current user.
  - quarantine_file.py: Isolates suspect executable files into secure directory.

* Self-Protection (agent/selfprotection):
  - service_guard.py: Prevents unauthorized service termination or tampering.
  - file_integrity_guard.py: Monitors agent binaries and config files.
  - tamper_logger.py: Logs anti-tamper events and alerts Manager upon security bypass attempts.

2.2 MANAGER COMPONENT (/manager)
The central backend server built with FastAPI, PostgreSQL, Redis, and Alembic.

* API Layer (manager/api):
  - RESTful endpoints for auth, agents, telemetry, alerts, policies, threat intel.
  - WebSocket endpoint (/ws/telemetry) for real-time telemetry streaming & command dispatch.

* Rule Engine (manager/rules):
  - Evaluates incoming telemetry against Sigma-like detection rules (YAML/JSON).
  - Handles complex nested conditions (AND, OR, NOT, wildcards, regex).

* Risk Engine (manager/risk):
  - Calculates dynamic risk scores (0 to 100) per endpoint and per user session.
  - Time-decay algorithms reduce risk score as time passes without new threats.
  - Risk Levels: LOW (0-29), MEDIUM (30-59), HIGH (60-84), CRITICAL (85-100).

* Policy Engine (manager/policy):
  - Maps risk levels to enforced policy profiles (e.g. CRITICAL risk triggers Isolation).

* MITRE ATT&CK Mapping (manager/mitre):
  - Maps rules and alerts to MITRE ATT&CK Tactic IDs, Technique IDs (e.g. T1059.001).

* Threat Intelligence (manager/threatintel):
  - Fetches, parses, and caches external IOC feeds (IPs, Hashes, Domains).

2.3 DASHBOARD COMPONENT (/dashboard)
Administrative interface built with React 18, TypeScript, Vite, and Tailwind CSS.
- Real-time WebSocket Telemetry Feed
- Enrolled Agent Management & System Metrics
- Alert & Incident Correlation
- Interactive MITRE ATT&CK Matrix Visualization
- Policy & Detection Rule Configurator
- System Audit Trail Log


3. FULL END-TO-END WORKFLOWS
--------------------------------------------------------------------------------

3.1 AGENT ENROLLMENT & HANDSHAKE
  [Agent Host]                                              [Manager]
       |                                                        |
       |----- 1. Post Registration Request (Enrollment Key) ---->|
       |                                                        | Validates Token
       |<---- 2. Issues Signed Client Cert & Agent ID ----------|
       |                                                        |
       |----- 3. Establishes mTLS Connection (Port 8000/443) --->|
       |<---- 4. Acknowledges Secure mTLS Session --------------|

3.2 TELEMETRY INGESTION & REAL-TIME THREAT DETECTION
  [Agent Collectors] -> [Offline Queue / SQLite] -> [mTLS Transport]
                                                          |
                                                          v
                                               [FastAPI Ingestion]
                                                          |
                                                          v
                                                [Rule Engine & IOCs]
                                                          |
                                     +--------------------+--------------------+
                                     |                                         |
                              (Match Found)                              (No Match)
                                     v                                         v
                           [Generate Security Alert]                    [Store Telemetry]
                                     |
                                     v
                          [Map MITRE Tactic/Technique]
                                     |
                                     v
                         [Update Risk Score (0-100)]

3.3 AUTOMATED INCIDENT RESPONSE & POLICY ENFORCEMENT
  [Risk Engine Score > 85 (CRITICAL)]
                  |
                  v
       [Policy Engine Triggered]
                  |
                  v
    [Sign Command Payload (RSA/HMAC)]
                  |
                  v
    [Dispatch Command via WebSockets]
                  |
                  v
       [Agent Validates Signature]
                  |
                  v
  [Execute Local Response (Process Kill / Isolation)]
                  |
                  v
     [Report Execution Status to Manager]


4. REPOSITORY DIRECTORY STRUCTURE
--------------------------------------------------------------------------------
zerotrust-edr/
├── agent/                         # Windows Agent Source Code
│   ├── collectors/                # 8 Host Telemetry Collectors
│   ├── communication/             # mTLS Transport, Registration & Heartbeat
│   ├── powershell/                # PowerShell Execution Engine
│   ├── responses/                 # Automated Response Engine
│   ├── localrules/                # Local Offline Rule Engine
│   ├── network/                   # Connectivity Monitoring & Reconnect
│   ├── selfprotection/            # Service & File Tamper Protection
│   ├── startup/                   # Service Entry Points
│   ├── storage/                   # SQLite Offline Queue & Cache
│   ├── windows_service/           # PyWin32 Service Wrapper
│   └── config/                    # Agent Configuration
├── manager/                       # Backend Central Manager
│   ├── api/                       # FastAPI App & Endpoints (14 routers)
│   ├── auth/                      # Argon2, JWT & RBAC Engine
│   ├── database/                  # SQLAlchemy Models & Alembic Migrations
│   ├── threatintel/               # IOC Feed Ingestion & Matching
│   ├── risk/                      # Risk Engine, Scoring & Decay
│   ├── policy/                    # Policy Engine & Evaluation
│   ├── rules/                     # Sigma Rule Engine & Loader
│   ├── mitre/                     # MITRE ATT&CK STIX Mapping Engine
│   ├── websocket/                 # Connection Manager & Command Dispatcher
│   ├── scheduler/                 # Heartbeat & Offline Monitor
│   ├── workers/                   # Background Alert & Notification Workers
│   └── config.py                  # Server Settings & Configuration
├── dashboard/                     # Web Administration Frontend (React + Vite)
├── deployment/                    # Container & Production Scripts (Docker Compose)
├── installer/                     # Windows Installer Generation (Inno Setup)
├── scripts/                       # System Utilities (generate_certs, seed_db)
├── ZEROTRUST_EDR_BLUEPRINT.txt    # Master Architectural Specification
├── seed_db_records.py             # Root DB Seeding Script
├── .env.example                   # Environment Template
├── README.md                      # Markdown Technical Documentation
└── README.txt                     # Plain Text Documentation File


5. SETUP & OPERATING INSTRUCTIONS
--------------------------------------------------------------------------------

STEP 1: Clone Repository & Setup Virtual Environment
  $ git clone https://github.com/your-org/zerotrust-edr.git
  $ cd zerotrust-edr
  $ python -m venv .venv
  $ .\.venv\Scripts\Activate.ps1   (Windows PowerShell)
  $ source .venv/bin/activate      (Linux/macOS)

STEP 2: Install Dependencies
  $ pip install -r manager/requirements.txt

STEP 3: Configure Environment (.env)
  $ cp .env.example .env

STEP 4: Generate PKI Certificates (mTLS)
  $ python scripts/generate_certs.py

STEP 5: Start Database & Redis (Docker Compose)
  $ docker-compose -f deployment/docker-compose.yml up -d postgres redis

STEP 6: Seed Database
  $ python scripts/seed_db.py
  (Default Credentials: Admin / admin / Admin123!)

STEP 7: Start Manager Backend Server
  $ uvicorn manager.api.main:app --host 0.0.0.0 --port 8000 --reload
  (API Documentation at http://localhost:8000/docs)

STEP 8: Start Dashboard Frontend
  $ cd dashboard
  $ npm install
  $ npm run dev
  (Access interface at http://localhost:5173)

STEP 9: Install & Start Agent
  $ pip install -r agent/requirements.txt
  $ python installer/install_agent.py
  $ python -m agent.windows_service.service_entry


6. API ROUTE SUMMARY
--------------------------------------------------------------------------------
POST  /api/v1/auth/login        - Authenticate user & obtain JWT token
POST  /api/v1/auth/refresh      - Refresh expired access token
GET   /api/v1/agents            - List all enrolled host agents
POST  /api/v1/agents/register   - Host enrollment & cert exchange
GET   /api/v1/telemetry         - Query filtered endpoint telemetry
GET   /api/v1/alerts            - List triggered security alerts
PATCH /api/v1/alerts/{id}       - Acknowledge/Resolve alert
GET   /api/v1/risk/{agent_id}   - Fetch current risk score & history
GET   /api/v1/policies          - Retrieve active dynamic policies
POST  /api/v1/commands/dispatch - Send signed command payload to agent
GET   /api/v1/mitre/matrix      - Get MITRE ATT&CK coverage matrix
GET   /api/v1/audit/logs        - Fetch system administration audit trail
WS    /ws/telemetry             - WebSocket stream for live agent events


7. SECURITY & CRYPTOGRAPHIC STANDARDS
--------------------------------------------------------------------------------
- Mutual TLS (mTLS): Enforced TLS 1.3 dual-authentication between Manager & Agent.
- Password Hashing: Argon2-cffi algorithm with high memory/time costs.
- Signed Commands: RSA-4096 / HMAC digital signatures on command dispatches.
- Role-Based Access Control (RBAC): Fine-grained permission system.


8. TESTING
--------------------------------------------------------------------------------
$ pytest manager/tests -v --cov=manager
$ pytest agent/tests -v --cov=agent
================================================================================
