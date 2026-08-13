# Zero Trust EDR (Endpoint Detection & Response)
## Continuous Authentication & Insider Threat Detection Platform

---

## 📋 Executive Overview

**Zero Trust EDR** is an enterprise-grade, open-architecture Endpoint Detection and Response (EDR) platform designed around the fundamental principles of **Zero Trust Security** ("Never Trust, Always Verify").

Unlike traditional EDR solutions that rely solely on perimeter controls or periodic authentication, Zero Trust EDR continuously collects host telemetry, evaluates behavioral risk in real-time, maps activity to the **MITRE ATT&CK® framework**, and dynamically enforces security policies—ranging from standard user notifications to full network isolation and automated process termination.

### Core Philosophy
1. **Continuous Verification**: Authenticate endpoints, users, and sessions continuously via mutual TLS (mTLS) and dynamic risk scoring.
2. **Least Privilege & Dynamic Policy**: Adjust host capabilities and security restrictions dynamically based on risk level changes (LOW, MEDIUM, HIGH, CRITICAL).
3. **Resilient Local Execution**: Agent operates autonomously even during network disconnects, caching telemetry locally in SQLite and maintaining local rule enforcement.
4. **Cryptographic Integrity**: All manager-to-agent commands are digitally signed (RSA/HMAC), preventing command spoofing or unauthorized execution.

---

## 🏗️ Architecture & Component Details

The platform consists of three main architectural tiers: **Agent**, **Manager**, and **Dashboard**.

```
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
```

---

### 1. Agent Component (`/agent`)
The agent runs as a native Windows service or standalone process on target endpoint machines.

* **Collectors Layer (`agent/collectors`)**:
  * `process_collector.py`: Monitors process creation, termination, command lines, parent-child relationships, hashes, and PE metadata.
  * `service_collector.py`: Tracks Windows Services creation, state changes, executable paths, and startup types.
  * `registry_collector.py`: Monitors sensitive registry paths (Run keys, Winlogon, Image File Execution Options, Services).
  * `network_collector.py`: Captures active socket connections, listening ports, remote IPs, and domain resolutions.
  * `usb_collector.py`: Detects USB storage device insertions, removals, volume labels, and device IDs.
  * `file_collector.py`: Monitors file creation, deletion, modifications in system and user directories.
  * `log_collector.py`: Reads Windows Event Logs (Security, System, PowerShell operational logs).
  * `login_collector.py`: Monitors user authentication events, interactive logins, lock/unlock state.

* **Storage & Offline Queue (`agent/storage`)**:
  * `offline_queue.py` & `local_db.py`: Uses SQLite to buffer telemetry when offline, ensuring 100% telemetry retention. Automatically syncs when connection to the Manager is restored.

* **Secure Transport (`agent/communication`)**:
  * `transport.py`: Handles HTTPS/mTLS connection setup, TLS 1.3 encryption, and client certificate verification.
  * `registration.py`: Performs host onboarding, CSR/certificate exchange, and registration key verification.
  * `heartbeat.py`: Sends structured heartbeat pings with host metrics (CPU, RAM, Disk, Uptime) every 30s.

* **Response Engine (`agent/responses`)**:
  * `kill_process.py`: Terminates malicious processes by PID or process name.
  * `network_isolation.py` & `firewall_rules.py`: Blocks inbound/outbound network traffic using Windows Firewall.
  * `logoff_user.py` & `lock_workstation.py`: Locks endpoint session or logs off current user.
  * `quarantine_file.py`: Isolates suspect executable files into secure quarantine directory.

* **Self-Protection (`agent/selfprotection`)**:
  * `service_guard.py`: Prevents unauthorized service termination or tampering.
  * `file_integrity_guard.py`: Monitors agent binaries and config files against modification.
  * `tamper_logger.py`: Logs anti-tamper events and alerts Manager upon security bypass attempts.

---

### 2. Manager Component (`/manager`)
The central backend server built with FastAPI, PostgreSQL, Redis, and Alembic.

* **API Layer (`manager/api`)**:
  * RESTful endpoints for authentication, agent control, telemetry querying, alert management, policy distribution, and threat intelligence.
  * WebSocket endpoint (`/ws/telemetry`) for real-time telemetry streaming and live command dispatching.

* **Rule Engine (`manager/rules`)**:
  * Evaluates incoming telemetry against Sigma-like detection rules written in YAML/JSON.
  * Evaluates complex nested logical conditions (`AND`, `OR`, `NOT`, wildcard matching, regex).

* **Risk Engine (`manager/risk`)**:
  * Calculates dynamic risk scores (0 to 100) per endpoint and per user session.
  * Implements time-decay algorithms (`decay.py`) to reduce risk score as time passes without new threats.
  * Categorizes risk into levels: `LOW` (0-29), `MEDIUM` (30-59), `HIGH` (60-84), `CRITICAL` (85-100).

* **Policy Engine (`manager/policy`)**:
  * Maps risk levels to enforced policy profiles (e.g., CRITICAL risk automatically triggers Network Isolation & Process Kill).

* **MITRE ATT&CK Mapping (`manager/mitre`)**:
  * Maps rules and alerts to MITRE ATT&CK Tactic IDs, Technique IDs (e.g., `T1059.001`), and Sub-techniques.

* **Threat Intelligence (`manager/threatintel`)**:
  * Fetches, parses, and caches external IOC feeds (IPs, Hashes, Domains).
  * Automatically flags telemetry matching known indicators of compromise.

---

### 3. Dashboard Component (`/dashboard`)
A modern, reactive administrative interface built with React 18, TypeScript, Vite, and Tailwind CSS.

* **Real-Time Telemetry Stream**: Live WebSocket feed displaying incoming process, network, and registry events.
* **Agent Management**: View enrolled agents, system specs, online/offline status, and trigger manual commands.
* **Alert & Incident Center**: Inspect triggered alerts, severity, correlation ID, and MITRE ATT&CK mappings.
* **MITRE ATT&CK Matrix View**: Interactive matrix showing detected tactics and techniques across target endpoints.
* **Policy & Rule Configurator**: Create, edit, enable/disable detection rules and dynamic policy rules.
* **Audit Trail**: Full security audit log tracking administrator actions and command execution history.

---

## 🔄 Full End-to-End Workflows

### Workflow 1: Agent Enrollment & Handshake
```
  [Agent Host]                                              [Manager]
       |                                                        |
       |----- 1. Post Registration Request (Enrollment Key) ---->|
       |                                                        | Validates Token
       |<---- 2. Issues Signed Client Cert & Agent ID ----------|
       |                                                        |
       |----- 3. Establishes mTLS Connection (Port 8000/443) --->|
       |<---- 4. Acknowledges Secure mTLS Session --------------|
```

### Workflow 2: Telemetry Ingestion & Real-Time Threat Detection
```
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
```

### Workflow 3: Automated Incident Response & Policy Enforcement
```
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
```

---

## 📁 Repository Directory Structure

```
c:\ztav2\
├── agent/                         # Windows Agent Source Code
│   ├── collectors/                # 8 Host Telemetry Collectors
│   │   ├── base_collector.py      # Abstract Base Class
│   │   ├── process_collector.py   # Process & Parent-Child Monitoring
│   │   ├── service_collector.py   # Service Creation/State Monitoring
│   │   ├── registry_collector.py  # Sensitive Registry Key Monitoring
│   │   ├── network_collector.py   # Socket & Connection Monitoring
│   │   ├── usb_collector.py       # USB Device Insertion Monitoring
│   │   ├── file_collector.py      # File System Event Monitoring
│   │   ├── log_collector.py       # Windows Event Log Monitoring
│   │   └── login_collector.py     # User Authentication Monitoring
│   ├── communication/             # mTLS Transport, Registration & Heartbeat
│   │   ├── transport.py           # HTTPS/mTLS SSL Context Client
│   │   ├── registration.py        # Enrollment & Certificate Provisioning
│   │   └── heartbeat.py           # Periodic Health & Metric Pings
│   ├── powershell/                # PowerShell Execution Engine
│   │   └── ps_executor.py         # Subprocess Parameterized PS Script Runner
│   ├── responses/                 # Automated Response Capabilities
│   ├── localrules/                # Local Offline Rule Engine
│   ├── network/                   # Connectivity Monitoring & Reconnect
│   ├── selfprotection/            # Service & File Tamper Protection
│   ├── startup/                   # Service Entry Points
│   ├── storage/                   # SQLite Offline Queue & Cache
│   ├── windows_service/           # PyWin32 Service Wrapper
│   └── config/                    # Agent Pydantic Configuration
├── manager/                       # Backend Central Manager
│   ├── api/                       # FastAPI App & Endpoints
│   │   ├── routers/               # 14 REST Routers (auth, agents, alerts, etc.)
│   │   ├── schemas/               # Pydantic Request/Response Schemas
│   │   ├── dependencies.py        # DB Session & Auth Dependencies
│   │   └── main.py                # FastAPI Application Factory
│   ├── auth/                      # Argon2 Hashing, JWT & RBAC Engine
│   ├── database/                  # SQLAlchemy Models & Alembic Migrations
│   ├── threatintel/               # IOC Feed Ingestion & Matching Engine
│   ├── risk/                      # Risk Engine, Scoring Rules & Decay
│   ├── policy/                    # Policy Engine & Evaluation Logic
│   ├── rules/                     # Sigma Rule Engine & Loader
│   ├── mitre/                     # MITRE ATT&CK STIX Mapping Engine
│   ├── websocket/                 # Connection Manager & Command Dispatcher
│   ├── scheduler/                 # Heartbeat & Offline Agent Monitor
│   ├── workers/                   # Background Alert & Notification Workers
│   └── config.py                  # Server Settings & Configuration
├── dashboard/                     # Web Administration Frontend
│   ├── src/                       # React Components, Views & Store
│   ├── package.json               # Node.js Dependencies
│   └── vite.config.ts             # Vite Build Configuration
├── deployment/                    # Container & Production Scripts
│   ├── Dockerfile.manager         # Manager Docker Build
│   └── docker-compose.yml         # Full Infrastructure Stack (PG + Redis + Manager)
├── installer/                     # Windows Installer Generation
│   ├── install_agent.py           # Automated Agent Installer Script
│   └── inno_setup.iss             # Inno Setup Script
├── scripts/                       # System & Utility Scripts
│   ├── generate_certs.py          # PKI Root CA & mTLS Cert Generator
│   ├── seed_db.py                 # Initial Roles, Permissions & Admin User
│   └── import_mitre_attack.py     # MITRE ATT&CK Database Importer
├── ZEROTRUST_EDR_BLUEPRINT.txt    # Architecture Master Blueprint
├── seed_db_records.py             # Root DB Seeding Entry Point
├── .env.example                   # Environment Configuration Template
└── README.md                      # Comprehensive Technical Documentation
```

---

## ⚡ Setup & Operating Instructions

### Prerequisites
* **Operating System**: Windows 10/11/Server (for Agent host), Linux/macOS/Windows (for Manager/Dashboard).
* **Python**: Version 3.12 or higher.
* **Node.js**: Version 18.x or 20.x with `npm`.
* **Database**: PostgreSQL 15+ (or run via Docker Compose).
* **Cache**: Redis 7+ (or run via Docker Compose).

---

### Step-by-Step Installation Guide

#### Step 1: Clone Repository & Create Virtual Environment
```bash
git clone https://github.com/your-org/zerotrust-edr.git
cd zerotrust-edr

# Create and activate Python virtual environment
python -m venv .venv
# On Windows PowerShell:
.\.venv\Scripts\Activate.ps1
# On Linux/macOS:
source .venv/bin/activate
```

#### Step 2: Install Manager Dependencies
```bash
pip install -r manager/requirements.txt
```

#### Step 3: Configure Environment Variables
Copy `.env.example` to `.env` and adjust configuration values as needed:
```bash
cp .env.example .env
```
Key settings in `.env`:
* `POSTGRES_USER=postgres`
* `POSTGRES_PASSWORD=postgres_secure_pass`
* `POSTGRES_DB=zerotrust_edr`
* `DATABASE_URL=postgresql+asyncpg://postgres:postgres_secure_pass@localhost:5432/zerotrust_edr`
* `REDIS_URL=redis://localhost:6379/0`
* `HEARTBEAT_INTERVAL_SECONDS=30`

#### Step 4: Generate PKI Certificates (mTLS)
Run the automated certificate generator to create Root CA, Manager Server Certs, and Agent Client Certs:
```bash
python scripts/generate_certs.py
```
This generates all required SSL/mTLS certificates into `certificates/` and `manager/certs/`.

#### Step 5: Start Infrastructure Stack (Docker)
Start PostgreSQL and Redis services using Docker Compose:
```bash
docker-compose -f deployment/docker-compose.yml up -d postgres redis
```

#### Step 6: Initialize Database & Seed Records
Run database migrations and populate default permissions, roles, and admin accounts:
```bash
# Seed initial database permissions and superadmin user
python scripts/seed_db.py
```
*Default Admin Credentials:*
* **Username**: `admin`
* **Password**: `AdminSecure123!` (Note: Change upon first login!)

#### Step 7: Launch Manager Backend Server
Start the FastAPI application using Uvicorn:
```bash
uvicorn manager.api.main:app --host 0.0.0.0 --port 8000 --reload
```
* API Documentation: `http://localhost:8000/docs`
* OpenAPI Schema: `http://localhost:8000/openapi.json`

#### Step 8: Launch React Dashboard
Open a new terminal window:
```bash
cd dashboard
npm install
npm run dev
```
* Dashboard URL: `http://localhost:5173`

#### Step 9: Install & Run Agent on Endpoint
On the target Windows endpoint machine:
```bash
# Install agent requirements
pip install -r agent/requirements.txt

# Run installer script to configure configuration and service
python installer/install_agent.py

# Launch agent process/service
python -m agent.windows_service.service_entry
```

---

## 🌐 API Route Summary

| Method | Endpoint Path | Description | Access Level |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/v1/auth/login` | Authenticate user & obtain JWT token | Public |
| `POST` | `/api/v1/auth/refresh` | Refresh expired access token | Authenticated |
| `GET` | `/api/v1/agents` | List all enrolled host agents | `agents:read` |
| `POST` | `/api/v1/agents/register` | Host enrollment & cert exchange | Agent mTLS |
| `GET` | `/api/v1/telemetry` | Query filtered endpoint telemetry | `telemetry:read` |
| `GET` | `/api/v1/alerts` | List triggered security alerts | `alerts:read` |
| `PATCH` | `/api/v1/alerts/{id}` | Acknowledge/Resolve alert | `alerts:write` |
| `GET` | `/api/v1/risk/{agent_id}` | Fetch current risk score & history | `alerts:read` |
| `GET` | `/api/v1/policies` | Retrieve active dynamic policies | `policies:read` |
| `POST` | `/api/v1/commands/dispatch` | Send signed command payload to agent | `commands:execute` |
| `GET` | `/api/v1/mitre/matrix` | Get MITRE ATT&CK coverage matrix | `alerts:read` |
| `GET` | `/api/v1/audit/logs` | Fetch system administration audit trail | `audit:read` |
| `WS` | `/ws/telemetry` | WebSocket stream for live agent events | `telemetry:read` |

---

## 🔒 Security & Cryptographic Standards

* **Mutual TLS (mTLS)**: Manager and Agent enforce mTLS (TLS 1.3) with client certificate validation against the custom Root CA.
* **Password Security**: Passwords hashed using `argon2-cffi` with high memory/iteration work factors.
* **Signed Commands**: All remote commands carry an RSA-4096 / HMAC signature. Agents reject unsigned or invalidly signed commands.
* **Role-Based Access Control (RBAC)**: Fine-grained permissions (`agents:read`, `commands:execute`, `alerts:write`) assigned to predefined roles (`admin`, `soc_analyst`, `viewer`).

---

## 🧪 Testing & Quality Assurance

Run the test suite across both Agent and Manager modules:

```bash
# Run Manager unit & integration tests
pytest manager/tests -v --cov=manager

# Run Agent unit tests
pytest agent/tests -v --cov=agent
```

---

## 📜 License & Compliance

Developed as a Zero Trust Continuous Authentication & EDR Platform. Designed following NIS2, NIST SP 800-207 (Zero Trust Architecture), and MITRE ATT&CK framework guidelines.
