# ZTA Platform — Production Operations Runbook & Admin Guide

## 1. Overview & Architecture

The Zero Trust Architecture (ZTA) Platform provides continuous endpoint telemetry ingestion, real-time behavioral risk scoring, and policy-driven automated response.

### Component Map
```
[Windows Endpoint Agent] 
       | (HTTPS / mTLS / Bearer Token)
       v
[Manager REST API (FastAPI / HTTP Server)]
       |
       +---> [Durable Database (SQLite WAL / Busy Timeout)]
       |
       +---> [Background Engine Pipeline (Rule, Risk, Alert, Policy)]
       |
       +---> [WebSocket Hub (Real-time Broadcaster with Session Guard)]
       |
[SOC Dashboard (Static HTML5/CSS3/Vanilla JS)]
```

---

## 2. Manager Deployment & Startup

### Prerequisites
- Python 3.11+
- Dependencies: `requests>=2.31.0`, `regex>=2024.11.6`

### Installation from Wheel
```bash
python -m pip install dist/zta_platform-0.1.0-py3-none-any.whl
```

### Production Environment Variables
Set the following environment variables before starting the manager:
```bash
# Security & Auth
export ZTA_ADMIN_USERNAME="admin"
export ZTA_ADMIN_PASSWORD="<STRONG_CHANGE_ME_PASSWORD>"
export ZTA_AGENT_TOKENS='{"agent-win-01": "<SECURE_RANDOM_TOKEN_WIN01>"}'

# Persistence
export ZTA_RUNTIME_DB="/var/lib/zta/zta_runtime.db"

# TLS / Proxy Settings (Production requires reverse proxy TLS termination)
export ZTA_ALLOW_PLAINTEXT_LOOPBACK="false"
```

### Starting Manager Service
```bash
zta-manager --host 0.0.0.0 --port 8080
```
Or directly via python:
```bash
python -m zta.dashboard.run_dashboard
```

---

## 3. Windows Agent Deployment & Management

### Prerequisites
- Windows 10, Windows 11, or Windows Server 2019/2022 (x64)
- Administrator privileges
- Python 3.11+ installed and present on system PATH

### Automated PowerShell Installation
Run from an elevated PowerShell console:
```powershell
.\install-zta-agent.ps1 -ManagerUrl "https://zta-manager.internal.corp:8080" -AgentId "agent-win-01"
```
The installer will:
1. Validate Administrator privileges.
2. Create `C:\Program Files\ZTA Agent` with strict ACLs (SYSTEM and Administrators only).
3. Create a dedicated Python virtual environment.
4. Install the ZTA Agent wheel.
5. Securely prompt for the agent authentication token.
6. Register and start the `ZTA Endpoint Agent` Windows Scheduled Task running under the `SYSTEM` account.

### Agent Service Commands
- **Check Task Status**:
  ```powershell
  Get-ScheduledTask -TaskName "ZTA Endpoint Agent"
  ```
- **Stop Agent**:
  ```powershell
  Stop-ScheduledTask -TaskName "ZTA Endpoint Agent"
  ```
- **Start Agent**:
  ```powershell
  Start-ScheduledTask -TaskName "ZTA Endpoint Agent"
  ```
- **View Agent Logs**:
  ```powershell
  Get-Content -Path "C:\Program Files\ZTA Agent\logs\zta-agent.jsonl" -Tail 50
  ```

---

## 4. Agent Upgrade & Rollback Procedures

### Upgrading an Agent
1. Stop the scheduled task:
   ```powershell
   Stop-ScheduledTask -TaskName "ZTA Endpoint Agent"
   ```
2. Back up existing configuration and offline telemetry database:
   ```powershell
   Copy-Item "C:\Program Files\ZTA Agent\config\zta_agent.env" "C:\Program Files\ZTA Agent\config\zta_agent.env.bak"
   Copy-Item "C:\Program Files\ZTA Agent\storage\zta_agent_offline.db" "C:\Program Files\ZTA Agent\storage\zta_agent_offline.db.bak"
   ```
3. Install new wheel into agent virtual environment:
   ```powershell
   & "C:\Program Files\ZTA Agent\venv\Scripts\python.exe" -m pip install --upgrade dist\zta_platform-0.1.0-py3-none-any.whl
   ```
4. Restart the agent task:
   ```powershell
   Start-ScheduledTask -TaskName "ZTA Endpoint Agent"
   ```
5. Verify heartbeat in Manager dashboard within 30 seconds.

### Rolling Back an Agent
If the upgraded agent fails to report or exhibits anomalous behavior:
1. Stop the scheduled task.
2. Re-install the previous wheel version or restore the `venv` directory.
3. Restore `zta_agent.env` and `zta_agent_offline.db` from `.bak` if corrupted.
4. Start the scheduled task and confirm heartbeat.

---

## 5. Database Backup, Restore, and Disaster Recovery

### Safe SQLite Backup
SQLite databases in WAL mode must be copied safely to avoid inconsistent state between the main file, `-wal`, and `-shm`.

**Recommended Backup Script (`backup_database.py`):**
```python
import sqlite3
import sys
from pathlib import Path

def backup_db(source_path, target_path):
    src = sqlite3.connect(source_path)
    dst = sqlite3.connect(target_path)
    with dst:
        src.backup(dst, pages=100)
    dst.close()
    src.close()
    print(f"Database successfully backed up from {source_path} to {target_path}")

if __name__ == "__main__":
    src_db = sys.argv[1] if len(sys.argv) > 1 else "zta_runtime.db"
    dst_db = sys.argv[2] if len(sys.argv) > 2 else "zta_runtime.db.backup"
    backup_db(src_db, dst_db)
```

### Restore Procedure
1. Stop the ZTA Manager service.
2. Archive the current corrupted/outdated database:
   ```bash
   mv zta_runtime.db zta_runtime.db.failed
   ```
3. Copy the verified backup into place:
   ```bash
   cp zta_runtime.db.backup zta_runtime.db
   ```
4. Start the ZTA Manager. Additive migrations run automatically on startup.
5. Verify schema and endpoint integrity via `/api/zta/overview`.

---

## 6. Security Administrator Guide

### Role-Based Access Control (RBAC)
- **ADMIN**: Full system control. Can manage operator accounts, create/delete detection rules and policies, trigger database operations, and view audit trails.
- **OPERATOR**: Security operations. Can view alerts, investigate endpoint telemetry, and dispatch manual containment commands if authorized.
- **ANALYST**: Read-only investigation. Can view dashboards, query telemetry, and generate reports.

### Safe Response Policy Configuration
- **Default State**: All policies are deployed in `ALERT_ONLY` mode.
- **Enabling Actions**: To switch an automated response to `ENFORCE`, the security administrator must explicitly verify the rule conditions and ensure targeted processes or endpoints are not on the system protected-resource allowlist.
- **Protected Resources**:
  - System processes: `csrss.exe`, `lsass.exe`, `smss.exe`, `services.exe`, `svchost.exe`.
  - Directory paths: `C:\Windows\System32`, `C:\Program Files\ZTA Agent`.
- **Command Verification**: The Manager will never report an action as successful unless cryptographic execution results with valid post-condition checks are received from the target agent.
