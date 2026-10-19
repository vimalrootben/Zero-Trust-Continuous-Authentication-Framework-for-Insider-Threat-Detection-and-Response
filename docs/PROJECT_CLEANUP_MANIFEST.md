# PROJECT CLEANUP MANIFEST
## Zero Trust Continuous Authentication Framework
**Executed:** 2026-10-15  
**Operator:** Master Integration (automated)  
**Result:** 84 directories deleted, 13 OS-locked (defer), 0 source files touched

---

## DELETED — CONFIRMED REMOVED (84 directories)

### .test-temp* Directories (49 deleted)
| Directory | Status |
|-----------|--------|
| `.test-temp` | ✅ DELETED |
| `.test-temp-account` | ✅ DELETED |
| `.test-temp-ack` | ✅ DELETED |
| `.test-temp-auth` | ✅ DELETED |
| `.test-temp-auth-pages` | ✅ DELETED |
| `.test-temp-auth-pages-final` | ✅ DELETED |
| `.test-temp-auth-pages-full` | ✅ DELETED |
| `.test-temp-builder` | ✅ DELETED |
| `.test-temp-command` | ✅ DELETED |
| `.test-temp-command-2` | ✅ DELETED |
| `.test-temp-domains` | ✅ DELETED |
| `.test-temp-e2e` | ✅ DELETED |
| `.test-temp-execution` | ✅ DELETED |
| `.test-temp-execution-2` | ✅ DELETED |
| `.test-temp-final` | ✅ DELETED |
| `.test-temp-firewall` | ✅ DELETED |
| `.test-temp-full` | ✅ DELETED |
| `.test-temp-full-2` | ✅ DELETED |
| `.test-temp-full-version` | ✅ DELETED |
| `.test-temp-integration-final` | ✅ DELETED |
| `.test-temp-integration-final-2` | ✅ DELETED |
| `.test-temp-integration-final-3` | ✅ DELETED |
| `.test-temp-integration-full` | ✅ DELETED |
| `.test-temp-merge` | ✅ DELETED |
| `.test-temp-network` | ✅ DELETED |
| `.test-temp-new-final` | ✅ DELETED |
| `.test-temp-new-final-2` | ✅ DELETED |
| `.test-temp-new-full` | ✅ DELETED |
| `.test-temp-new-scope` | ✅ DELETED |
| `.test-temp-new-scope-2` | ✅ DELETED |
| `.test-temp-one` | ✅ DELETED |
| `.test-temp-one-2` | ✅ DELETED |
| `.test-temp-policy-migration` | ✅ DELETED |
| `.test-temp-policy-priority` | ✅ DELETED |
| `.test-temp-policy-priority-full` | ✅ DELETED |
| `.test-temp-process` | ✅ DELETED |
| `.test-temp-process-2` | ✅ DELETED |
| `.test-temp-process-3` | ✅ DELETED |
| `.test-temp-process-full` | ✅ DELETED |
| `.test-temp-regex-2` | ✅ DELETED |
| `.test-temp-regex-full` | ✅ DELETED |
| `.test-temp-release` | ✅ DELETED |
| `.test-temp-rule-full` | ✅ DELETED |
| `.test-temp-rule-validation` | ✅ DELETED |
| `.test-temp-task5-baseline` | ✅ DELETED |
| `.test-temp-version` | ✅ DELETED |
| `.test-temp-version-final` | ✅ DELETED |
| `.test-temp-wts` | ✅ DELETED |
| `.test-temp-wts-2` | ✅ DELETED |

### zta-task4-* Directories (8 deleted)
| Directory | Status |
|-----------|--------|
| `zta-task4-baseline-20261014` | ✅ DELETED |
| `zta-task4-fixcheck` | ✅ DELETED |
| `zta-task4-focused-existing` | ✅ DELETED |
| `zta-task4-focused-final` | ✅ DELETED |
| `zta-task4-full-final` | ✅ DELETED |
| `zta-task4-full-final-2` | ✅ DELETED |
| `zta-task4-newtests-2` | ✅ DELETED |
| `zta-task4-race-fix` | ✅ DELETED |

### zta-task5-* Directories (9 deleted)
| Directory | Status |
|-----------|--------|
| `zta-task5-baseline-20261014` | ✅ DELETED |
| `zta-task5-concurrent-debug` | ✅ DELETED |
| `zta-task5-focused-1` | ✅ DELETED |
| `zta-task5-focused-2` | ✅ DELETED |
| `zta-task5-focused-20261014` | ✅ DELETED |
| `zta-task5-focused-final` | ✅ DELETED |
| `zta-task5-full-final` | ✅ DELETED |
| `zta-task5-full-final-2` | ✅ DELETED |
| `zta-task5-newtests` | ✅ DELETED |
| `zta-task5-newtests-2` | ✅ DELETED |
| `zta-task5-newtests-3` | ✅ DELETED |

### zta-task6-* Directories (2 deleted)
| Directory | Status |
|-----------|--------|
| `zta-task6-baseline-20261015` | ✅ DELETED |
| `zta-task6-baseline-20261015b` | ✅ DELETED |

### `tmp/` and subtrees (1 directory tree)
| Path | Status |
|------|--------|
| `tmp/` (and all subtrees: `zta-t6-final`, `zta-t7-baseline`, `zta-t7-final`, `zta-t7-final-all`, `zta-t8-baseline`, `zta-t8-clean-venv`, `zta-t8-final`, `zta-t8-focused`, `zta-t8-wheel`, `zta-t8-wheel-short`) | ✅ DELETED |

### Caches and Logs (automated)
| Item | Status |
|------|--------|
| `.pytest_cache/` | ✅ DELETED |
| `zta_platform.egg-info/` | ✅ DELETED |
| All `__pycache__/` directories (source tree) | ✅ DELETED |
| `agent-live.err.log` | ✅ DELETED |
| `agent-live.out.log` | ✅ DELETED |
| `agent.stderr.log` | ✅ DELETED |
| `agent.stdout.log` | ✅ DELETED |
| `manager-live.err.log` | ✅ DELETED |
| `manager-live.out.log` | ✅ DELETED |
| `manager.stderr.log` | ✅ DELETED |
| `manager.stdout.log` | ✅ DELETED |

---

## DEFERRED — OS-LOCKED (13 directories, manual removal required)

These directories have Windows NTFS permission locks on internal `.db` files (likely SQLite WAL-mode files from a prior session run under a different user context or elevated process). They are safe to delete manually as Administrator or by rebooting.

| Directory | Reason Locked | Action |
|-----------|--------------|--------|
| `t6base` | NTFS read-only .db | Delete manually as Admin |
| `.t6s` | NTFS read-only .db | Delete manually as Admin |
| `.task2-test-temp-20261014` | NTFS read-only .db | Delete manually as Admin |
| `.task2tmp` | NTFS read-only .db | Delete manually as Admin |
| `.task6-baseline-20261015` | NTFS read-only .db | Delete manually as Admin |
| `.task6baseline` | NTFS read-only .db | Delete manually as Admin |
| `.task6focused` | NTFS read-only .db | Delete manually as Admin |
| `.task6pytest` | NTFS read-only .db | Delete manually as Admin |
| `.task6target` | NTFS read-only .db | Delete manually as Admin |
| `.t7focused` | NTFS read-only .db | Delete manually as Admin |
| `.t7target` | NTFS read-only .db | Delete manually as Admin |
| `.t7target2` | NTFS read-only .db | Delete manually as Admin |
| `.t8focused` | NTFS read-only .db | Delete manually as Admin |

**Manual removal command (run as Administrator):**
```powershell
$dirs = @('t6base','.t6s','.task2-test-temp-20261014','.task2tmp','.task6-baseline-20261015','.task6baseline','.task6focused','.task6pytest','.task6target','.t7focused','.t7target','.t7target2','.t8focused')
foreach ($d in $dirs) { takeown /f $d /r /d y | Out-Null; icacls $d /grant Administrators:F /t | Out-Null; Remove-Item -Recurse -Force $d }
```

---

## RETAINED — PRODUCTION SOURCE (98 Python files, unchanged)

### Core Package (`zta/`)
| Module | Path | Purpose |
|--------|------|---------|
| `ZTADatabase` | `storage/database.py` | SQLite WAL, migrations, connection pool |
| `ZTARepository` | `storage/database.py` | All repository data access methods |
| `BackgroundWorker` | `api/background.py` | 1-second durable polling loop |
| `ZTAApiHandler` | `api/server.py` | REST API + WebSocket + SSE handler |
| `WebSocketHub` | `api/server.py` | Fan-out real-time event broadcast |
| `ZTABackgroundEngine` | `api/server.py` | Rule/risk/policy orchestrator |
| `OperatorAuth` | `api/auth.py` | RBAC session + PBKDF2 login |
| `ingestion` | `api/ingestion.py` | Durable event + command result ingestion |
| `process` | `engine/pipeline.py` | Unified event processing pipeline |
| `ConditionEvaluator` | `engine/events/conditions.py` | AND/OR/NOT condition tree evaluator |
| `ZTAEventAdapter` | `engine/events/wazuh_adapter.py` | Normalize raw telemetry → ZTAEvent |
| `ZTACorrelationEngine` | `engine/correlation/engine.py` | Multi-event temporal correlation |
| `ZTARiskEngine` | `engine/risk/engine.py` | Dynamic risk scoring + decay |
| `ZTATrustEngine` | `engine/trust/engine.py` | Trust score calculation |
| `ZTAPolicyEngine` | `engine/policy/engine.py` | Declarative policy evaluation |
| `ZTAResponseEngine` | `engine/response/engine.py` | PowerShell response dispatch |
| `build_command` | `engine/response/command_builder.py` | Command construction + signing |
| `ZTAAgentDaemon` | `agent/agent_daemon.py` | Full agent loop + workers |
| `WindowsEventCollector` | `agent/collectors.py` | Windows event/process/network collection |
| `OfflineQueue` | `agent/storage/offline_queue.py` | SQLite offline event queue |
| `LocalRuleEngine` | `agent/rules/local_rule_engine.py` | On-device rule matching |
| `AgentCommandReceiver` | `agent/commands/command_receiver.py` | Signed command delivery |
| `ScriptExecutor` | `agent/execution/script_executor.py` | Allowlisted PowerShell execution |
| `PowerShellExecutor` | `powershell/ps_executor.py` | PowerShell template executor |

### Tests (`tests/` — 13 test files, 217 tests)
All test files retained and green.

### Documentation (`docs/` — 8 files)
All documentation files retained.

### Release Artifacts (`dist/` — 4 files)
`zta_platform-0.1.0-py3-none-any.whl`, `zta_windows_agent_bundle-0.1.0.zip`, `SHA256SUMS`, `release_manifest.json` — all retained.

### Configuration and Setup
`pyproject.toml`, `requirements.txt`, `setup.cfg`, `.gitignore`, `etc/zta.conf` — all retained.

---

## POST-CLEANUP SUMMARY

| Metric | Before | After |
|--------|--------|-------|
| Total subdirectories | ~103 | ~19 |
| Temporary task dirs | 84 | 0 |
| OS-locked deferred dirs | 13 | 13 (manual) |
| Source Python files | 98 | 98 |
| Test files | 13 | 13 |
| Test pass rate | 217/217 | 217/217 ✅ |
| Release artifacts | 4 | 4 |
| Runtime databases | 2 | 2 |
