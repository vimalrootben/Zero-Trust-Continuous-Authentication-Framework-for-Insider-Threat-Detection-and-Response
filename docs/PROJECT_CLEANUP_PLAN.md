# PROJECT CLEANUP PLAN
## Zero Trust Continuous Authentication Framework
**Generated:** 2026-10-15  
**Inspector:** Master Integration Analysis

---

## OVERVIEW

The project root contains **103 subdirectories** as a result of prior task-by-task development work where temporary test environments, focused regression runners, and task isolation directories were created and left in place. None of these directories are application source, tests, documentation, installers, migrations, or release artifacts.

The `.gitignore` already covers `*.db`, `*.log`, `.test-temp*/`, and `__pycache__/`. The temporary task directories (`zta-task*`) and temp runner directories (`tmp/`, `t6base/`, `.t6s`, `.t7*`, `.t8*`, `.task*`) are not covered by `.gitignore` but should be.

---

## SAFE DELETION CANDIDATES

### Category 1: `.test-temp*` Directories (60 directories)

These are isolated per-run SQLite test databases created by prior pytest runs on earlier branch iterations. The current test suite uses `tmp_path` (pytest's temp mechanism) or explicit paths, not these directories. Each contains only `.db` files; none are source code.

**Pattern:** `.test-temp`, `.test-temp-account`, `.test-temp-ack`, `.test-temp-auth`, `.test-temp-auth-pages`, `.test-temp-auth-pages-final`, `.test-temp-auth-pages-full`, `.test-temp-builder`, `.test-temp-command`, `.test-temp-command-2`, `.test-temp-domains`, `.test-temp-e2e`, `.test-temp-execution`, `.test-temp-execution-2`, `.test-temp-final`, `.test-temp-firewall`, `.test-temp-full`, `.test-temp-full-2`, `.test-temp-full-version`, `.test-temp-integration-final`, `.test-temp-integration-final-2`, `.test-temp-integration-final-3`, `.test-temp-integration-full`, `.test-temp-merge`, `.test-temp-network`, `.test-temp-new-final`, `.test-temp-new-final-2`, `.test-temp-new-full`, `.test-temp-new-scope`, `.test-temp-new-scope-2`, `.test-temp-one`, `.test-temp-one-2`, `.test-temp-policy-migration`, `.test-temp-policy-priority`, `.test-temp-policy-priority-full`, `.test-temp-process`, `.test-temp-process-2`, `.test-temp-process-3`, `.test-temp-process-full`, `.test-temp-regex-2`, `.test-temp-regex-full`, `.test-temp-release`, `.test-temp-rule-full`, `.test-temp-rule-validation`, `.test-temp-task5-baseline`, `.test-temp-version`, `.test-temp-version-final`, `.test-temp-wts`, `.test-temp-wts-2`

| Attribute | Value |
|-----------|-------|
| FILE | `.test-temp*` (60 directories) |
| REASON | Isolated test database artifacts from prior task iterations, not produced by current test suite |
| REFERENCES | None — not referenced by any source or test file |
| IMPORT DEPENDENCIES | None |
| RUNTIME USAGE | Not used at runtime; current tests use `tmp_path` |
| TEST IMPACT | Zero — current 217-test suite does not use these directories |
| DELETION RISK | **NONE** |

---

### Category 2: `zta-task4-*`, `zta-task5-*`, `zta-task6-*` Directories (21 directories)

These are snapshots of project state taken at various phases of Tasks 4–6 development. They contain copies of test files and databases that no longer match the current codebase. They are not referenced by any current source, test, or installer.

**Directories:** `zta-task4-baseline-20261014`, `zta-task4-fixcheck`, `zta-task4-focused-existing`, `zta-task4-focused-final`, `zta-task4-full-final`, `zta-task4-full-final-2`, `zta-task4-newtests-2`, `zta-task4-race-fix`, `zta-task5-baseline-20261014`, `zta-task5-concurrent-debug`, `zta-task5-focused-1`, `zta-task5-focused-2`, `zta-task5-focused-20261014`, `zta-task5-focused-final`, `zta-task5-full-final`, `zta-task5-full-final-2`, `zta-task5-newtests`, `zta-task5-newtests-2`, `zta-task5-newtests-3`, `zta-task6-baseline-20261015`, `zta-task6-baseline-20261015b`

| Attribute | Value |
|-----------|-------|
| FILE | `zta-task4-*`, `zta-task5-*`, `zta-task6-*` (21 directories) |
| REASON | Task-phase snapshots and isolated regression runners from development stages |
| REFERENCES | None — no source or test imports from these paths |
| IMPORT DEPENDENCIES | None |
| RUNTIME USAGE | None |
| TEST IMPACT | Zero |
| DELETION RISK | **NONE** |

---

### Category 3: `tmp/` Directory

Contains per-task SQLite test databases (`zta-t7-ui.db`, `zta-t8-benchmark.db`) and task-phase test directories (`zta-t6-final`, `zta-t7-baseline`, `zta-t7-final`, `zta-t7-final-all`, `zta-t8-baseline`, `zta-t8-clean-venv`, `zta-t8-final`, `zta-t8-focused`, `zta-t8-wheel`, `zta-t8-wheel-short`). These are temporary working directories for prior tasks.

| Attribute | Value |
|-----------|-------|
| FILE | `tmp/` (entire directory) |
| REASON | Temporary task-phase test environments and isolated databases |
| REFERENCES | None |
| IMPORT DEPENDENCIES | None |
| RUNTIME USAGE | None |
| TEST IMPACT | Zero |
| DELETION RISK | **NONE** |

---

### Category 4: `t6base/`, `.t6s`, `.task6-baseline-20261015`, `.task6baseline`, `.task6focused`, `.task6pytest`, `.task6target`

Task 6 baseline snapshot directories.

| Attribute | Value |
|-----------|-------|
| FILE | `t6base/`, `.t6s`, `.task6-baseline-20261015`, `.task6baseline`, `.task6focused`, `.task6pytest`, `.task6target` |
| REASON | Task 6 baseline captures — isolated database snapshots |
| REFERENCES | None |
| IMPORT DEPENDENCIES | None |
| RUNTIME USAGE | None |
| TEST IMPACT | Zero |
| DELETION RISK | **NONE** |

---

### Category 5: `.t7focused`, `.t7target`, `.t7target2`, `.t8focused`, `.task2-test-temp-20261014`, `.task2tmp`

Task 7–8 focused test runners.

| Attribute | Value |
|-----------|-------|
| FILE | `.t7focused`, `.t7target`, `.t7target2`, `.t8focused`, `.task2-test-temp-20261014`, `.task2tmp` |
| REASON | Task-phase focused test runners and temp databases |
| REFERENCES | None |
| IMPORT DEPENDENCIES | None |
| RUNTIME USAGE | None |
| TEST IMPACT | Zero |
| DELETION RISK | **NONE** |

---

### Category 6: `__pycache__` Directories

Standard Python bytecode cache directories. Covered by `.gitignore`.

| Attribute | Value |
|-----------|-------|
| FILE | All `__pycache__/` directories throughout source tree |
| REASON | Auto-generated bytecode; regenerated on next run |
| DELETION RISK | **NONE** |

---

### Category 7: `.pytest_cache/` Directory

| Attribute | Value |
|-----------|-------|
| FILE | `.pytest_cache/` |
| REASON | pytest internal cache; regenerated automatically |
| DELETION RISK | **NONE** |

---

### Category 8: `zta_platform.egg-info/`

Setuptools build metadata. Regenerated by `pip install -e .`.

| Attribute | Value |
|-----------|-------|
| FILE | `zta_platform.egg-info/` |
| REASON | Auto-generated setuptools distribution metadata |
| DELETION RISK | **NONE** |

---

### Category 9: `.venv/` Directory

The existing `.venv` was created for Python 3.14 which is not present on this machine (Python 3.15 is installed system-wide). The `.venv` contains a broken Python interpreter symlink. The project runs correctly with system Python 3.15.

| Attribute | Value |
|-----------|-------|
| FILE | `.venv/` |
| REASON | Stale virtual environment created for Python 3.14 — incompatible with current Python 3.15 |
| DELETION RISK | **LOW** — system Python 3.15 already has all dependencies |

---

### Category 10: Log Files

`agent-live.err.log` (492KB), `agent.stderr.log` (70KB), `manager-live.err.log` (129KB), `manager.stderr.log` (99KB), `agent-live.out.log`, `agent.stdout.log`, `manager-live.out.log`, `manager.stdout.log`

These are runtime log files from prior smoke tests. Not referenced by any code.

| Attribute | Value |
|-----------|-------|
| FILE | `*.log`, `*.err.log`, `*.stdout.log`, `*.stderr.log` |
| REASON | Runtime log artifacts from prior smoke tests; covered by `.gitignore` |
| DELETION RISK | **NONE** |

---

## FILES TO RETAIN — UNCERTAINTY NOTES

| File/Directory | Status | Reason for Retention |
|---------------|--------|----------------------|
| `zta_runtime.db` (125MB) | **RETAIN** | Live runtime database with real registered agents, rules, policies, audit records |
| `storage/zta_agent_local.db` (115MB) | **RETAIN** | Live agent local queue with accumulated telemetry |
| `admin-credentials.env` | **RETAIN** | Runtime operator credentials (git-ignored) |
| `dist/` | **RETAIN** | Release artifacts (whl, bundle, manifest, checksums) |
| `build/` | **INSPECT** | May contain leftover build artifacts |
| `etc/zta.conf` | **RETAIN** | Configuration template |
| `docs/` | **RETAIN** | Architecture and installation documentation |

---

## .gitignore ADDITIONS RECOMMENDED

```gitignore
# Task working directories
zta-task*/
tmp/
t6base/
.t6s/
.t7*/
.t8*/
.task*/
```

---

## SUMMARY

| Category | Count | Safe to Delete |
|----------|-------|----------------|
| `.test-temp*` dirs | 49 | YES |
| `zta-task*` dirs | 21 | YES |
| `tmp/` | 1 | YES |
| `t6base/` and task snapshot dirs | 7 | YES |
| `__pycache__/` dirs | ~25 | YES |
| `.pytest_cache/` | 1 | YES |
| `zta_platform.egg-info/` | 1 | YES |
| Log files | 8 | YES |
| `.venv/` | 1 | OPTIONAL |
| **Total deletable** | **~113** | |
| **Active source files** | 98 | MUST RETAIN |
| **Release artifacts** | 4 | RETAIN |
| **Live databases** | 2 | RETAIN |
