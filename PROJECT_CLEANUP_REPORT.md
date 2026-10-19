# Project Cleanup Report

Date: 2026-10-16  
Scope: Original Zero Trust EDR repository only. Application source and runtime data were not changed.

## Cleanup performed

- Removed 17 complete source-tree `__pycache__` directories containing only regenerable CPython bytecode.
- Partially cleaned `tests/__pycache__`; some long-path bytecode entries could not be removed by Windows and are listed for manual review.
- Added standard exclusions for `build/`, `dist/`, and `*.egg-info/` to `.gitignore`; existing exclusions already cover caches, test work directories, environments, databases, logs, secrets, and Graphify output.
- Validation recreated bytecode caches; a final cache-removal pass was performed after testing.
- No source, tests, reports, databases, logs, credentials, certificates, virtual environments, Graphify tools, or unknown files were deleted.

## Preserved and why

- `.git/` and every pre-existing modified/untracked source or documentation file: user work and history.
- `zta_runtime.db`, WAL/SHM files, storage queues, and backups: protected runtime state.
- `logs/`: telemetry/forensic evidence.
- `.venv/` and `.venv-graphify/`: active tool environments.
- Graphify scripts, configuration, and `graphify-out/`: required index tooling.
- `build/` and `dist/`: likely generated but pre-existing/untracked with uncertain ownership.
- Task reports, checklists, guides, and `docs/`: potentially required evidence/documentation.
- Snapshot/test-looking directories (`.t*`, `.task*`, `.test-*`, `zta-task*`, `t6base`, `tmp`): untracked/pre-existing; some have restrictive ACLs, so preserved under the zero-uncertainty rule.
- `admin-credentials.env`: protected secret; contents were not copied.

## Manual review candidates

The owner may review `build/`, `dist/`, snapshot/test-looking directories, `.pytest_cache`, and residual `tests/__pycache__`. They were not removed because ownership is uncertain or Windows ACL/long-path behavior prevented conclusive safe deletion. Confirm release provenance and forensic retention requirements first.

## Project structure after cleanup

```text
agent/       endpoint daemon, collectors, commands, queue
api/         manager API, auth, ingestion, workers
dashboard/   browser UI and local runner
engine/      detection, policy, risk, correlation, response
manager/     manager support components
powershell/  guarded execution/quarantine support
storage/     SQLite schema and repository
scripts/     startup and release helpers
tests/       automated test suite
docs/        installation, operations, integration documentation
ruleset/     detection content
etc/         configuration/deployment material
graphify-out/ generated dependency/call-flow index
```

Root startup/install scripts, packaging metadata, configuration templates, AGENTS.md, the working guide, and protected SQLite runtime files remain in place.

## Validation results

- Graphify dependency query: PASS before cleanup (1,155-node index).
- Python imports (`api.server`, `storage.database`, `agent.agent_daemon`, `engine.pipeline`): PASS.
- Startup CLI (`scripts/start_zta_local.py --help`): PASS.
- Dashboard JavaScript syntax (`node --check dashboard/assets/dashboard.js`): PASS.
- Existing SQLite database opened read-only: PASS (61 schema objects; no mutation).
- Focused dashboard/API/Rules/Policies/auth selection: 3 passed; remaining cases were blocked at fixture/database setup by Windows path-length/temporary-directory ACL behavior. These environmental errors occurred before feature assertions and did not touch the live database.
- Live browser testing was unavailable in this cleanup run; no browser PASS is claimed. Rules/Policies source was not modified.

## Graphify refresh

- Final refresh: PASS — 1,155 nodes, 2,546 edges, 78 communities; reports and call-flow regenerated.
- Post-refresh architecture query: PASS.
