# Status

Updated: 2026-09-14 (Asia/Calcutta)

Current review (2026-09-14): rule-validation branch passes 134 tests after strict toggle validation. Historical records below describe the original Windows environment. See update.txt for current evidence.

## Completed

- Created `.venv` with declared dependencies.
- Smoke-tested manager on ports 8000/8080: dashboard returned HTTP 200.
- Smoke-tested `agent-local`: manager accepted repeated heartbeats and offline-sync requests.
- Stopped manager PID 18004 and agent PID 4172; ports 8000/8080 are no longer listening.
- Added the four compact project-reference documents.
- Initialized Git and recorded the imported source baseline.
- Implemented authenticated operator users, sessions, permission enforcement, protected WebSockets, dashboard login/logout, and admin user creation.
- Provisioned the named runtime operator `admin` with role `ADMIN`; password login was verified. Credentials are stored in ignored `admin-credentials.env` with a restricted Windows ACL.
- Added centralized validation that blocks invalid rule creation, updates, and reactivation without changing valid stored rules.

## Source state

- Baseline commit: `a2fc14e` (`chore: establish imported project baseline`).
- Baseline tag: `baseline-2026-09-13` (annotated).
- Current implementation commit: `00e85d2ec60d1f53219096be64365a31a5866467`; branch: `fix/rule-activation-validation`.
- Git executable: `C:\Program Files\Git\cmd\git.exe`; repository-local author is `Codex Agent <codex@local>`.
- Access-control base commit: `7f0ad172c49355aa85b742345fecfccc30da182d`; branch: `feat/permission-access`.
- Rule-validation base commit: `cb634cf9a1588f5a142ea8a51a3ce1f7983a548c`; branch: `fix/rule-activation-validation`.
- Runtime artifacts created during smoke test: `.venv/`, `zta_runtime.db`, `storage/zta_agent_local.db`, and manager/agent log files.

## Tests

- Git-workflow documentation check: `git diff --check` passed on `chore/git-workflow-records`.
- Access-control focused tests: `3 passed in 3.26s`.
- Full regression after compatibility updates: `116 passed, 1 warning in 43.46s`.
- Final authorization and rule/policy regression: `9 passed in 9.35s`; `git diff --check` passed.
- Runtime admin provisioning check: account creation and password login passed against `zta_runtime.db`.
- Rule/condition focused regression: `58 passed, 1 warning in 17.70s`.
- Full rule compatibility regression: `129 passed, 1 warning in 52.25s`.
- JavaScript `node --check` unavailable because Node.js is not installed; dashboard integration/assets are covered by the passing Python suite.
- Discovery: 113 tests collected.
- Baseline: 48 passed, 65 setup errors in 2.82s; errors are `PermissionError [WinError 5]` creating pytest temp/cache directories, so this is not a valid code-failure baseline.
- Warning: Requests reports no acceptable character-detection dependency under the current Python 3.14.7 environment.
- Runtime limitation: Sysmon channel was absent (exit 15007) and Security log access was denied (exit 5); heartbeats still succeeded.

## Next task

Define user disable/password-reset and session-revocation administration flows, then remove the legacy bootstrap token from deployment.
