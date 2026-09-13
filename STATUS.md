# Status

Updated: 2026-09-14 (Asia/Calcutta)

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
- Bounded regex matching to 4096 input characters and 25 ms, with explicit timeout/limit evidence in condition traces.
- Added immutable rule definition history, rollback-as-new-version, linked-policy deletion protection, and version-stamped match/incident evidence.

## Source state

- Baseline commit: `a2fc14e` (`chore: establish imported project baseline`).
- Baseline tag: `baseline-2026-09-13` (annotated).
- Current implementation commit: `2deb54e97d54981f0d95a42141a9bdd382ee3507`; branch: `feat/rule-version-rollback` (rule-version work pending commit).
- Git executable: `C:\Program Files\Git\cmd\git.exe`; repository-local author is `Codex Agent <codex@local>`.
- Access-control base commit: `7f0ad172c49355aa85b742345fecfccc30da182d`; branch: `feat/permission-access`.
- Rule-validation base commit: `cb634cf9a1588f5a142ea8a51a3ce1f7983a548c`; branch: `fix/rule-activation-validation`.
- Regex-cost base commit: `1ae3ce7eed605abbc711a710a0f5acd17e920dd4`; branch: `fix/regex-evaluation-cost`.
- Rule-version base commit: `2deb54e97d54981f0d95a42141a9bdd382ee3507`; branch: `feat/rule-version-rollback`.
- Runtime artifacts created during smoke test: `.venv/`, `zta_runtime.db`, `storage/zta_agent_local.db`, and manager/agent log files.

## Tests

- Git-workflow documentation check: `git diff --check` passed on `chore/git-workflow-records`.
- Access-control focused tests: `3 passed in 3.26s`.
- Full regression after compatibility updates: `116 passed, 1 warning in 43.46s`.
- Final authorization and rule/policy regression: `9 passed in 9.35s`; `git diff --check` passed.
- Runtime admin provisioning check: account creation and password login passed against `zta_runtime.db`.
- Rule/condition focused regression: `58 passed, 1 warning in 17.70s`.
- Full rule compatibility regression: `129 passed, 1 warning in 52.25s`.
- Regex/rule focused regression: `61 passed in 17.68s`; full regression: `132 passed in 53.59s`.
- Rule-version focused regression: `22 passed in 15.23s`; full regression: `134 passed in 45.11s`. Unrestricted execution was required because sandboxed pytest temp-directory creation was denied.
- The original long-path `.venv` could not load the `regex` extension DLL; verification used `C:\Users\vegeta\zta-venv` successfully.
- JavaScript `node --check` unavailable because Node.js is not installed; dashboard integration/assets are covered by the passing Python suite.
- Discovery: 113 tests collected.
- Baseline: 48 passed, 65 setup errors in 2.82s; errors are `PermissionError [WinError 5]` creating pytest temp/cache directories, so this is not a valid code-failure baseline.
- Warning: Requests reports no acceptable character-detection dependency under the current Python 3.14.7 environment.
- Runtime limitation: Sysmon channel was absent (exit 15007) and Security log access was denied (exit 5); heartbeats still succeeded.

## Next task

Define user disable/password-reset and session-revocation administration flows, then remove the legacy bootstrap token from deployment.
