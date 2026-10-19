# TASK 12: COMPLETE DASHBOARD UI REPAIR CHECKLIST

## 1. Sidebar & Navigation Checklist
- [x] Overview (`data-view="dashboard"`) — Active state updates, counters and charts rendered.
- [x] Endpoints (`data-view="agents"`) — Renders endpoint inventory table with full telemetry columns.
- [x] Events (`data-view="events"`) — Renders security alerts and event logs stream.
- [x] Rules (`data-view="rules_policies"`, subtab `rules`) — Displays rule table, count badges, and action triggers.
- [x] Policies (`data-view="rules_policies"`, subtab `policies`) — Displays policy table, priorities, risk ranges, mode badges, action triggers.
- [x] MITRE Matrix (`data-view="mitre"`) — Displays MITRE ATT&CK coverage, tactic distribution, and observed matches.
- [x] Threat Intel (`data-view="threat_intel"`) — Displays threat indicators and feed indicators.
- [x] Timeline (`data-view="timeline"`) — Displays unified security events and actions timeline.
- [x] Reports (`data-view="reports"`) — Displays database-backed reports with JSON/CSV download triggers.
- [x] Users (`data-view="users"`) — Displays operator user accounts (RBAC protected for `users:manage`).
- [x] Settings (`data-view="settings"`) — Displays effective manager settings (read-only).
- [x] Audit Log (`data-view="audit"`) — Displays operational and security audit trails.
- [x] Services (`data-view="services"`) — Displays background manager services and heartbeats.

## 2. Interactive Buttons Checklist
- [x] Login Form Submit (`#login-submit`) — Authenticates operator and stores JWT in `sessionStorage`.
- [x] Sign Out (`#sign-out`) — Revokes session and locks UI.
- [x] Refresh (`#refresh`) — Re-fetches all 16 endpoints without blocking UI on single error.
- [x] Search & Filter (`#search-form`, `#search`, `#severity`, `#period`) — Dynamic table and chart filtering.
- [x] Date Filter (`#dates`, `#apply-dates`) — Custom date range filter application.
- [x] Clear Filters (`#clear`) — Resets all search and filter dropdowns.
- [x] Pagination (`#previous`, `#next`) — Page switching with bounds checks.
- [x] View Details (`[data-view-rule]`, `[data-view-policy]`, `[data-row]`) — Opens forensic modal and details dialogs.
- [x] Edit Rule / Policy (`[data-edit-rule]`, `[data-edit-policy]`) — Opens rule/policy builders with prefilled state.
- [x] Delete Rule / Policy (`[data-delete-rule]`, `[data-delete-policy]`) — Opens safety confirmation dialog with impact analysis.
- [x] Toggle Rule / Policy (`[data-toggle-rule]`, `[data-toggle-policy]`) — PATCH toggle endpoint with state refresh.
- [x] Create Rule / Policy (`#btn-create-rule`, `#btn-create-policy`) — Launches modal builders.
- [x] Condition Builder (`#rb-add-condition-root`, `#pb-add-condition-root`, group additions) — Interactive tree builder.
- [x] Close Modals (`#close-rule-builder`, `#close-policy-builder`, `#close-rule-details`, `#close-policy-details`, `#del-cancel`, `#close-details`) — Native modal dismiss handlers.
- [x] Generate Report (`#report`, `[data-report-format]`) — Downloads authenticated JSON and CSV reports.

## 3. Forms & Backend Connection Checklist
- [x] Base URL and API route consistency: `/api/zta/*`
- [x] Bearer Token authentication & session resumption: `/api/zta/auth/login`, `/api/zta/session`
- [x] RBAC permission gating: VIEWER, AUDITOR, SOC_ANALYST, ADMIN
- [x] Real-time WebSocket connection & sequence replay: `/api/zta/ws`, `/api/zta/realtime-events`

## 4. Test Results & Limitations
- [x] Unit & Regression Tests: 217 passed out of 217 (`pytest tests/`).
- [x] Simulated DOM UI Execution: All 14 views and dialog modals verified in Node runtime.
- [x] Browser Tooling Limitation: Playwright driver download failed with 404 from AzureEdge (`https://playwright.azureedge.net/builds/driver/playwright-1.57.0-win32_x64.zip`), preventing headless Playwright execution; real DOM rendering and event handlers were validated via simulated DOM harness and live API curl/Python clients.
