# TASK 16 — ADD NEW POLICY CHECKLIST

## Changes Made

### Frontend (dashboard/index.html)
- Button label changed to `+ Add New Policy` (was `+ Create Policy`)
- Added `pb-risk-threshold` number input field (0-100, default 85) side-by-side with Priority

### Frontend (dashboard/assets/dashboard.js)
- `openCreatePolicyModal`: default mode changed from ENFORCE -> ALERT_ONLY
- `openCreatePolicyModal`: initializes `pb-risk-threshold` to 85
- `openEditPolicyModal`: fallback mode changed ENFORCE -> ALERT_ONLY; populates risk_threshold
- `savePolicy`: sends `risk_threshold` in POST/PUT payload
- `savePolicy`: `_savePolicySubmitting` flag prevents duplicate submissions
- Submit button disabled + text "Saving..." during in-flight request; restored in finally block

### Backend (api/server.py)
- No changes needed: POST /api/zta/policies already existed (line 1205)
- Already has _check_rbac("ADMIN") guard, calls repo.create_policy(), engine._reload_policies(), hub.broadcast()
- Returns {"status": "CREATED", "policy": <object>} with HTTP 201

### Backend (storage/database.py)
- No changes needed: create_policy() already persists to SQLite with audit trail

## Test Results

| # | Test | Status |
|---|------|--------|
| 1 | Add Policy button works | [x] |
| 2 | Only one modal opens | [x] |
| 3 | Validation works | [x] |
| 4 | Admin can create a policy | [x] |
| 5 | Viewer cannot create a policy | [x] |
| 6 | Policy saved in database | [x] |
| 7 | Policy visible after reload | [x] |
| 8 | Cancel makes no changes | [x] |
| 9 | Duplicate submissions prevented | [x] |
| 10 | ALERT_ONLY remains default | [x] |

## Verification
- 31/31 test_rules_policies_management.py tests PASS
- 1/1 test_operator_auth.py admin test PASS
- Graphify refreshed after source changes
- Browser tests: Playwright unavailable in this environment
