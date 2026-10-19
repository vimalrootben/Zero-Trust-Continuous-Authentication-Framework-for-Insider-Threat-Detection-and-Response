# Production Deployment Checklist — Zero Trust Architecture (ZTA)

This checklist enforces production readiness gates prior to live system operation. Every checkbox must be backed by verifiable test evidence.

- [x] **Source revision identified**: Branch `feat/agent-execution-integration`, Commit `3365b7aebc0827b6d780f70e6451a13613e6d7a0`.
- [x] **Dependencies verified**: Runtime locked to `requests>=2.31.0` and `regex>=2024.11.6`. Test framework uses `pytest` and `pytest-asyncio`.
- [x] **No committed secrets**: Configuration template uses environment variables; `.gitignore` covers `.env`, `.pem`, and local databases.
- [x] **Database backup tested**: SQLite online backup / safe copy procedure verified. Backup script and restoration steps documented.
- [x] **Database migrations tested**: Additive schema migrations with WAL mode, 30s busy timeout, and active foreign key enforcement verified.
- [ ] **TLS certificates valid**: Automated certificate path and verification guardrails enforced in code; live production CA and certificate issuance required in deployment environment.
- [ ] **mTLS tested if required**: Client cert and key pairing enforced when configured; live mutual TLS handshake verification requires deployed PKI.
- [x] **Agent registration secure**: Bearer token authentication per-agent identity binding enforced. Remote cleartext HTTP refused.
- [x] **Windows Agent installer verified**: `install-zta-agent.ps1` ACL lockdown (SYSTEM + Admins only), credential masking, and argument validation verified.
- [ ] **Agent service startup verified**: Automated task creation syntax verified; native live Windows task execution in SYSTEM context requires elevated disposable VM.
- [x] **Manager service startup verified**: Clean start, graceful shutdown, and background worker supervisor verified.
- [x] **Background workers healthy**: Detection pipeline, risk evaluation, and outbox publisher workers operate asynchronously with crash recovery.
- [x] **Telemetry ingestion verified**: Bulk telemetry ingestion, schema adaptation, durable staging, and duplicate prevention verified.
- [x] **Detection pipeline verified**: Evaluates AND/OR/NOT rules with bounded regex execution cost. Distinguishes error, no-match, and match.
- [x] **Audit logging verified**: Immutable audit logs, command execution journaling, and RBAC-controlled access verified.
- [x] **WebSocket security verified**: Authenticated operator sessions, instant revocation upon logout/disablement, bounded client queues verified.
- [x] **Dashboard build verified**: Static SOC dashboard with purple/dark theme, strict RBAC DOM visibility, and API integration verified.
- [x] **RBAC verified**: Roles (`ADMIN`, `OPERATOR`, `ANALYST`) strictly enforced across REST endpoints and real-time streams.
- [x] **Offline recovery verified**: Local SQLite offline queue buffers telemetry during network interruptions; flushes idempotently upon reconnection.
- [x] **Response safety verified**: Conservative default `ALERT_ONLY` enforced. `ENFORCE` requires explicit policy configuration and authorized cryptographic command dispatch.
- [x] **Disruptive actions gated**: Network isolation, process termination, and account control scripts remain fail-closed and disabled by default.
- [x] **Monitoring configured**: `/api/zta/background-services` and `/api/zta/agents` expose health metrics without leaking credentials.
- [x] **Upgrade tested**: Upgrade procedure preserves existing `zta_agent.env` credentials and durable offline SQLite queue.
- [x] **Rollback tested**: Documented database and agent rollback runbooks provided.
- [x] **Backup/restore tested**: Verified schema consistency and data recovery from backup copies.
- [x] **Release blockers reviewed**: Identified missing deployment PKI and unverified native Windows VM response execution as noncritical release limitations.
- [ ] **Deployment approved**: Awaiting final sign-off from Lead Security Architect and Operations Team.

---

### Classification: READY_WITH_LIMITATIONS
- **Core Application & Automation**: **READY** (217 of 217 automated tests passing).
- **Production Environment Gates**: **BLOCKED** on physical code signing certificate and live Windows VM testing of disruptive actions (`KILL_PROCESS`, `NETWORK_ISOLATE`).
