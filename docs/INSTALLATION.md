# ZTA Platform installation

Run from the unified project root:

```bash
bash install-zta.sh
.venv/bin/python -m zta
```

Open http://127.0.0.1:8000. The local agent API listens on port 8080.

To verify the ZTA application:

```bash
.venv/bin/python -m pytest -q
```

The direct launcher is `dashboard/run_dashboard.py`. Dependencies are declared in `pyproject.toml`; `requirements.txt` is retained for compatibility. Configuration files are in `etc/` and PowerShell templates are in `powershell/scripts/`.

The native EDR source is in `src/`, with its installer at `install.sh`. It requires a separate build and deployment; installing the local dashboard does not deploy the native manager or Windows services. Response actions exposed by the local API remain dry-run previews.

See [the project README](../README.md) for full structure, API routes, database paths, and integration status. Native installation documentation is preserved under `reference/native/INSTALLATION.md`.

## Production prerequisites and recovery

- The built-in HTTP servers bind to loopback and do not terminate TLS. Place the Manager behind an approved HTTPS reverse proxy, or otherwise provide trusted TLS before remote Agent use. Agents reject non-loopback cleartext Manager URLs.
- Configure `ZTA_AGENT_TOKENS` and an operator bootstrap path in the service environment. Never place credentials in source-controlled configuration.
- Agent mTLS is enabled only when both `ZTA_CLIENT_CERT` and `ZTA_CLIENT_KEY` are present; `ZTA_CA_BUNDLE` selects the trusted CA bundle. Certificate issuance and rotation require deployment infrastructure.
- SQLite is the implemented database. Redis and PostgreSQL are not runtime dependencies in this repository.
- Stop the Manager before a filesystem-level backup. Preserve the database file together with any `-wal` and `-shm` companions, or use the SQLite online-backup API from an authorized maintenance tool. Restore into an isolated location first, start the Manager against the restored path, and verify `/api/zta/overview` and migration startup before cutover.
- Manager health is exposed through `/api/zta/background-services`; Agent health, queue depth and last heartbeat are available through `/api/zta/agents`.
- Manager operational logs use the service supervisor's stdout/stderr destination. Agent rotating JSONL logs default to `logs/zta-agent.jsonl`; its durable queue defaults to `storage/zta_agent_offline.db`.

The Windows installer requires an elevated disposable/production endpoint, protects its installation directory for SYSTEM/Administrators, creates a dedicated virtual environment, and registers the `ZTA Endpoint Agent` scheduled task. This repository's automated tests validate its command construction and security contracts; actual task registration, Sysmon access and native responses remain **REQUIRES REAL WINDOWS TEST**.
