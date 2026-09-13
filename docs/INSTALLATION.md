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
