# Reusable project prompt

Work on the Zero Trust Continuous Authentication Framework for Insider Threat
Detection and Response in this project folder:
`C:\p\Zero-Trust-Continuous-Authentication-Framework-for-Insider-Threat-Detection-and-Response-main\Zero-Trust-Continuous-Authentication-Framework-for-Insider-Threat-Detection-and-Response-main`.

This Python ZTA/EDR platform contains:
- agent/: telemetry collectors, durable offline queue, heartbeat and signed commands.
- api/: HTTP routes, operator sessions/RBAC, agent authentication, ingestion,
  background workers and WebSocket updates.
- engine/: correlation, rule conditions, risk/trust, adaptive policy and response.
- storage/: SQLite schema, repositories and evidence persistence.
- dashboard/: HTML/CSS/JavaScript operator UI using REST and WebSocket APIs.
- powershell/: allowlisted Windows response and execution verification.
- tests/: regression and integration coverage. Runtime dependencies are requests
  and regex; Python 3.11+ is required.

Before exploring this repository, follow AGENTS.md and query Graphify with
`.\graphify.cmd query "<my specific task>"`. Use the returned file/symbol links
to inspect only relevant source. Avoid reading the whole repository or full graph.
The graph is a navigation aid; confirm behavior in source and tests before edits.
Regenerate missing/stale graphs with `.\refresh_graphify.cmd` (local code-only
extraction, no LLM or API key). Continue with targeted searches if extraction fails.
Do not assume every dynamic route or frontend/backend edge is statically resolved.

Interactive views: graphify-out/graph.html and graphify-out/callflow.html.
This prompt aims to reduce repeated discovery/context; it does not guarantee a
fixed token saving, and ordinary assistant conversations still consume tokens.
