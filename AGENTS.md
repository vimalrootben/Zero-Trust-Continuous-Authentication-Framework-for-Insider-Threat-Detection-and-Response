# Project instructions

This is the ZTA endpoint detection and response platform. For repository-related
requests, consult the local Graphify graph first to locate relevant code.

- Start with `.\graphify.cmd query "<focused task question>" --budget 1000`.
- Follow up with `.\graphify.cmd explain "<symbol>"` or
  `.\graphify.cmd path "<source symbol>" "<target symbol>"` as needed.
- Read only the relevant source ranges returned by the graph before making
  claims or edits. The current source and tests are authoritative.
- Do not load the entire graph.json, HTML, or GRAPH_REPORT.md into context for
  routine tasks. Use scoped query output to reduce unnecessary context.
- If graphify-out/graph.json is missing, stale after source changes, or incomplete,
  run `.\refresh_graphify.cmd`, then retry once.
  If a query has no matches, try a precise symbol or filename before refreshing.
  If Graphify fails, use targeted source searches and report the limitation.
- Refresh after changing source or dependencies when graph-based work continues.
  Do not rebuild on every prompt when the source has not changed.
- Static AST edges do not prove runtime HTTP/WebSocket behavior. Verify security,
  authentication, network, and dynamic flows in the relevant source and tests.
- Read again.md only when a project overview or reusable onboarding prompt is needed.
- Keep changes minimal; preserve unrelated local work and run relevant tests.
- Never collect secrets, runtime databases, logs, or build/test snapshots into graphs.

These instructions apply to chats opened with this folder as the Codex project.
They do not configure unrelated chats or other assistants automatically.
