# Wazuh source inspection and data-flow verification

Inspection date: 2026-09-08. Project: `/home/ben/Projects/wazuh-main`.

Status: **partial source map; baseline and end-to-end Sysmon flow NOT verified**.
This document records inspected code, not evidence of a running deployment.

## Repository and baseline

- Core source resides in the project root; `VERSION.json` declares version `5.1.0`, stage `alpha0`.
- The project root does not contain `.git`. Exact upstream commit, provenance, local diff and untouched baseline cannot be established from this snapshot.
- Dashboard, indexer and OpenSearch Dashboards versions are unknown. No `opensearch_dashboards.json` was found in the core source tree.
- `docs/BASELINE.md` claims a verified `src/analysisd` baseline and XML rules. `src/analysisd` and `ruleset/rules` do not exist in this tree.
- Windows enrollment, heartbeat, Sysmon collection, detection, indexing, dashboard and Active Response have not been demonstrated by this inspection. Deployment OS and Docker/non-Docker status remain unverified.
- Custom ZTA modules are now in `agent/`, `engine/`, `storage/`, `dashboard/`, and `api/server.py` in the unified project root.

## Source-confirmed event transport and output points

Paths below are relative to the project root.

| Stage | Source and symbol | Confirmed behavior |
| --- | --- | --- |
| Windows collection | `src/logcollector/src/read_win_event_channel.c`: `event_channel_callback`, `send_channel_event` | Subscribes with `EvtSubscribe`; renders event XML with `EvtRenderEventXml`; calls `SendMSG(..., "EventChannel", WIN_EVT_MQ)` at line 360. |
| Windows forwarding | `src/win32/win_utils.c`: `SendMSG`, `SendMSGAction` (line 418) | Wraps the message and calls `w_https_client_submit_event`. The source explicitly describes HTTPS `/stateless` accumulation. |
| HTTPS batching | `src/client-agent/https_client/src/statelessStream.hpp` | Implements the `/stateless` sender abstraction. |
| Manager forwarding | `src/remoted/remoted_module/src/endpoints/statelessEndpoint.cpp`: `makeHandler` | Uses an authenticated handler and `DeferredForwarder::forward` toward engine event ingress. |
| Engine ingress | `src/engine/source/api/event/src/handlers.cpp`: `pushEvent` | Parses NDJSON with `protocol::parseNDJson` and queues events using `orchestratorRef->postEvent`. Acceptance is not proof of detection. |
| Processed event output | `src/engine/source/builder/src/builders/stage/indexerOutput.cpp`: `indexerOutputBuilder` | Validates an index prefix of `wazuh-events-v5-`, then calls `wic->index(finalIndexName, event->str())` at line 135. Actual target depends on loaded content. |
| Indexer connector | `src/engine/source/wiconnector/src/windexerconnector.cpp` | Connector implementation; adjacent README documents indexing and retrieval of policy content. |

The source points establish collection, forwarding, ingestion and an output stage. They do not establish the active Sysmon decoder, loaded detection policy, matched rule or final event schema. The precise intermediate decoder/rule execution chain remains to be traced against loaded content.

Do not describe this checkout as the traditional `analysisd -> alerts.json -> Filebeat` pipeline without additional evidence.

## Sysmon process-create trace: evidence still required

Target input: a benign Sysmon Event ID 1 from `Microsoft-Windows-Sysmon/Operational`, collected from an owned Windows test VM. Capture the original XML including timestamp, event record ID, image, command line, process identifiers and parent image.

- **Captured raw event:** unavailable in the inspected project evidence; no authentic sample is asserted here.
- **Captured resulting alert/indexed document:** unavailable. Export the complete document, `_index` and `_id` from the running baseline before defining the adapter contract.
- **Decoder:** unresolved. `sysmon_event1` is asserted in `docs/ZTA_DATA_FLOW.md`, but no corresponding implementation was found in the core source search.
- **Rule ID:** unresolved. `184666` appears in custom documentation/tests; no matching core rule implementation was found. Treat it as a synthetic fixture value, not a verified Wazuh detection.
- **Synthetic example:** `tests/test_full_pipeline.py` supplies an input dictionary with `id=evt-001`, rule `184666`, and `data.win.eventdata.image/commandLine`. It manually applies risk deltas. It is not a captured Wazuh alert or a Windows-to-response end-to-end test.

After a benign process-create trace succeeds, repeat with controlled encoded PowerShell activity to establish the actual detection, rule metadata and MITRE mapping. Also capture Windows authentication and PowerShell channel events separately.

## Dashboard data path

The existing UI is `dashboard/index.html`, hosted by Python `SimpleHTTPRequestHandler` in `dashboard/run_dashboard.py`. Its custom API is `zta/api/server.py`. This is a standalone UI, not a verified Wazuh/OpenSearch Dashboards plugin.

The API hardcodes endpoint entries, risk distribution and containment counts. Its heartbeat route acknowledges input and returns an empty command list. These responses do not establish ingestion into the correlation/risk pipeline.

The Wazuh Dashboard repository, plugin versions, index-pattern/data-view configuration and actual query path are not available in this project inspection. They must be mapped in the matching dashboard checkout.

## Recommended Zero Trust integration boundary

Provisionally use the separate-service approach (Option A), consuming processed indexed events through an authenticated, read-only interface after validating the actual schema. For this tree, the indexer output stage is a candidate boundary; no supported external consumption API or deployment contract has been verified yet.

Before implementing consumption, pin the source/content versions, confirm event identity, define durable checkpoints and deduplication, and test restart/replay behavior. Preserve the original event and its index/document references. Verify low-severity authentication events are actually available for correlation.

Do not wire the existing adapter to an assumed `alerts.json` path or insert Python into manager internals at this stage.

## Implementation gaps affecting the supplied plan

1. **Response authorization and routing:** `zta/api/server.py` accepts action requests without authentication/authorization and lets the caller set `dry_run=false`. It directly invokes `AgentCommandReceiver`; `PowerShellExecutor` runs a local subprocess. `agent_id` does not select a remote execution target. Default localhost binding limits exposure but does not implement SOC permissions or endpoint routing.
2. **Command verification:** `agent/commands/command_receiver.py` describes signed commands but implements no signature, expiry or replay validation. Script allowlisting exists; parameter validation is a character blacklist rather than per-action typed schemas.
3. **Incorrect success semantics:** `zta/engine/response/engine.py` reports unknown/unimplemented actions as successful monitoring actions. Dry-run validation is also reported as success; this is not endpoint execution evidence.
4. **State durability and decay:** `zta/engine/risk/engine.py` keeps active scores/history in dictionaries. Its decay method has no incident-state guard and can reduce critical risk to the minimum without checking an unresolved incident.
5. **Adapter validation:** `zta/engine/events/wazuh_adapter.py` fabricates missing identity/time defaults and classifies any event containing an image as process creation. Its expected `data.win` schema has not been validated against this core version's output.
6. **Baseline and branding:** existing branding, custom agent work and a standalone dashboard precede the verified baseline required by the plan.

## Validation performed

Read-only source inspection and targeted searches. No installers, endpoint response actions or services were started. Existing source and prior documents were preserved.

Attempted selected adapter, synthetic pipeline and PowerShell dry-run tests with bytecode/cache disabled. Execution failed before collection: `/usr/bin/python: No module named pytest`. No test pass claim is made. Full deployment/end-to-end checks were not run.

## Next dependency and completion criteria

Establish a reproducible, version-pinned Wazuh baseline, including matching indexer/dashboard and loaded detection content. Record source provenance and tested deployment configuration. Then capture one real Sysmon XML event and its indexed result, verify the decoder/rule, and complete the dashboard query trace.

This first reconnaissance task is complete only when those missing artifacts and exact detection links are present. Feature integration should remain pending until then.
