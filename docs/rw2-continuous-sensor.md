# RW-2: continuous passive sensor service

## Scope and operation

`sentinel-net sensor` owns a long-running receive-only capture service and its API in one process. It does not train models, scan hosts, inject packets, modify traffic, or provide remote capture controls. The public product page and existing SOC routes are preserved.

```sh
# Provision a private API key through the environment or a protected .env file.
# The directory must contain an already fitted DetectionPipeline saved by the
# existing ModelRegistry, including model.joblib and manifest.json.
sentinel-net sensor --interface en0 --model /absolute/registry/runtime/1.0.0
```

Use an interface actually present on the capture host; `en0` is only an example. `SENTINEL_CAPTURE_INTERFACE` and `SENTINEL_SENSOR_MODEL` are equivalent configuration options. Database, BPF filter, queue limits, and idle timeout use existing `SENTINEL_*` settings. `--host` and `--port` control the API listener, defaulting to loopback. API credentials are not printed.

There is **no deployable trained artifact in this working tree**. An operator must supply an approved, already-fitted complete `DetectionPipeline`; startup fails without one. The existing `ModelRegistry.save_model(pipeline, manifest)` can persist an approved in-memory pipeline without training it. `--model` points to its `<registry>/<model_name>/<model_version>` directory. The loader checks manifest identity, schema version, checksum, pipeline type, and fitted flags before capture. It preserves the pipeline's existing preprocessor, classifier, anomaly detector, thresholds and optional anomaly explainer. Joblib deserialization requires an operator-trusted artifact; a checksum does not establish trust. This is a minimal loader using the existing registry, not a new frozen-bundle or artifact-distribution phase.

## Architecture and ownership

`SensorService` owns the lifecycle, capture source, bounded packet queue, live processing worker, database, event bus, metrics, health monitor and cleanup. FastAPI borrows these exact resources through its lifespan. `SensorServer` is the CLI adapter that requests shutdown and quiesces the service before stopping API clients.

```text
Receive-only L2 socket → Scapy AsyncSniffer → bounded capture queue
  → existing packet parser → existing flow aggregator
  → shared infer_completed → existing FeatureExtractor / DetectionPipeline
  → existing evidence enrichment → shared persist_and_publish
  → SQLite commit → EventBus subscriber queues → authenticated WebSocket
                  ↘ authenticated REST / SOC
```

Recorded replay continues to use the same parser, aggregator, extractor, inference and enrichment classes. Live and replay now call the same completed-flow inference helper and the RW-1 durable output helper. Their input scheduling remains separate: capture uses a wall clock only when its queue is empty; replay uses recorded timestamps and EOF. RW-2 does not force replay through a wall-clock live worker.

## Startup and lifecycle

1. Transition STOPPED → STARTING; validate positive finite limits, interface syntax/existence and BPF safety.
2. Initialize SQLite.
3. Load the trusted already-fitted pipeline in a worker thread.
4. Initialize event bus and bounded capture queue.
5. Start processing worker with the owning asyncio loop and database.
6. Open the receive-only capture socket synchronously, verifying interface/filter/permissions; wait for Scapy worker readiness.
7. Transition to RUNNING and start operational monitoring.

Any failed stage closes opened resources and leaves FAILED, with a useful stage-specific local error. No failed startup reports RUNNING. Startup does not prove sustained throughput or operating-system capture quality.

The live lifecycle is `STOPPED → STARTING → RUNNING → [DEGRADED] → STOPPING → STOPPED`. Fatal capture/worker/startup/shutdown failures end in FAILED and request process shutdown. DEGRADED latches operational error/drop reasons for the run, even if the condition later subsides. Processing can continue while degraded. Cleanup after a processing or persistence failure retains FAILED as the terminal result. A service instance is one-shot; construct a new owner to restart. Replay retains REPLAYING / REPLAY_COMPLETE / ERROR and a separate recorded-traffic mode label.

## Shutdown

SIGINT and SIGTERM use the CLI's signal handler. It requests shutdown without waiting for packets. Repeated signals remain graceful.

1. Mark STOPPING and stop the health monitor.
2. Stop accepting capture callbacks. Wake Scapy's control socket and join capture, including while idle.
3. Clear the processing run flag; drain already accepted packets.
4. Finalize active flows once; finish extraction, inference and evidence.
5. Commit each remaining event before publishing it.
6. Allow subscriber queues up to 1.5 seconds to drain while the API is still alive.
7. Stop API connections; Uvicorn allows up to 5 seconds for connection tasks, then cancels them. WebSocket cleanup accounts for queued and in-flight undelivered copies.
8. Close event bus, count remaining queue copies as dropped, close SQLite, freeze uptime, and mark STOPPED or retain FAILED.

Zero subscribers is valid: persistence continues, and an event with no delivery recipients is not counted as dropped. WebSocket delivery is best effort; reconnecting clients recover durable events through REST. A socket send completion is not an application-level client acknowledgment.

Capture join has a 5-second bound and processing join a 30-second bound. A surviving worker is a shutdown failure, never a clean STOPPED result, and its database is not closed underneath it. A native library or I/O call that hangs beyond those bounds requires operator intervention; this phase does not promise recovery from uninterruptible native code. Tests cover normal busy and idle shutdown, not a wedged kernel or hung model library.

## Health and failure behavior

- `/health`: safe live state/mode/reason codes, distinct from model detections. API-only mode retains its existing liveness response.
- `/readiness`: SQLite check plus RUNNING requirement in live mode; returns 503 for degradation/failure/stopping.
- Authenticated `/api/v1/status`: lifecycle, explicit source mode, metrics, schema and subscriber count.
- No REST start/stop or arbitrary interface selection endpoint was added.

Permission/filter/interface failures prevent startup. Capture worker death requests shutdown. Malformed/unhandled packet and inference errors increment counters; other accepted work continues. A SQLite write failure increments persistence errors, never publishes that event, and degrades the run. It is not retried automatically and cannot be recovered from SQLite if it never committed; retain source captures independently where required. Failures never become threat events. Queue overflow drops only the overflowing packet or subscriber copy and increments the appropriate counter. Safe reason codes contain no interface names, filesystem paths, exceptions or credentials.

## Counter semantics

| Metric | Meaning |
|---|---|
| packets_received / packets_observed | Capture callbacks observed, including rejected/overflowed packets; aliases |
| packets_parsed | Packets successfully parsed (or supplied as ParsedPacket by test/replay input) |
| packets_processed | Packets successfully ingested into aggregation |
| packets_malformed | Unparseable/non-IP packets, plus capture serialization failures; existing classification retained |
| packet_errors | packets_malformed + packet_processing_errors; excludes queue drops |
| packet_processing_errors | Exceptions during packet parsing/aggregation |
| packets_dropped | Capture queue overflow |
| flows_created | Aggregator-created flow segments, including segments later evicted |
| flows_completed | Finalized flows handed to inference, including failed extraction/inference attempts |
| flows_active | Currently active aggregate segments |
| flows_evicted | Cumulative capacity evictions, which are finalized rather than silently discarded |
| features_generated | Successfully extracted vectors |
| detections_generated | Actual generated events submitted to durable output, including later write failures |
| events_persisted | Successful SQLite commits |
| persistence_errors | Failed event writes |
| events_enqueued | Successful per-subscriber queue insertions; one event can produce multiple copies |
| events_delivered | Completed WebSocket event sends; not client acknowledgments |
| events_dropped | Undelivered subscriber copies: overflow, disconnect, failed send or shutdown |
| subscriber_count | Current EventBus subscribers; also exposed as websocket_subscribers |
| sensor_uptime / uptime_sec | Elapsed time since RUNNING, frozen after drain; zero before successful startup |
| processing_errors | Processing/output failures; may overlap packet/persistence counters |
| capture_errors | Capture initialization/worker/stop failures |
| capture_queue_depth | Sampled queue depth; 80% or higher can latch queue-pressure degradation |

`detection_queue_depth` remains a legacy zero gauge: this worker processes completed flows inline, not through a second queue. Operating-system/kernel packet-drop counters are not measured by these metrics. Existing snap-length/buffer settings are not applied by this adapter; capture uses backend defaults. Do not interpret their configured values as verified kernel limits.

## Verification and scientific compatibility

Focused tests use injected capture and real SQLite. Real-model integration uses synthetic training fixtures solely for test isolation, then unmocked parsing, extraction, XGBoost/Isolation Forest inference, evidence, persistence, REST and authenticated WebSocket delivery. No production model was trained or changed. Four subprocess checks send real SIGINT/SIGTERM in busy and idle cases through the CLI signal handler. An actual Scapy control-pipe test verifies idle select wakeup without network privileges.

`rw2-scientific-integrity.json` records pre-RW-2 SHA-256 values for all feature, detection, explainability modules and the flow aggregator. Every recorded file remains byte-identical. The canonical feature schema remains 52 names in the same order, version 2.0.0. A serialization round-trip test verifies identical scores, thresholds and transformed feature names. RW-1 replay/REST/WebSocket regressions remain in the full suite.

RW-1 flow-segmentation corrections can alter runtime predictions. Historical scientific metrics have **not** been reproduced in RW-2; they require explicit scientific revalidation on the corrected segmentation and approved model artifacts.

## Remaining long-running risks

- Per-flow timestamps and packet-size histories remain unbounded for never-idle flows. Bounding active-flow count does not bound each flow's memory.
- Existing offline analysis can accumulate flows/vectors/results. RW-2 does not route live capture through that accumulating path.
- SQLite history grows without a service-owned retention scheduler in this phase. Existing retention settings are not a claim that this service enforces them.
- No full resource-budget, sustained-load, throughput, kernel-drop or deployment-security validation was performed.
- Link-layer behavior beyond the existing parser's supported traffic and host-specific capture backend remains environment-dependent; Ethernet TAP/SPAN input is the primary manual validation target.
- API access can create observed traffic if management and capture interfaces overlap. Use a separate management interface/network where appropriate.

## Manual real-interface validation (not executed here)

1. Supply an approved fitted registry artifact and privately configured API key. Set a temporary database location and verify available interfaces locally.
2. Use an authorized passive TAP/SPAN capture interface and the minimal capture permissions required by the host. Keep API binding on loopback or a designated management interface. No scanning, injection or test traffic generation is needed.
3. Run the command above. Confirm RUNNING only after startup, schema 2.0.0 / 52, and live source mode. Connect the SOC with the same API endpoint/key.
4. Observe existing ordinary traffic. Confirm increasing receive/processed/flow counters and matching persisted records in REST and authenticated WebSocket events. Inspect degradation and drop counters separately from detection scores.
5. Send SIGINT while traffic is present. Confirm final records persisted and process exit after drain. Repeat with SIGTERM on an idle interface; it must not wait for a new packet.
6. Repeat with an invalid interface, unavailable capture permission, and a temporary unwritable database. Expect explicit startup failure and no RUNNING state. Never perform destructive fault injection on production data.
7. Document OS, interface/link type, capture backend, model manifest, observations and exit status. This is deployment validation, not a benchmark or scientific accuracy evaluation.

## Proposed RW-3 design — not implemented

Introduce a small passive-source protocol exposing packet iteration, source identity, capture-time watermark, EOF and stop/drain behavior. Implement live-queue and PCAP sources around the existing adapters. Move source-independent orchestration onto one processing owner, retaining explicit source-time policies: no wall-clock expiration of paused historical replay, EOF flush once, and live idle expiration only after accepted packets drain. Preserve one event serializer, one durable output path and distinct LIVE/REPLAY labels. Add raw-packet → feature → score → event parity fixtures before removing old orchestration. Do not add intelligence or new models in that work.

## Git recommendation

The pre-RW-2 working tree contained RW-1, frontend/product-page work and unrelated presentations/assets. No commit or staging operation was performed. Commit reviewed RW-1 runtime/security changes first, then the product page independently, then review only the RW-2 files listed in the completion report. Shared files need hunk-level staging or reconstruction against a saved baseline; `git add .` is inappropriate here.

Suggested RW-2 commits: `feat(sensor): assemble continuous passive sensor service`; `feat(cli): add passive sensor runtime command`; `test(sensor): cover lifecycle and graceful shutdown`; `docs(sensor): document real-world passive deployment`. Keep each commit coherent with its imports/dependencies, or use one bounded RW-2 implementation commit plus separate tests/docs after the baseline is committed. Stop before RW-3.

## Completed checks

- Full backend suite: **576 passed, 14 warnings** (36 tests added over the 540-test RW-1 baseline).
- Full frontend suite: **57 passed across 5 files** (3 tests added).
- TypeScript check: **PASS**. Frontend production build: **PASS**.
- Full suite includes the real RW-1 replay-to-REST/WebSocket regression and RW-2 raw-packet-to-real-model delivery regression.
- Additional actual CLI/Uvicorn smoke runs bound only to loopback with injected synthetic capture. SIGINT and SIGTERM each persisted all 8 accepted flow records, reached STOPPED, exited with status 0, and did not log the test API key.
- Real privileged interface capture, throughput benchmarks and historical scientific metric reproduction: **not run**.
- Existing security assertion corrected to allow receive-only AsyncSniffer only in capture.py; all transmit imports remain prohibited, with a new AST assertion prohibiting transmit calls/socket factories.
