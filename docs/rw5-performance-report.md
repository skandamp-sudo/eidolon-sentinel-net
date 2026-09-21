# RW-5 performance report — no benchmark executed

**NOT RUN: mandatory scientific design review stop.** This is a measurement plan and status record, not a performance baseline. See [resource audit and decision](rw5-resource-hardening.md).

## Actual results

| Requested measurement | RW-5 result |
|---|---|
| Packets processed / flows completed / events generated / bytes processed | Not measured |
| Wall-clock duration | Not measured |
| Packets/sec / flows/sec / processing Mbps | Not measured |
| Packet latency p50/p95/p99 | Not measured |
| Finalization-to-event latency p50/p95/p99 | Not measured |
| Inference latency p50/p95/p99 | Not measured |
| Persistence latency p50/p95/p99 | Not measured |
| Publication latency p50/p95/p99 | Not measured |
| Initial / peak / final RSS | Not measured |
| Active-flow / queue / subscriber peaks | Not measured |
| Sustained workloads A–E | Not run |
| Real-interface validation | NOT VERIFIED; not attempted due semantic stop |
| Kernel capture drops | NOT AVAILABLE from current capture adapter |

[Benchmark JSON](rw5-benchmark.json) uses `null` for measurements, not invented zeros. `harness_implemented` is false. [Environment inventory](rw5-environment-manifest.json) records the actual inspection environment; no workload/model/hash is fabricated. Available inventory: macOS 26.7, x86_64 process architecture, 16 reported logical CPUs, Python 3.12.14, NumPy 2.5.2, SciPy 1.18.1, scikit-learn 1.9.0, XGBoost 3.4.1, joblib 1.6.0 and Scapy 2.7.0. CPU model, physical cores and RAM were unavailable to the unprivileged inventory queries; their exact query failures are recorded in JSON. This is not a complete benchmark environment manifest, because no benchmark occurred.

## Proposed reproducible harness — not implemented

Use a standalone offline operator harness with an explicit local approved model identity, PCAP path and output directory. Load using the existing RW-4 loader; no training/fallback. Process through the production source/parser/shared worker, feature extraction, frozen inference/evidence, real temporary SQLite, and EventBus output. A bounded consumer observes publications. Include authenticated REST/WS identity consistency as an integration check; publication into EventBus is not the same as delivery to a WebSocket client.

For reproducibility record: input SHA-256 and workload generation seed/recipe; model name/version/manifest digest; schema; effective limits/timeouts/queue sizes/retention settings; subscriber behavior; exact library versions; CPU/core/RAM/OS; process architecture; DB journal/synchronous settings; warm-up policy; repetitions; elapsed duration and start/stop criterion. Do not use an existing historical metric report as evidence for a newly loaded candidate.

Rate denominator: monotonic elapsed time from source processing start through EOF/stop, accepted-input drain, final durable output and publication. Report cold model loading and warm-up separately. Count all source observations and successfully processed packets separately. Define bytes explicitly (for example accepted parsed IP bytes); do not label IP-byte throughput as wire-rate/link capacity. Derive:

```text
packets_per_sec = successfully_processed_packets / measured_elapsed_seconds
flows_per_sec   = completed_flows / measured_elapsed_seconds
processing_Mbps = counted_IP_bytes * 8 / measured_elapsed_seconds / 1_000_000
```

An empty/zero-duration run must produce unavailable rates with a reason, not infinity or manufactured capacity. Include drain time and state whether subscriber transmission completion is part of the chosen end boundary.

### Latency boundaries

Use monotonic runtime timestamps within a process. Historical PCAP timestamps remain exclusively the recorded flow-time input.

| Measurement | Proposed start/end and interpretation |
|---|---|
| Live queue residence | Capture callback acceptance/enqueue → worker dequeue; excludes time spent in NIC/kernel before observation |
| Packet worker latency | Worker receipt → packet processing and attributable downstream work completed; declare whether a packet that finalizes a flow includes inference/persistence |
| Replay processing latency | Source delivery to worker → processing completion; pacing delay reported separately, never wall-clock minus PCAP epoch |
| Flow finalization → event | Actual aggregator finalization → successful persist-and-publish completion; a timestamp first taken when draining completed flows omits waiting and must be named a drain-to-event proxy |
| Inference | Entry/exit around existing model inference; separately label evidence-inclusive versus model-only measurements |
| Persistence | Immediately before awaited `store_event` → successful committed return; failures/timeouts get separate counts and durations |
| Publication | EventBus publish entry → return; measure subscriber send separately if claimed |

Precise finalization/model-internal instrumentation may require a reviewed observation hook in protected code. Do not quietly weaken the byte-identical requirement or relabel an external proxy as exact internal latency. This is another design detail to resolve before implementing the harness.

Percentiles must state sample count, timing window, estimator/method, warm-up exclusion and any sampling/error bound. Use fixed-memory telemetry histograms or bounded windows for sustained monitoring; label approximate/windowed percentiles honestly. If exact full-run percentiles are required, bound the run/sample count or explicitly budget external storage. Never introduce an all-run latency list under the guise of observability. This telemetry policy is separate from the prohibited approximation of canonical ML features.

### Sustained workloads and memory

Proposed workloads are non-offensive offline synthetic PCAPs, clearly labeled, or authorized recorded traffic:

- A: reproducible mixed protocols and flow lengths, ordinary metadata only.
- B: high five-tuple cardinality around and beyond the configured active-flow limit.
- C: one continuously active long-lived conversation to expose per-flow history growth.
- D: bursts that fill the configured input queue.
- E: deliberately slow subscribed consumers and deterministic SQLite slow/locked/failing scenarios.

The current pull-based replay source cannot demonstrate live capture-queue saturation. D requires a bounded local source/queue feeding the same worker, using preconstructed records in memory and no packet transmission. Never equate pull replay throughput with an independently driven network capture rate.

Run a short smoke check first, then predeclare a sustained duration long enough to cross several retention cycles and detect a trend; report the actual duration. No duration or run was selected here. Sample RSS, active-flow occupancy, capture/subscriber queues, drop counters, DB/WAL sizes and latency windows with bounded telemetry storage. Obtain initial RSS after a documented warm-up boundary, sample peak and final RSS at fixed points including drain. Disclose sampling interval: sampled peak RSS can miss shorter spikes. Distinguish explicit configured bounds from empirical stability; a flat short trace is not proof of bounded memory.

Do not run the long-lived-flow workload indefinitely on the present unbounded history implementation. Define resource stop criteria before execution, and report an aborted run as aborted rather than successful capacity validation. Observe logical database rows and physical file allocation separately. Validate no duplicate IDs and required persistence-before-publication ordering under pressure; do not promise global timestamp ordering or exactly-once WebSocket delivery unless the contract supports it.

## Verification and decision

No new tests or scientific evaluation were run. The last verified RW-4/UI results remain **631 backend tests (14 warnings), 61 frontend tests across 5 files, strict TypeScript/build PASS, and seven frozen-model live/replay parity scenarios PASS**. They are historical baseline results, not RW-5 sustained-load evidence. The one fresh verification is [23/23 scientific-file SHA-256 matches](rw5-scientific-integrity.json).

No performance or production-readiness claim is justified by this pass. The next engineering work is resolution/completion of RW-5, not intelligence expansion.

**NO-GO FOR SIH INTELLIGENCE HARDENING** — exact-history resource policy is unresolved; no new harness, sustained-load measurements, operational retention or real-interface validation has been completed.
