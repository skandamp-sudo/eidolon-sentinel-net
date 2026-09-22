> **Historical RW-5 audit, superseded by RW-5B.** The user accepted exact per-flow history growth for the SIH prototype. See [RW-5B operational validation](rw5b-performance-report.md) for implemented retention, measured workloads, regression gates, and the current GO/NO-GO decision. The original audit below is retained as historical evidence.

# RW-5 resource audit — stopped for scientific design review

**Status: audit/design only; RW-5 is not complete.** No runtime, scientific, frontend or test code was changed. No retention scheduler, performance harness or new resource policy was implemented.

The brief explicitly requires: “Where an exact feature requires quantiles/median and cannot be reproduced exactly without full history: STOP and report the scientific trade-off before changing semantics.” It also requires stopping if resource bounds require canonical semantic changes. The current implementation reaches that gate. This report documents the decision before any behavioral change.

## Resource-bound audit

Bounds below are source-code defaults, not guarantees about an operator's deployed configuration. A bounded object count is not necessarily a bounded byte footprint.

| State | Current owner | Current bound | Failure mode | Proposed bound (not implemented) | Semantic impact |
|---|---|---|---|---|---|
| Active conversations | `flow/aggregator.py`, `_active` | `max_active_flows=100000`; oldest-last-seen eviction | One conversation can still grow indefinitely; capacity eviction finalizes segments | Retain explicit active-count limit; separately resolve per-flow bound | Changing eviction or segment limits changes inference inputs |
| Forward/reverse timestamp histories | `_ActiveFlow.fwd_timestamps`, `rev_timestamps` | None per flow; append on every packet | Busy flows never idle out; memory grows with packets | Decision required: exact external history, or approved packet-count segmentation | Streaming arrival-order deltas are not equivalent with out-of-order packets |
| Packet-size history | `_ActiveFlow.packet_sizes` | None per flow | Memory grows; finalization/NumPy copies raise peak | Consider validated finite-domain histogram; otherwise exact external history or approved segmentation | Current extractor consumes full sequences; histogram integration touches protected code and numerical behavior |
| Directional IAT arrays | `FlowAggregator._finalize`, `ObservedFlow` | Up to directional packet counts minus one | Sorting, copied timestamp lists and IAT lists coexist at finalization | Exact ordered-history strategy required | Sorted timestamps define current gaps; dropping/reordering samples changes features |
| Pooled IATs and quantile scratch | `features/extractor.py` | Proportional to per-flow sample count | Concatenations and NumPy arrays create transient amplification | Resolve exact order-statistic representation first | Exact `iat_median` cannot be obtained from count/sum/min/max/variance alone |
| Retained packet objects | `_ActiveFlow.packets` | Disabled by default; unlimited when `store_packets=True` | Analysis mode can retain every parsed packet | Keep disabled in deployment; explicit analysis budget if enabled | Losing requested packet records changes analysis API output |
| Completed-flow queue | `FlowAggregator._completed` | Shared runtime drains each source iteration; EOF/expiry batches can scale with active-flow count | A batch contains potentially huge histories; undrained callers accumulate all completed flows | Bounded draining/iteration, preserving existing sort order and finalization timing | Naive immediate yielding can change whole-run output ordering |
| Live packet queue | `SensorService`, `LiveCaptureSource` | `capture_queue_size=10000` entries | Full queue drops incoming packets; no configured byte ceiling | Explicit entry and byte budgets, peaks and queue-delay measurement | Drops remove observations and may alter affected flow features; must remain visible |
| Capture backend buffers/packet size | Scapy listen socket/AsyncSniffer | `store=False`; backend owns buffering; configured snap length/buffer fields are not passed to socket construction | Advertised configuration is not evidence of effective kernel buffer/snap limits | Verify effective backend controls before claiming byte bounds | Truncation can change parsing/feature inputs; do not enable silently |
| Replay pending input | `PcapReplaySource` | One pending paced packet; pull-based | A single oversized record can still be large; per-flow state persists | Preserve pull-based reading; audit input-record byte limits separately | Rejecting/truncating input needs an explicit policy |
| Runtime flow/event output | `PacketProcessingPipeline` | Sequential per-flow inference and awaited persistence; no whole-run event list | Slow storage stalls processing and fills live queue; completed batch remains referenced | Preserve one pending durable write; expose latency/backlog; no unbounded retries | Failed durable writes must remain failures, never published successes |
| Subscriber event queues | `EventBus` | `event_queue_size=1000` per subscriber | Full queues drop delivery copies; event remains stored | Explicit per-subscriber and aggregate budgets | Delivery availability changes, not stored detection values |
| Subscriber registry and network sends | EventBus and WebSocket handlers | No application subscriber-count cap; one in-flight send per connection; transport has separate buffering | Total memory grows with subscribers despite per-queue limits | Subscriber cap plus bounded send time/transport review | Slow/disconnected clients must use REST for retained records; no exactly-once WS promise |
| Persistence buffering | Database write lock, aiosqlite, shared worker | Sensor submits/awaits one event at a time; no retry spool | Lock waits/I/O stalls block input draining; concurrent API reads use the same DB connection | Bounded DB concurrency and explicit lock/time policies after validation | A timeout must not abandon an uncertain write then duplicate it |
| Offline packet accumulation | `ingestion/replay.py`, `replay_sync()` | Entire PCAP materialized | RAM proportional to input packet count | Add streaming iterator; retain collecting API only when explicitly requested | Preserve ordering and existing collecting API contract |
| Offline flow/result accumulation | `PcapPipeline.process`, `PipelineResult` | Entire flow and feature result lists; completed queue not drained inside loop | All packets, finalized flows and vectors may coexist | Separate streaming analysis API from explicit collecting wrapper | Existing global `(start_time, conversation_key)` sorting needs retention/external sort or an explicit streaming-order contract |
| SQLite events | `storage/database.py` | Defaults exist: 100000 events / 168 hours; cleanup is not service-scheduled | Indefinite disk growth; current cleanup DELETE can remove arbitrarily many rows in one transaction | Lifecycle-owned periodic bounded deletion batches using existing defaults; not a new retention duration | Retention changes available historical records, not inference; document timestamp basis |
| SQLite flows, WAL and file allocation | SQLite | Event cleanup does not delete orphan flows; no explicit filesystem budget | Flow rows/WAL/file allocation can grow; deleting rows does not guarantee file shrinkage | Bounded orphan cleanup, checkpoint observation and explicit disk-pressure policy | Never remove flows referenced by retained events or in-progress transactions |
| Metrics state | `SensorMetrics` | Fixed set of scalar counters/gauges; no sample history | No RSS/peak/latency distributions; scalar processing time cannot produce percentiles | Bounded telemetry histograms/rings with documented window and precision | Telemetry approximation must be disclosed; never applied to canonical model features |
| Browser live-event state | `App.tsx` | 100 events and bounded ID cache; REST pages request 50 rows | Server/query/transport load is separate from UI list bound | Preserve current bounded UI state | No SOC redesign needed |
| Deployment bundle load | `deployment/bundle.py` | Fixed artifact inventory, but no total byte limit; verified bytes and deserialized objects coexist | Trusted but excessively large bundle can exhaust startup RAM | Operator artifact-size budgets evaluated against actual approved models | Reject oversize bundles explicitly; no substituted or partially loaded model |

`ws_queue_size` and `detection_queue_size` settings are not proof of active runtime queue bounds: the current WebSocket path subscribes directly to EventBus, and the shared worker has no separate detection queue. The capture callback's `packets_dropped` counts application-queue drops, not kernel losses.

## Scientific blocker and design alternatives

Protected `flow/aggregator.py` appends one size and one directional timestamp per packet. `store_packets=False` does not disable these histories. Idle expiry is not a maximum duration: continuous traffic on one tuple can grow them indefinitely. Finalization sorts directional timestamps and materializes adjacent gaps.

Protected `features/extractor.py` calculates exact NumPy packet-size median/p25/p75/p90 and `iat_median` over the concatenation of the two directional IAT lists. Its current global IAT semantics are **pooled directional gaps**, not gaps from a merged global timestamp stream; changing that during resource work would be a scientific change too.

Count/sum/mean/variance summaries do not determine a median. Even mathematically equivalent streaming mean/variance can differ from current NumPy reductions through floating-point evaluation order. Out-of-order observations mean a newly inserted timestamp can replace an existing gap with two gaps; simply taking differences between consecutive arrivals is incorrect. A sorted multiset can retain exact order statistics but still grows with distinct timestamps/gaps. These are source-level findings, not a new performance benchmark or proof that every conceivable finite-domain representation is impossible.

| Option | Resource consequences | Scientific consequences / decision needed |
|---|---|---|
| Streaming moments only | Reduces some stored state, but leaves exact median/history growth unresolved | Not a complete bound; protected interface/numerical equivalence still requires approval and tests |
| Exact packet-size histogram | Can bound size-distribution state after establishing the parser's actual accepted size domain; dense histograms multiply badly across many flows | Potentially preserves size order statistics, but requires protected extractor/aggregator integration and exact interpolation/numerical verification; does not solve IAT median |
| Exact disk-backed timestamp/order-statistic storage | Can bound RAM through explicit caches/external sorting, but disk demand grows with input; disk exhaustion remains a hard failure | Best candidate when existing segmentation must remain unchanged; not a trivial substitution for current list/NumPy APIs and outside a small in-memory fix |
| Packet-count segmentation | Bounds samples per segment; active-flow and queue limits are still needed for a total budget | Changes flow boundaries, duration, counts, rates, direction ratios, flag ratios, distributions, event count and model inputs; requires explicit scientific approval and fresh evaluation |
| Maximum duration alone | Limits time horizon, not samples or bytes at arbitrary rate | Changes segmentation and still does not establish a strict memory bound |
| Reservoir/quantile sketches, truncation or dropping history | Fixed budget possible | Approximate/omit canonical samples; prohibited without explicit approval; not proposed as a silent fallback |
| Stop on reaching a declared resource ceiling | Could bound retention while stopping service instead of silently changing features | Availability/data-loss trade-off; define accepted-packet draining and incomplete-flow policy before implementation |

**Recommendation:** decide first whether unchanged flow segmentation is mandatory. If yes, scope a separate exact-storage/numerical-equivalence design with explicit disk and failure budgets. If bounded in-memory operation is the priority, explicitly approve packet-count segmentation as a changed observation contract, identify its policy/version in provenance, and scientifically revalidate it. No default cap, approximation or segmentation policy was selected here.

The brief protects the aggregator as well as the extractor. Even a potentially exact replacement is not authorized to edit these 23 files in this pass. No hidden wrapper truncation or forced `flush_all()` workaround was used.

## Retention and storage design — not implemented

The existing defaults are 168 hours, 100000 events and a 300-second cleanup interval. They are project defaults, not newly recommended production policy. Existing cleanup is unscheduled, deletes events only, and takes an unrestricted age DELETE under the write lock.

A future implementation should own one cancellable cleanup task in the storage/service lifespan, await its shutdown before closing SQLite, cap rows and elapsed work per cycle, yield between transactions, and record deletions, failures, duration and last successful cleanup. Delete orphan flow rows only after rechecking references within the same serialized write context; independently stored flows need an explicit policy. Test cleanup against active writes and reads. Inspect WAL/file growth separately from logical row retention. Do not silently change age semantics from existing event timestamps to PCAP capture timestamps or file modification time.

Current `persist_and_publish` commits flow/event atomically before publication. Write failures increment errors and do not publish. The shared worker waits for each persistence result, so slow storage backpressures capture rather than feeding an unbounded retry queue. There is no durable retry spool: a failed event is not guaranteed recoverable. Error counting and eventual health degradation/failure are not proof of lossless durable delivery. Slow/locked/unavailable storage still requires controlled testing; SQLite WAL with `synchronous=NORMAL` must not be described as an independently verified power-loss durability guarantee.

## Drop and health status

- `packets_observed` / `packets_received` alias: packets observed by the application, not a kernel receive statistic.
- `packets_processed`: packets successfully parsed and ingested by the shared worker.
- `packets_dropped`: application capture-queue saturation.
- `events_dropped`: subscriber delivery copies lost (including pending copies at disconnect/shutdown), not necessarily unique detections lost from storage.
- Kernel capture drops: **NOT AVAILABLE** in the current adapter; no zero is asserted.
- Resource-related errors/drops already influence live operational health. Detection anomaly scores must remain separate.

## Real-interface result and operator procedure

**NOT VERIFIED — not attempted in this turn because the mandatory scientific stop was reached.** This is not a newly established privilege failure. No interface was selected/opened, no live packets were collected, and no probes, crafted traffic or attacks were sent.

After design authorization and a reviewed bundle are available:

1. Select an authorized isolated interface locally. Record OS, actual resolved Scapy socket backend, effective snap/buffer settings, interface and required privileges. On macOS the chosen backend may require BPF device access; verify locally rather than automatically invoking elevated capture.
2. Configure a temporary DB, privately supplied API key and trusted registry. Start `sentinel-net sensor --interface <approved-interface> --model <approved-name/version>` with only ordinary ambient traffic. Record actual start/stop times and counters.
3. Open authenticated REST/WebSocket clients on a separate management interface where possible. Their requested responses are expected management traffic; distinguish them from forbidden packet injection/probing on the monitored interface.
4. Verify RUNNING only after model/capture readiness; compare observed/processed packets, flow counts, persisted events and REST/WS IDs. Account for malformed input and each supported drop layer separately. Retain no sensitive packet content in the report.
5. Exercise idle and active-arrival SIGINT/SIGTERM shutdown in separate runs, verifying producer stop, accepted-input drain, final persistence, closed workers and no duplicate event IDs. An ordinary authorized source may already supply traffic; do not make Sentinel-NET transmit test packets.
6. Independently inspect the capture path and outbound behavior. Lack of a Python `send()` call alone is not runtime proof; report the verification method and management traffic exclusions. If environment/privileges prevent a step, record NOT VERIFIED and the actual reason.

## Deliverables, verification and next phase

Changed files in this turn are only:

- `docs/rw5-resource-hardening.md`
- `docs/rw5-performance-report.md`
- `docs/rw5-benchmark.json`
- `docs/rw5-environment-manifest.json`
- `docs/rw5-scientific-integrity.json`

The SHA-256 check was executed: **23/23 protected files match RW-4**. Schema 2.0.0 and all 52 features remain unchanged. No model was loaded, trained, replaced or scientifically reevaluated in this turn. Runtime remains unchanged, including inference-only deployment behavior.

No tests were added or rerun after the audit stop. Last verified RW-4/UI baseline (not a new RW-5 result): **631 backend passed / 14 warnings; 61 frontend passed across 5 files; TypeScript/build PASS; frozen-model regression PASS; live/replay parity 7/7 PASS**. Performance, latency, RSS and sustained-load results are unmeasured; see the companion report and explicit nulls in JSON.

No runtime change was made, so this pass creates no new scientific metric invalidation. RW-1's previously documented segmentation correction still requires separate scientific revalidation. Approving segmentation now would additionally invalidate transfer of prior accuracy/F1/recall/false-positive/calibration/novelty results to the new observation policy; those results remain historical until rerun. Thresholds need not change for segmentation to change their operational effect.

Recommended next step: resolve the RW-5 exact-semantics/resource-policy decision and complete resource, retention, real-interface and sustained-load validation before starting SIH intelligence features. No DNS/TLS/C2/DGA work was begun.

Git recommendation: a documentation-only commit such as `docs: audit RW-5 resource bounds and scientific stop condition`, selectively staging the five files above after reviewing the existing uncommitted baseline. No commit was made.

**NO-GO FOR SIH INTELLIGENCE HARDENING** — per-flow exact-history bounds are unresolved, and retention lifecycle, full-path performance/sustained measurements and real-interface validation remain incomplete. Scientific integrity took precedence over silently changing the feature contract.
