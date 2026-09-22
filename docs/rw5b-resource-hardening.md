# RW-5B operational resource policy

The user explicitly resolved the scientific review gate: preserve all canonical v2.0.0 semantics and document growing exact histories as an accepted SIH prototype limitation. This work does not implement SIH-F3/F4/F5 intelligence features.

## Implemented lifecycle and retention

`RetentionWorker` starts with both the live `SensorService` and standalone/replay API lifespan. It runs an initial cleanup, then sleeps for the configured interval. Shutdown cancels and awaits it before closing SQLite. Cancelled transactions roll back; producers and the processing worker drain before their database closes.

Existing defaults remain **168 hours, 100000 events, 300 seconds**. These are project defaults, not universal production recommendations. `SENTINEL_RETENTION_HOURS`, `SENTINEL_MAX_EVENTS`, and `SENTINEL_CLEANUP_INTERVAL_SEC` still override them. New defaults are **500 deleted rows per transaction** and **5000 deleted rows per cycle**, across events and flows combined. `SENTINEL_CLEANUP_BATCH_ROWS` and `SENTINEL_CLEANUP_CYCLE_ROWS` override those bounds. Every transaction yields to the event loop. Failed cycles record a failure and wait until the next configured interval; there is no retry backlog.

A cycle computes one age cutoff using the existing event timestamp semantics. Indexed oldest events are removed for age or excess count. Each batch reserves capacity for orphan cleanup to avoid starving it under continued event insertion. Logical retention is eventual: the event total can temporarily exceed the configured target between cycles or if ingestion outpaces the deletion budget. Row limits do not bound disk I/O time or the work of index/count scans on an arbitrarily large existing database. SQLite's default busy timeout remains finite (5 seconds); tests override it to 30 ms for deterministic contention.

The additive `flows.retention_eligible` column defaults to false. Atomic event persistence marks its completed flow eligible. Cleanup also marks flows referenced by removed legacy events eligible within the same transaction. Orphan deletion requires both eligibility and `NOT EXISTS` a retained event reference, under `BEGIN IMMEDIATE` and the shared writer lock. Active runtime flows are not stored until finalized. Standalone/in-progress `store_flow` rows and legacy orphan rows with no evidence of completion remain protected; they require a separate explicit administrative policy if their volume matters. This is conservative cleanup, not deletion of every unreferenced historical row.

Metrics include last-cycle duration, cumulative event/flow deletion counts, failures, completed cycles, last successful cleanup time, and independently observed database/WAL file bytes. DELETE does **not** promise filesystem shrink. No automatic VACUUM, WAL truncation, or checkpoint policy was added.

## Persistence and delivery

The single worker awaits one durable output future per event: flow + event commit first, then publication of the canonical event serializer. A failed write never publishes. There is no unbounded retry queue. Slow writes apply backpressure to processing; live arrivals can fill the bounded capture queue and then drop. Shutdown waits for accepted work. If the worker cannot drain within its existing 30-second join limit, the service reports failure and does not close storage beneath a surviving worker.

EventBus now defaults to at most **32 authenticated subscribers**, each with the existing **1000-entry** queue. `SENTINEL_MAX_SUBSCRIBERS` overrides the count. Invalid nonpositive limits are rejected. Rejected subscriptions close with WebSocket 1013. Each socket has at most one in-flight delivery; authenticated sends have a default **5-second** timeout, configurable through `SENTINEL_WS_SEND_TIMEOUT_SEC`. Pending and failed in-flight copies are counted on disconnect/timeout. Network/ASGI buffering is separate from EventBus entry limits; this is not an aggregate byte-limit claim. Admission before authentication remains bounded by the existing authentication timeout, not by the subscriber cap.

No-client operation still persists detections, with zero delivery-copy loss. A WebSocket send completion means acceptance by the server transport, not proof the remote application read the message. The slow-reader benchmark separately records actual client reads.

## Metrics and health

- `packets_observed` / `packets_received`: packets observed by the application.
- `packets_processed`: packets successfully parsed and ingested.
- `packets_dropped`: application capture-queue saturation only.
- `events_dropped`: subscriber delivery-copy loss, including pending copies discarded during disconnect/shutdown.
- `kernel_capture_drops`: a real native BPF `get_stats()` reading when available; otherwise JSON `null`. Unsupported backends and failed reads never become synthetic zero.

Operational errors, retention failures, subscriber admission failures, and drops drive operational health/readiness separately from scientific anomaly scores or threat classifications. Live degradation remains latched. The existing SOC sensor page adds storage/delivery counters, cleanup information, kernel-stat availability, and the exact-history limitation without redesigning the console or product page.

## Measurement boundaries

Operational timing uses `time.monotonic()` only. An adapter delegates actual canonical `_finalize`, stamps its entry time on the runtime flow object, and leaves serialized domain fields unchanged. The inference adapter temporarily times the detector instance's existing enrichment hook and restores it even on failure. Runtime detector instances have one processing owner; they must not be shared concurrently across workers.

Stages are packet processing (including any inline downstream backpressure), actual finalization entry to the complete enriched DetectionEvent, inference excluding the measured evidence hook, evidence enrichment, SQLite persistence including failed attempts, and publication including serialization into EventBus. Inclusive inference is also reported. Frozen models, thresholds, extraction and aggregation mathematics are unchanged. A focused parity test checks instrumentation against the uninstrumented implementation.

Each stage keeps a fixed deque of the **last 4096** observations, plus its lifetime observation count. Percentiles use linear interpolation over that window; they are not whole-run percentiles when observations exceed 4096. The harness samples these windows and RSS every 0.5 seconds, capped at 1000 samples. It reports input bytes, successfully processed captured bytes, monotonic duration including final drain, packets/s, flows/s and processing Mbps. Model loading and packet-template creation precede the measured processing interval.

## Accepted limits and remaining deployment risks

A continuously active high-volume tuple can retain growing exact forward/reverse timestamp and packet-size histories because the current median/quantile and pooled directional IAT contract requires them. Memory per flow is **not strictly bounded**. Finalization adds sorting, IAT and feature-array scratch allocations. Active-flow count, capture queues and subscriber queues have entry limits, not a universal byte bound.

The capture `snap_length` and `capture_buffer_size` settings are still not evidence of effective backend controls; no silent packet truncation or scientific input change was introduced. Legacy collecting offline helpers can materialize entire captures and are not the continuous runtime benchmark path. A frozen model's fixed footprint depends on the supplied artifacts. The measured bundle is a small synthetic QA model, not a production accuracy/evaluation claim.

Real-interface BPF access failed under uid 501. Hardware capture, actual kernel drops and real-interface SIGINT/SIGTERM behavior remain **NOT VERIFIED** on this host. Four fake-source OS-signal regressions pass, but are explicitly not substituted for that hardware result.
