# RW-3: unified passive sources

RW-3 is complete. RW-4 is a proposal only.

## Source contract

`PassivePacketSource` is a small structural protocol in `sensor/sources.py`:

- `mode` and safe `provenance` identify LIVE or REPLAY input.
- `start()` opens the source once.
- `read(timeout)` returns one `SourceRead`: PACKET, IDLE, EOF or CANCELLED.
- `acknowledge()` accounts for a consumed live queue entry; replay needs no queue acknowledgment.
- `stop()` stops the producer or interrupts replay pacing and closes the file safely.

PACKET contains the existing `RawPacket` or test-compatible `ParsedPacket`, including its original timestamp. IDLE optionally carries an expiry watermark. Controls are separate result kinds, never synthetic network packets. The source has no flow aggregation, feature extraction, model, detection or persistence responsibilities. Only one processing worker reads and acknowledges a source. Stop may be requested concurrently.

## Implementations and shared owner

`LiveCaptureSource` adapts the RW-2 receive-only capture object and its bounded queue. It joins capture before exposing cancellation, then yields every accepted queue entry before CANCELLED. It reports capture failure; an empty live queue is IDLE, not EOF. Service startup and cleanup still belong to `SensorService`. It now constructs an explicit source and `PacketProcessingPipeline`.

`PcapReplaySource` pulls one record at a time through Scapy's PCAP/PCAPNG reader. It preserves file ordering, including out-of-order timestamps. There is no replay producer queue and no whole-file materialization. At most one raw packet is held for optional pacing. File access/closure is serialized; stop wakes pacing before waiting for that lock. A packet already read for pacing is accepted work and drains on cancellation, but subsequent file records are not read.

Both inputs feed exactly the same `PacketProcessingPipeline`:

```text
PassivePacketSource.read
  → existing packet parser
  → existing flow aggregator
  → shared infer_completed
  → unchanged 52-feature extractor
  → unchanged DetectionPipeline and evidence enrichment
  → source provenance attachment
  → persist_and_publish
  → SQLite commit → EventBus → authenticated WebSocket
                  ↘ authenticated REST
```

The replay-to-dashboard function now only prepares dependencies/source, runs this owner, manages the replay lifecycle, and reports a summary. Its separate aggregation/inference/output loop was removed. `LiveSensorPipeline` remains a compatibility constructor around the same owner for callers with an externally managed queue; it contains no separate processing implementation.

## Time semantics

| Clock or timestamp | Semantics |
|---|---|
| Live packet timestamp | Original observation timestamp supplied by capture |
| Replay packet timestamp | Original recorded timestamp, never shifted to today's date |
| Capture-time watermark | Nondecreasing maximum of parsed packet timestamps; shared packet-driven expiry policy |
| Live idle watermark | Current wall-clock time, supplied only when the accepted queue is empty; preserves RW-2 idle expiration |
| Replay IDLE | Pacing wait with no wall-clock expiry watermark |
| `processing_time_sec` | Cumulative monotonic elapsed time spent on packet/idle processing and finalization, including inference and durable-output waits; excludes source reads, queue waits and pacing |
| Event timestamp | Existing model event creation time, unchanged |

Processing time is not computed as wall time minus capture time and is not an end-to-end queue-latency measurement. The live idle watermark does not rewrite the packet capture-time watermark. Replay pauses cannot expire historical flows using today's clock.

The source defaults to unpaced reads. The CLI still defaults to unpaced replay and opts into pacing with `--realtime`; `--speed` now reaches the source and divides recorded inter-packet delays. The older `DemoReplayConfig` default remains compatible (`realtime=True`). No new timing delay is imposed when pacing is disabled. Negative timestamp deltas do not delay delivery or reorder the file.

## EOF, cancellation and errors

Natural file exhaustion returns EOF. Live input has no natural EOF. Explicit cancellation stops new input and drains already accepted packets; no fake EOF packet is inserted. The worker's single finalizer flushes active flows, performs inference/evidence, persists and publishes. Repeated wait/stop calls do not rerun finalization.

Replay task cancellation is converted into source stop and worker drain before cancellation is returned to the caller. CLI replay shutdown now awaits that cleanup before its database lifespan ends. A completed replay reports REPLAY_COMPLETE; a cancelled replay reports STOPPED, not successful EOF. Live retains the RW-2 lifecycle and graceful signal behavior.

| Error kind | Observation and behavior |
|---|---|
| SOURCE_ERROR | Source open/read/capture failure; source_errors and safe error messages, fatal worker failure where applicable; finalize already accepted flows |
| PROCESSING_ERROR | Parser exception or aggregation/inference failure; processing counters. Live can continue after individual failures; a replay parser exception cancels that replay and ends visibly in ERROR |
| PERSISTENCE_ERROR | Failed durable write; persistence_errors, no publication of that event |
| OUTPUT_ERROR | Publication failure after persistence; output_errors, durable record retained |

`last_error_kind` identifies the most recently recorded category; counters retain earlier failures. Legacy `processing_errors` still overlaps persistence/output failures for compatibility and must not be summed as a disjoint total. Non-IP/unparseable packets returning `None` retain the existing skipped/malformed accounting and produce no detection. Scapy's existing packet/container decoding behavior is reused, not replaced by a new strict capture-file validator.

Live queue pressure/drops remain observable and bounded by the existing configured queue. Pull replay applies natural backpressure: a slow inference/output operation prevents the next file read. Existing subscriber queue limits/drop accounting are unchanged. No new unbounded source queue was introduced.

## Provenance

Before durable output, the shared worker adds safe source metadata. The common `EventRecord` exposes additive nullable fields:

- `source_mode`: LIVE or REPLAY.
- `capture_interface`: supplied for live service events.
- `replay_file_identifier`: opaque UUID identifying a replay session, not a content hash or local path.

The same fields survive SQLite, REST and WebSocket serialization. No replay path or basename is added to event provenance. The CLI's local replay summary can still contain its input path. Existing historical/direct-inference records with no recorded provenance remain unknown; they are never labeled LIVE by default. Detection detail displays LIVE PASSIVE SENSOR, RECORDED TRAFFIC REPLAY or Not recorded independently of current service state.

## Verification

- **601 backend tests passed, 14 warnings**: 25 new RW-3 tests over the 576-test baseline.
- **60 frontend tests passed across 5 files**: 3 new provenance cases.
- TypeScript strict check: **PASS**. Production build: **PASS**.
- Seven real-model parity scenarios: FIN/grace-tail, RST, idle expiry, tuple reuse, EOF versus shutdown, capacity eviction, and out-of-order timestamps.
- All seven produce identical complete canonical feature vectors, flow data except UUIDs, classifier/anomaly scores, evidence and normalized event content. Generated event/flow/explanation IDs, runtime creation times and source provenance are the only excluded per-run fields.
- Empty sources, idle shutdown, paced cancellation, ordering/timestamps, repeated EOF/stop, no duplicate events, source/parser/persistence/output failures, slow-consumer pull backpressure and runtime-clock accounting pass.
- RW-1 replay/authentication/REST/WebSocket regressions and RW-2 service/queue/signal regressions pass. Integration assertions now verify source provenance across REST and WebSocket too.
- Two RW-1 test fixtures were adapted to the new boundary: the before-EOF persistence checkpoint now observes the third source read; the write-failure test injects an unavailable write after valid startup. A new test independently verifies rejection of a disconnected database before input starts.

The RW-2 SHA-256 evidence matches all **23 protected files** byte-for-byte. See `rw3-scientific-integrity.json`. Feature names/order/count/version remain 52 / 2.0.0; extraction mathematics, preprocessing, classifiers, Isolation Forest, thresholds, score semantics, explainability and flow-segmentation code are unchanged. Historical scientific accuracy metrics were not reproduced in RW-3.

## Remaining duplication and risks

The legacy `PcapReplay` parsed-packet APIs and `PcapPipeline` offline feature-analysis utility remain. They are not used to independently assemble the live/replay detection-to-dashboard path. The offline utility's result accumulation is explicitly deferred. Replay's legacy dependency-training entry point also remains separate from the live fitted-model loader; RW-4 should align deployment dependency loading without altering training/scoring algorithms.

Per-flow timestamp/size histories can still grow; offline accumulation remains; SQLite retention is not service-scheduled. Native file/capture/model calls can still stall beyond normal cooperative cancellation guarantees. No real-interface deployment, sustained-load benchmark, kernel-drop validation, frozen deployment bundle, or new intelligence feature was added. Existing capture backend/link-layer limitations and RW-1 scientific revalidation requirements remain.

## Proposed RW-4 — not implemented

Define an immutable deployment bundle containing the approved fitted preprocessor, classifier, Isolation Forest, existing thresholds, optional explanation baseline, exact feature schema/order, training provenance, dependency versions and checksums. Validate compatibility and trust before deserialization or opening capture; do not train implicitly at runtime. Load the same approved bundle for live and replay. Verify save/load score parity with fixed vectors and recorded input, reject missing/mismatched/tampered bundles, and keep deployment packaging separate from model training and scientific evaluation. Do not claim a checksum alone authenticates an artifact.

## Changed files and Git recommendation

New:
- `src/sentinel_net/sensor/sources.py`
- `tests/unit/test_passive_sources.py`
- `docs/rw3-unified-sources.md`
- `docs/rw3-scientific-integrity.json`

Modified:
- `src/sentinel_net/sensor/pipeline.py`
- `src/sentinel_net/sensor/service.py`
- `src/sentinel_net/sensor/metrics.py`
- `src/sentinel_net/sensor/event_output.py`
- `src/sentinel_net/demo_replay.py`
- `src/sentinel_net/models/event_record.py`
- `src/sentinel_net/cli.py`
- `tests/unit/test_rw1_correctness.py`
- `tests/integration/test_rw1_delivery.py`
- `tests/integration/test_rw2_service_delivery.py`
- `frontend/src/api/types.ts`
- `frontend/src/pages/DetectionDetail.tsx`
- `frontend/src/pages/Sensor.tsx`
- `frontend/src/__tests__/detection-detail.test.tsx`

No dependencies changed. No staging or commits were performed. Earlier RW-1/RW-2, product-page and unrelated work remain in the working tree. Commit reviewed phase baselines separately, then hunk-review RW-3 against the pre-RW-3 snapshot. Suggested commits: `refactor(sensor): unify passive sources and processing`; `feat(events): retain live and replay provenance`; `test(sensor): verify source parity and cancellation`; `docs(sensor): document unified source semantics`. Keep imports and tests coherent across commit boundaries; do not use a catch-all commit.

**GO FOR RW-4**: unified processing, source/time semantics, parity, drain/error behavior, scientific integrity and all required automated gates pass. This is engineering-phase readiness, not production deployment approval.
