# RW-1 correctness and security

Scope: RW-1 / audit F2a only. No sensor CLI/service assembly, input-source abstraction,
frozen deployment bundle, protocol intelligence, risk policy, or benchmark was added.
The existing EIDOLON dashboard design is retained.

## Defects and behavior

| Defect / root cause | Corrected behavior | Regression coverage |
| --- | --- | --- |
| HTTP `Upgrade` header skipped API-key middleware | HTTP requests always authenticate; actual ASGI WebSocket scopes use their own authentication | Upgrade requests on status/events/flows/stats; existing valid/invalid WS and CORS tests |
| Domain events were nested but WS frontend expected flat records | `EventRecord` is the public contract; `DetectionEvent.to_dict()` is its serializer; REST uses the same schema | Full DB/REST/WS equality; frontend preserves the real exported event |
| Database omitted classifier confidence, evidence and separate model provenance | New events persist the entire public JSON record alongside existing indexed columns | Round trip, actual replay integration, legacy migration |
| Flow identity was generated only by storage | Finalized flows carry IDs before inference; persistence reuses them | Round trip and two events referencing one flow |
| Reused tuples never expired during replay/offline ingestion | Capture-time expiry precedes ingestion; tuple reuse also checks expiry | Idle split and before-EOF persistence tests |
| FIN/RST only set flags | RST finalizes immediately; FIN starts a fixed 1-second grace period, then finalizes | RST, FIN-tail and boundary tests |
| EOF used a separate path that skipped counters | EOF flows use the same replay completion/output helpers | Real EOF inference and empty replay |
| Live shutdown discarded `flush_all()` and abandoned queued packets | Stop drains accepted input, processes the returned final flows, waits for persistence, then reports failures | Immediate stop, idle without more packets, write failure |
| Live path had no database write | Database and its owning event loop are required; shared output helper commits before publication | Live persistence and rollback tests |
| Persistence success depended on subscriber count | Database success, queue insertion, WS sends, delivery drops and write failures have separate counters | Zero clients, fast/slow subscribers, real WS delivery |
| Existing explanation components were never attached | Inference attaches the existing SHAP/statistical explainers, rationale and qualified ATT&CK context; failures have explicit unavailable reasons | Statistical evidence alignment, unavailable/failure cases, UI rendering |

## Public event contract

New events use `event_schema_version: "2.0.0"`. This is an **event** contract version;
it does not change `feature_schema_version: "2.0.0"` or the 52 model features.

- `id` and `event_id` are explicit equal aliases for old/new consumers.
- `threat_type` and `threat_class` are equal aliases.
- `classification_score` is tagged `uncalibrated_classifier_score`.
- `classification_score_class` identifies the model class whose score is reported,
  even if minimum-confidence policy changes the final threat class to `unknown`.
- `anomaly_score` is tagged `normalized_anomaly_score`; it is not a probability.
- `severity` retains the existing threshold policy. No operational risk is invented.
- `model_version` identifies the classifier (or anomaly model if no classifier exists).
  `anomaly_model_version` preserves the second model's version independently.
- `detection_source` identifies the classifier and anomaly detector separately.
- `evidence` is the merged evidence collection. Individual explanation availability,
  rationale and contextual ATT&CK mappings remain in `metadata.explanation`.
- Evidence values from the existing explainers use **standardized model input** space,
  recorded as `metadata.explanation.evidence_value_space`. Statistical deviations
  are not model-causal contributions. ATT&CK mappings are contextual possibilities.
- `created_at` is event creation time, stable across delivery paths; it is not a
  persistence-latency measurement.
- Packet bytes and growing packet histories are excluded from the public record.

SQLite migration adds nullable `event_json`. Existing rows remain readable and are
identified as event contract 1.0.0; absent scores are null rather than invented.
Existing metadata evidence is retained. Event and flow insertion share a transaction;
a rejected event rolls back its newly inserted flow. Normal output publishes only
following a successful commit. Failed writes are observable but are not durably spooled
or automatically retried in RW-1.

## Flow finalization policy

Idle timeout uses `current_time - last_seen >= idle_timeout_sec` (default 120 seconds).
Replay/offline processing advances a nondecreasing capture-time watermark. The live
worker uses capture time while draining its queue and wall clock during empty-queue
polls. Out-of-order packets cannot move a flow's last-seen time backward. Timestamp
zero remains valid.

RST includes its own packet and completes that observed segment immediately. The
first observed FIN starts a fixed grace window (default 1 second) to retain nearby
teardown ACKs. Later traffic does not extend it. A FIN does not establish that both
sides completed a TCP close. Traffic beyond the window creates another segment.
EOF/shutdown finalizes remaining observed segments regardless of TCP completeness.

This corrects segmentation and therefore can change feature values and predictions
for PCAPs previously merged across idle/closed sessions. The canonical feature schema,
extractor, classifiers, anomaly scoring and thresholds are unchanged. Regression tests
compare enriched inference against direct model predictions on identical feature vectors.
Do not interpret this as scientific revalidation of changed flow segmentation.

## Counter semantics

| Counter | Unit / meaning |
| --- | --- |
| `flows_completed` | Cumulative finalized observed segments, including EOF/shutdown |
| `flows_active` | Current active segment gauge |
| `flows_evicted` | Capacity evictions only, not idle expiry or EOF |
| `features_generated` | Extracted feature vectors |
| `detections_generated` | Model-produced event records handed to output, including benign records |
| `events_persisted` | Successfully committed event records, independent of clients |
| `events_enqueued` | Subscriber copies accepted by event-bus queues |
| `events_delivered` | Subscriber copies whose WebSocket send completed; not browser acknowledgment |
| `events_dropped` | Subscriber copies lost to overflow, disconnect/send failure, or queue shutdown |
| `persistence_errors` | Failed event persistence attempts; separate from delivery drops |
| `processing_errors` | Processing/output failures, including persistence failures |

Multiple subscribers can make copy counters exceed the number of detections. Zero
subscribers cause neither a persistence failure nor a delivery drop. Persisted records
remain available through REST after delivery overflow. Event-bus `publish()` retains
its legacy integer return value; `publish_result()` supplies atomic per-call accounting.

## Validation

Final RW-1 verification: **540 backend tests passed** (14 warnings), **54 frontend
tests passed** (4 files), **594 total passing tests**. TypeScript strict checks and
the production frontend build passed. Relative to the verified baseline, this adds
33 backend and 6 frontend tests. The initial defect-reproduction run had 11 failures
across the ten audit defects before their fixes.

The feature schema and extractor are byte-for-byte unchanged from the pre-edit
snapshot, as are classifier, anomaly scoring and threshold implementation files.


Run from the repository root:

```sh
PYTHONPATH=src .venv/bin/python -m pytest -q
npm --prefix frontend test
npm --prefix frontend run typecheck
npm --prefix frontend run build
```

The new real integration test uses a tiny locally trained XGBoost + Isolation Forest
fixture, then the actual replay/parser/extractor/inference/evidence/database/API/WS
components. Only the expensive external-dataset training entry point is substituted.
It does not insert fake detections or bypass model inference.

The frontend fixture was exported from that integration test's actual WebSocket output:

```sh
SENTINEL_RW1_EVENT_FIXTURE=frontend/src/__tests__/fixtures/rw1-event.json \
PYTHONPATH=src .venv/bin/python -m pytest tests/integration/test_rw1_delivery.py -q
```

Frontend tests exercise the WS consumer, REST consumer and mounted investigation page
with this record. They do not constitute a deployed-browser/network load test.

## Changed files

Backend:
- `api/auth.py`, `api/main.py`, `api/schemas.py`, `api/routes/websocket.py`
- `models/types.py`, new `models/event_record.py`
- `storage/database.py`
- `flow/aggregator.py`, `pipeline.py`, `demo_replay.py`
- `sensor/pipeline.py`, `sensor/event_bus.py`, `sensor/metrics.py`, new `sensor/event_output.py`
- `detection/inference.py`, `detection/preprocessing.py` (output-name introspection only)
- new `explainability/enrichment.py`

Frontend:
- `api/types.ts`, `api/websocket.ts`
- `pages/DetectionDetail.tsx`, `pages/Sensor.tsx`
- API/WS tests, new investigation-page tests and exported replay fixture

Backend tests:
- auth and WS fixture updates
- new `tests/unit/test_rw1_correctness.py`
- new `tests/integration/test_rw1_delivery.py`

## Remaining risks and RW-2 proposal

No real interface capture or SIGINT/SIGTERM service test was performed. The repaired
live component requires an initialized database and its active owning event loop.
Stop the producer first, then `await pipeline.astop()`, then close storage. Calling its
blocking `stop()` on the database loop is rejected to prevent deadlock. Stop timeout
raises explicitly; it does not claim a successful drain.

Per-flow histories and offline result materialization remain unbounded; subscriber
caps, sustained resource limits, durable retry/spooling, a distinct risk policy,
frozen model deployment and complete performance measurement remain outstanding.
Replay still trains at startup, deliberately left for RW-4. Optional SHAP may be
unavailable. Explanation work adds runtime cost that has not been throughput-benchmarked.

After approval, RW-2 should assemble a CLI-owned service with explicit initialization
and failure ordering: configuration -> database -> detector -> existing capture/worker
-> API; lifecycle STOPPED/STARTING/RUNNING/DEGRADED/STOPPING/STOPPED; signal-driven
producer stop -> queue drain -> flow flush -> persistence finish -> output/storage close.
Capture shutdown must work without waiting for another packet. The API should expose
health/metrics only, with no arbitrary interface or mitigation control. Retain separately
identified replay lifecycle. RW-3 input abstraction and RW-4 deployment artifacts remain
separate milestones and must not be claimed as implemented by that assembly.

Suggested focused commits (after review against the pre-existing dirty working tree):
1. `fix(auth): prevent HTTP Upgrade authentication bypass`
2. `fix(events): preserve versioned detection records across storage and delivery`
3. `fix(runtime): finalize flows and persist live shutdown output`
4. `test(rw1): verify real replay delivery and document runtime semantics`

No commit was created automatically.
