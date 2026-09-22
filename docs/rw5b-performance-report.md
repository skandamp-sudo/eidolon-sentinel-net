# RW-5B operational validation — complete

**GO FOR SIH INTELLIGENCE HARDENING**, within the explicitly accepted SIH prototype scope. No production-readiness or unlimited-operation claim. The exact-history limitation does not require a v3 redesign to proceed. Real-interface operation remains NOT VERIFIED because native BPF access was denied.

## 22-point completion report

1. **Retention implementation:** lifecycle-owned, cancellable cleanup in live and API/replay lifespans; awaited before SQLite closes. Existing defaults remain 168 hours / 100000 events / 300 seconds. New limits are 500 deleted rows per transaction and 5000 per cycle across both tables, with yields between batches. Eligibility plus a transactional reference check protects standalone/in-progress flows and retained-event references. Duration, deletions, failures, last success, database bytes and WAL bytes are exposed. See [resource policy](rw5b-resource-hardening.md).
2. **Persistence/backpressure:** normal, delayed, locked, failed and unavailable writes, concurrent reads, and shutdown during slow persistence pass. A single awaited durable write precedes EventBus publication; failures never publish and there is no retry backlog. Sustained workload F injects 20 ms per write and shows its throughput/packet-latency cost. Subscriber count defaults to 32; timed-out sends release the subscription and account pending/in-flight copies.
3. **Drop semantics:** observed/received means application-observed; processed means successfully parsed/ingested; packet drops mean application capture-queue saturation; event drops mean subscriber delivery-copy loss. Kernel drops are native BPF readings only, otherwise null/unavailable. Backend-stat handling has distinct zero, positive, unavailable and unsupported-backend tests.
4. **Real-interface result:** NOT VERIFIED. Receive-only en0 opening reached `L2bpfListenSocket`, then failed with permission denied opening `/dev/bpf0` under uid 501. No traffic was generated, transmitted, probed or scanned for this attempt. Capture counters and idle/arrival SIGINT/SIGTERM checks are unavailable, not fabricated zeros. [Machine-readable result](rw5b-real-interface.json) and the operator procedure below preserve the gap.
5. **Measured packets/sec:** see workload table below, derived from successfully processed packets divided by monotonic processing duration including final drain.
6. **Measured flows/sec:** see workload table; this is completed flow throughput under each workload’s unchanged canonical segmentation.
7. **Measured processing Mbps:** see workload table, using successfully processed captured frame bytes × 8 / elapsed seconds / 1e6, not synthetic link capacity.
8. **Latency p50/p95/p99:** all six requested stages measured below using monotonic clocks. Exact bounded windows retain the latest 4096 observations; totals and sample counts are recorded. Flow timing starts at actual canonical finalization entry and includes waiting behind earlier completed flows, extraction, inference and evidence. It excludes later persistence/publication, which have separate timings.
9. **RSS initial/peak/final:** measured per fresh workload process below. Current RSS is sampled every 0.5 seconds. Peak in the table is the OS process-lifetime peak, which also includes setup; the JSON additionally records the sampled processing peak. These observations are not memory-bound guarantees.
10. **Sustained findings:** six predeclared 30-second synthetic offline workloads, plus drain, with 56–59 sampled windows each. Queue saturation and slow-reader timeout were deliberately exercised. No persistence or retention failures occurred. Detailed pressure, storage and latency-window observations follow.
11. **Explicit v2.0.0 limit:** a continuously active high-volume tuple retains growing exact timestamp and packet-size histories. C retained 47,475 packet-size samples and corresponding directional timestamp samples before finalization. No segmentation, truncation, reservoir, approximate quantile or IAT change was introduced.
12. **Files changed:** operational modules, API lifecycle/health/status/WebSocket, config, SQLite storage, additive SOC types/sensor page, operational tests, two benchmark/report scripts and documentation; complete inventory below. Protected scientific files were not edited.
13. **Tests added:** 24 backend cases (17 operational and 7 report-validation cases), plus one frontend missingness/history-limit test. Existing tests cover active-flow caps, high cardinality, queue shutdown, duplicate/order invariants, deterministic replay, auth and event contracts.
14. **Exact backend total:** **655 passed, 14 warnings**, 57.85 seconds. [Full output](rw5b-validation/backend.txt).
15. **Exact frontend total:** **62 passed across 5 files**. [Full output](rw5b-validation/frontend.txt). Combined total: **717 passing tests**.
16. **TypeScript/build:** strict project typecheck PASS and production Vite build PASS. Browser checks at 1440 px and 390 px found no horizontal overflow or page errors and verified truthful kernel-stat unavailability. [Browser results](rw5b-validation/browser.json), [TypeScript](rw5b-validation/typescript.txt), [build](rw5b-validation/build.txt).
17. **23-file SHA-256:** 23/23 byte-identical against the RW-5/RW-4 inventory; schema remains exactly 52 features, v2.0.0, existing ordering. [Verification](rw5b-scientific-integrity.json).
18. **Frozen-model regression:** PASS in the full backend suite, including bundle checksums, contract validation, identity, rejection paths and inference-only runtime. No runtime training or model/threshold changes. The measurement artifact is the existing small synthetic QA XGBoost/Isolation Forest bundle, not an approved production accuracy claim.
19. **Live/replay parity:** **7/7 PASS**: FIN, RST, idle, tuple reuse, EOF/shutdown, capacity, out-of-order. The added timing-adapter test separately checks exact feature and canonical event equality against the uninstrumented path.
20. **Remaining risks:** exact per-flow histories and finalization scratch can grow; count bounds are not byte bounds; retention is eventual and its budget can lag ingestion; standalone legacy orphan rows are conservatively retained; SQLite/WAL sizes need monitoring; capture snap/buffer settings are not verified effective backend controls; real BPF capture remains unverified; 30-second workloads do not establish long-term stability or production capacity; the QA model is much smaller than an eventual deployment bundle.
21. **SIH-F3 recommendation:** proceed to separately scoped streaming threat intelligence while retaining these operational limits and the canonical 52-feature contract. No intelligence features were implemented here. Recommend separate scientific revalidation with the intended deployment dataset/model; no full scientific evaluation was run automatically, and these changes do not alter segmentation, feature mathematics, inference inputs or thresholds.
22. **Git recommendation:** review and commit only RW-5B operational code, tests, scripts and reports, with a message such as `Harden sensor retention and validate operational backpressure`. Keep benchmark databases, generated PCAPs and local QA binaries outside the commit. No commit was made; the pre-existing staged report was preserved and updated within this requested scope.

## Environment and reproduction

Measured on macOS-26.7-x86_64-i386-64bit, Intel(R) Core(TM) i9-9880H CPU @ 2.30GHz, 8 physical / 16 logical cores, 16 GiB RAM; Python 3.12.14. NumPy 2.5.2, scikit-learn 1.9.0, XGBoost 3.4.1. Results do not generalize to other hardware or model sizes.

Frozen identity: `runtime/1.0.0`; manifest SHA-256 `23457a635f7c6acb1b5e017ef1b59ecf9aae6db654102a7a36f6118bed0fd06f`. Feature count/order/schema are verified by the frozen loader. The complete hardware, dependency, input SHA/configuration/duration manifest is [here](rw5b-environment-manifest.json). Full source digests, stage samples, counters and time windows are in [benchmark JSON](rw5b-benchmark.json).

From the repository root, with an existing approved frozen bundle:

```sh
PYTHONPATH=src .venv/bin/python scripts/rw5b_benchmark.py \
  --registry /path/to/registry --model runtime/1.0.0 \
  --seconds 30 --output /tmp/sentinel-rw5b-new-run
PYTHONPATH=src .venv/bin/python scripts/rw5b_environment.py \
  --benchmark /tmp/sentinel-rw5b-new-run/benchmark.json \
  --output /tmp/sentinel-rw5b-new-run/environment.json
```

The measured registry was `/tmp/sentinel-rw4-preview/registry`, an existing synthetic QA artifact from RW-4. Supply the same artifact for an identical model digest; newly generated or production bundles must carry their own identity and results. The harness does not train or approve models. For an independent synthetic fixture, the existing `tests/unit/test_passive_sources.py::real_detector` and `tests/unit/test_sensor_runtime_model.py::save_pipeline` define the explicit offline QA setup; this is not a deployment recommendation.

Every workload runs in a fresh child process. Deterministic 1024-packet templates have explicit Ethernet addresses and documentation-range IP addresses and are written to PCAP only. Cyclic replay preserves historical timestamps without rewriting them; no runtime latency uses those timestamps. D supplies offline raw frames through a 128-entry queue in bursts of 256 every 20 ms. E uses only an authenticated loopback WebSocket with a 4096-byte socket send buffer and a reader delayed 250 ms between reads. F injects a 20 ms await before each actual SQLite write.

Benchmark overrides: active-flow cap 64, subscriber queue 16, subscriber cap 4, retention target 500, cleanup interval 1 s, 50 rows/transaction and 200 rows/cycle. These accelerate observation of resource behavior and are **not** the production defaults. The harness injects SQLite at `/tmp/rw5b-final/<workload>/events.db`; the serialized generic settings object also contains its unused default `database_path`. Model loading and template generation are outside measured processing time. Each run includes actual parser, aggregation, extraction, frozen inference, evidence, durable SQLite and EventBus output.

## Throughput and memory

Peak RSS below is the OS process-lifetime peak (including setup); all RSS values are MiB. C emits only one flow/event on shutdown, so its inference/flow percentiles each represent one observation and cannot establish a tail-latency distribution.

| Workload | Packets | Flows / events | Elapsed s | Packets/s | Flows/s | Mbps | RSS initial / peak / final MiB |
|---|---:|---:|---:|---:|---:|---:|---|
| A · mixed replay | 12,704 | 1,604 / 1,604 | 30.211 | 420.51 | 53.09 | 0.4823 | 213.52 / 219.82 / 219.80 |
| B · high cardinality | 3,183 | 3,057 / 3,057 | 30.609 | 103.99 | 99.87 | 0.1241 | 213.36 / 219.72 / 219.62 |
| C · long-lived tuple | 47,475 | 1 / 1 | 30.057 | 1579.48 | 0.03 | 1.8889 | 213.54 / 220.77 / 220.59 |
| D · bursty source | 9,640 | 2,410 / 2,410 | 30.562 | 315.43 | 78.86 | 0.2279 | 213.39 / 219.39 / 219.38 |
| E · slow WebSocket | 8,264 | 2,066 / 2,066 | 30.036 | 275.14 | 68.78 | 0.3285 | 228.40 / 237.81 / 237.79 |
| F · slow persistence | 3,380 | 845 / 845 | 30.027 | 112.56 | 28.14 | 0.1341 | 213.40 / 218.68 / 218.66 |

## Latencies (milliseconds)

Percentiles are over the latest min(total, 4096) observations per stage. The JSON records additional inclusive inference timing and each sampled window. Publication is serialization and EventBus queue publication; it is not client receipt latency. Persistence includes the injected delay in F. Packet processing includes downstream backpressure whenever the packet finalizes a flow.

### Packet processing

| Workload | p50 ms | p95 ms | p99 ms | Samples / observations |
|---|---:|---:|---:|---:|
| A · mixed replay | 0.5380 | 11.2466 | 19.5986 | 4096 / 12704 |
| B · high cardinality | 8.2212 | 18.9978 | 30.8334 | 3183 / 3183 |
| C · long-lived tuple | 0.3077 | 0.4750 | 0.5977 | 4096 / 47475 |
| D · bursty source | 0.5814 | 11.4188 | 22.6609 | 4096 / 9640 |
| E · slow WebSocket | 0.5348 | 12.4271 | 24.4227 | 4096 / 8264 |
| F · slow persistence | 0.5537 | 31.2293 | 47.3459 | 3380 / 3380 |

### Actual flow finalization → enriched DetectionEvent

| Workload | p50 ms | p95 ms | p99 ms | Samples / observations |
|---|---:|---:|---:|---:|
| A · mixed replay | 5.8127 | 7.9793 | 28.8784 | 1604 / 1604 |
| B · high cardinality | 5.1574 | 6.9069 | 297.1135 | 3057 / 3057 |
| C · long-lived tuple | 41.8594 | 41.8594 | 41.8594 | 1 / 1 |
| D · bursty source | 5.6284 | 8.0231 | 23.5348 | 2410 / 2410 |
| E · slow WebSocket | 5.8540 | 7.6128 | 24.1698 | 2066 / 2066 |
| F · slow persistence | 6.2588 | 8.7189 | 25.3569 | 845 / 845 |

### Inference excluding measured evidence enrichment

| Workload | p50 ms | p95 ms | p99 ms | Samples / observations |
|---|---:|---:|---:|---:|
| A · mixed replay | 4.2438 | 5.6174 | 21.2117 | 1604 / 1604 |
| B · high cardinality | 4.0318 | 5.1293 | 20.0785 | 3057 / 3057 |
| C · long-lived tuple | 5.4055 | 5.4055 | 5.4055 | 1 / 1 |
| D · bursty source | 4.2021 | 6.2686 | 21.6820 | 2410 / 2410 |
| E · slow WebSocket | 4.3951 | 5.6787 | 22.2738 | 2066 / 2066 |
| F · slow persistence | 4.7107 | 6.5349 | 23.5323 | 845 / 845 |

### Evidence enrichment

| Workload | p50 ms | p95 ms | p99 ms | Samples / observations |
|---|---:|---:|---:|---:|
| A · mixed replay | 0.4782 | 0.7784 | 0.9369 | 1604 / 1604 |
| B · high cardinality | 0.3891 | 0.4950 | 0.7971 | 3057 / 3057 |
| C · long-lived tuple | 15.1924 | 15.1924 | 15.1924 | 1 / 1 |
| D · bursty source | 0.4751 | 0.6783 | 0.8972 | 2410 / 2410 |
| E · slow WebSocket | 0.5004 | 0.6113 | 0.8121 | 2066 / 2066 |
| F · slow persistence | 0.5267 | 0.6313 | 0.7696 | 845 / 845 |

### Persistence

| Workload | p50 ms | p95 ms | p99 ms | Samples / observations |
|---|---:|---:|---:|---:|
| A · mixed replay | 2.2767 | 5.9527 | 14.7160 | 1604 / 1604 |
| B · high cardinality | 1.9321 | 11.3737 | 14.1823 | 3057 / 3057 |
| C · long-lived tuple | 13.0688 | 13.0688 | 13.0688 | 1 / 1 |
| D · bursty source | 2.2790 | 10.8642 | 22.4239 | 2410 / 2410 |
| E · slow WebSocket | 2.2449 | 11.6309 | 23.4610 | 2066 / 2066 |
| F · slow persistence | 22.7367 | 31.6080 | 43.4451 | 845 / 845 |

### Publication

| Workload | p50 ms | p95 ms | p99 ms | Samples / observations |
|---|---:|---:|---:|---:|
| A · mixed replay | 0.2812 | 0.3580 | 0.4557 | 1604 / 1604 |
| B · high cardinality | 0.2350 | 0.3130 | 0.3958 | 3057 / 3057 |
| C · long-lived tuple | 0.3244 | 0.3244 | 0.3244 | 1 / 1 |
| D · bursty source | 0.2784 | 0.3571 | 0.4222 | 2410 / 2410 |
| E · slow WebSocket | 0.2939 | 0.3693 | 0.4478 | 2066 / 2066 |
| F · slow persistence | 0.3024 | 0.3820 | 0.4426 | 845 / 845 |

## Sustained pressure and storage

| Workload | Active-flow peak | Capture-queue peak | Subscriber-queue peak | Packet / event-copy drops | Removed events / flows | Retained events / flows | DB / WAL final MiB |
|---|---:|---:|---:|---:|---:|---:|---:|
| A · mixed replay | 17 | 0 | 2 | 0 / 0 | 1,100 / 1,100 | 504 / 504 | 20.29 / 4.03 |
| B · high cardinality | 64 | 0 | 2 | 0 / 0 | 2,300 / 2,300 | 757 / 757 | 21.95 / 4.05 |
| C · long-lived tuple | 1 | 0 | 1 | 0 / 0 | 0 / 0 | 1 / 1 | 0.00 / 0.16 |
| D · bursty source | 1 | 128 | 2 | 322,136 / 0 | 1,900 / 1,900 | 510 / 510 | 21.23 / 4.04 |
| E · slow WebSocket | 1 | 0 | 16 | 0 / 1,107 | 1,566 / 1,566 | 500 / 500 | 21.25 / 4.04 |
| F · slow persistence | 1 | 0 | 1 | 0 / 0 | 330 / 330 | 515 / 515 | 19.19 / 4.00 |

- A: mixed TCP/UDP cyclic replay completed without application or delivery drops. Exact histories for repeatedly active UDP tuples also grow; longest retained packet-size history reached 400.
- B: 1024 distinct tuples against a 64-active-flow cap exercised canonical eviction. Retention completed bounded cycles without failure but finished with 757 events against a 500 target. The 200-row/cycle budget is shared by event and orphan deletion and can lag this input rate. This is an observed capacity limitation, not a hard database-count guarantee.
- C: one continuous tuple reached 47,475 exact packet-size samples plus its timestamp history and generated one event at final drain. Sampled memory and history windows document growth. No bound on long-term per-flow memory is inferred.
- D: the offline producer observed 331,776 packets; the 128-entry queue accepted only what processing could drain, dropping 322,136 incoming copies. All 9,640 accepted packets processed; 2,410 events persisted, with no persistence failure or event-copy drops.
- E: the actual loopback client read 106 event messages. The subscriber queue reached 16; a slow transport hit the 5-second send timeout, accounting one output/processing error and 1,107 delivery-copy drops. All 2,066 generated events persisted. After the client was disconnected, inference continued with no subscribers; that is correctly not counted as additional delivery loss. Raw windows show the pressure interval rather than implying all 30 seconds retained a connected slow reader.
- F: an explicitly injected 20 ms per-write delay lowered throughput to 112.56 packets/s and 28.14 flows/s. No persistence failure, unbounded retry or packet loss occurred for this pull-based source.

All six runs had zero source, persistence and retention failures. E’s expected slow-consumer failure is observable degradation, not a scientific anomaly. Final database/WAL sizes above precede connection close. Deletion does not reclaim filesystem space automatically; initial/peak/final file sizes are retained in JSON. Partial final queues are drained/accounted, and no accepted worker survives completion.

### Early/late latency windows

Each comparison uses the first and last sampled window with at least 10 packet observations; these windows overlap when their bounded histories have not filled, and are descriptive rather than a trend-significance test. For C there is no flow-finalization observation until final drain.

| Workload | Early elapsed s / packet p95 ms | Late elapsed s / packet p95 ms |
|---|---:|---:|
| A · mixed replay | 0.55 / 9.204 | 30.02 / 11.247 |
| B · high cardinality | 0.08 / 0.713 | 30.47 / 18.998 |
| C · long-lived tuple | 0.10 / 0.730 | 29.62 / 0.475 |
| D · bursty source | 0.55 / 10.128 | 30.44 / 11.401 |
| E · slow WebSocket | 0.56 / 9.862 | 30.01 / 12.426 |
| F · slow persistence | 0.54 / 29.507 | 29.95 / 31.227 |

## Operator procedure for the unverified real-interface gate

On an authorized host with a reviewed BPF/device access policy and an approved deployment bundle, run the existing `sentinel-net sensor` command with the selected interface and model. Grant only the required local capture privileges through the host’s normal operator procedure; this report does not change system permissions. Keep capture receive-only and promiscuous mode disabled unless separately authorized. Do not generate traffic to satisfy this check.

1. Record OS, uid/capabilities, interface, actual listen backend, model manifest, schema and wall-clock start time. Confirm the sensor reaches RUNNING and record actual status/health counters.
2. Allow ordinary ambient traffic. Confirm observed/processed packets, finalized flows and persisted events. Compare a retained event’s REST and WebSocket canonical record; keep capture traffic separate from optional management loopback checks.
3. Repeat SIGINT and SIGTERM on idle capture (or explicitly label a receive filter with no matching ambient packets). Measure stop duration; verify producer and worker exit, accepted packets drain, retention stops before SQLite closes, and persistence completes.
4. Repeat both signals while ambient arrivals are actually observed. If no arrivals occur, mark that condition unverified instead of generating packets. Record counters immediately before and after shutdown, database event count and actual kernel statistics or unavailable.
5. Save results separately; do not replace this host’s NOT VERIFIED outcome until the real checks have run.

## Changed files

- `frontend/src/__tests__/sensor-health.test.tsx`
- `frontend/src/api/types.ts`
- `frontend/src/pages/Sensor.tsx`
- `scripts/rw5b_benchmark.py`
- `scripts/rw5b_environment.py`
- `src/sentinel_net/api/main.py`
- `src/sentinel_net/api/routes/health.py`
- `src/sentinel_net/api/routes/status.py`
- `src/sentinel_net/api/routes/websocket.py`
- `src/sentinel_net/config.py`
- `src/sentinel_net/sensor/capture.py`
- `src/sentinel_net/sensor/event_bus.py`
- `src/sentinel_net/sensor/event_output.py`
- `src/sentinel_net/sensor/metrics.py`
- `src/sentinel_net/sensor/operational_health.py`
- `src/sentinel_net/sensor/pipeline.py`
- `src/sentinel_net/sensor/processing.py`
- `src/sentinel_net/sensor/retention.py`
- `src/sentinel_net/sensor/service.py`
- `src/sentinel_net/sensor/telemetry.py`
- `src/sentinel_net/storage/database.py`
- `tests/unit/test_rw5b_operations.py`
- `tests/unit/test_rw5b_report.py`

Reports and machine-readable artifacts: `docs/rw5b-resource-hardening.md`, `docs/rw5b-performance-report.md`, `docs/rw5b-benchmark.json`, `docs/rw5b-environment-manifest.json`, `docs/rw5b-real-interface.json`, `docs/rw5b-scientific-integrity.json`, and `docs/rw5b-validation/`. The canonical RW-5 report paths now point to this completed phase; the initial review-gate audit remains available as historical evidence.

**GO FOR SIH INTELLIGENCE HARDENING** — bounded operational work, honest measured pressure and missingness, passing regressions, and unchanged scientific semantics. Stop after RW-5B.
