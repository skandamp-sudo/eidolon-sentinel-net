# RW-2 completion and review record

RW-2 implementation is complete. RW-3 has not been started.

1. **Architecture:** `SensorService` owns capture, processing worker, database, output bus, metrics and cleanup. Live and replay share completed-flow inference and the RW-1 persist-before-publish path. Existing models and enrichment are reused.
2. **Lifecycle:** STOPPED → STARTING → RUNNING → optional DEGRADED → STOPPING → STOPPED. Fatal initialization/worker/shutdown failures end in FAILED. Replay retains its own labels. Degradation reasons latch for the run.
3. **Startup:** Validate configuration/interface; initialize SQLite; load a trusted fitted registry pipeline; initialize bus/queue; start processing; open receive-only capture and verify readiness; mark RUNNING. A failed stage unwinds owned resources.
4. **Shutdown:** Stop/join capture; drain accepted packets; finalize flows once; infer/enrich; persist then publish; allow bounded subscriber drain; stop API clients; count undelivered copies; close bus/database. The CLI handles SIGINT/SIGTERM without needing another packet.
5. **Failure behavior:** Errors and drops are operational counters/reason codes, never threat detections. Failed persistence is not published. Other work continues after individual processing errors. Fatal worker failure requests process exit. Stuck native workers are reported as failure rather than clean shutdown; their database is not prematurely closed.
6. **Changed files:** Listed below. Existing unrelated work remains unstaged and uncommitted.
7. **Tests:** 36 backend tests added: service lifecycle/failure/drain/health/queue coverage, fitted-model load and score preservation, real-model REST/WS delivery, four actual-signal subprocess cases, and transmit-call security checks. Three frontend tests verify degraded/failed live state and replay distinction. No privileged capture is required.
8. **Backend:** 576 passed, 14 warnings.
9. **Frontend:** 57 passed across 5 test files. Combined total: 633 passed.
10. **TypeScript/build:** Both PASS.
11. **Feature compatibility:** All feature-module SHA-256 values match the pre-RW-2 working tree. Schema remains 52 names, unchanged ordering and version 2.0.0.
12. **Model compatibility:** All detection, threshold, preprocessing and explainability modules remain byte-identical. The aggregator is also unchanged. The fitted-artifact round-trip test produces identical scores/thresholds. No production training occurred. See `rw2-scientific-integrity.json`.
13. **Replay:** Existing EOF, idle finalization, event contract, real-model REST/WebSocket delivery and live/offline parity regressions pass.
14. **Resource risks:** Per-flow histories can still grow without bound; offline accumulation remains; SQLite retention is not service-scheduled. No sustained performance, native-hang recovery or kernel-drop validation is claimed. RW-1 segmentation changes still require scientific revalidation; historical metrics were not rerun.
15. **Manual interface procedure:** The operator guide documents trusted artifact setup, local permissions/interface selection, passive existing-traffic observation, REST/WS verification, busy/idle signal shutdown and safe initialization failures. Real-interface capture was not performed. Loopback CLI tests with synthetic input verified SIGINT and SIGTERM, each with 8 persisted events and clean status-0 exit.
16. **Proposed RW-3:** A passive-source protocol carrying packets, source identity, timestamp watermark, EOF and stop/drain semantics; shared orchestration with explicit live/replay clock policies and raw-input-to-score parity tests. Proposal only.
17. **Git:** Commit reviewed RW-1 first, product-page work separately, then bounded RW-2 implementation/tests/docs commits. Shared files require hunk-level review against the pre-RW-2 baseline. Do not stage everything. No commits were created here.

## RW-2 file scope

New runtime modules:
- `src/sentinel_net/sensor/service.py`
- `src/sentinel_net/sensor/runtime_model.py`
- `src/sentinel_net/sensor/processing.py`

Runtime integration changes:
- `src/sentinel_net/sensor/capture.py`
- `src/sentinel_net/sensor/pipeline.py`
- `src/sentinel_net/sensor/lifecycle.py`
- `src/sentinel_net/sensor/metrics.py`
- `src/sentinel_net/sensor/event_bus.py`
- `src/sentinel_net/demo_replay.py`
- `src/sentinel_net/cli.py`
- `src/sentinel_net/config.py`
- `src/sentinel_net/api/main.py`
- `src/sentinel_net/api/schemas.py`
- `src/sentinel_net/api/routes/health.py`
- `src/sentinel_net/api/routes/status.py`

SOC types/state rendering and updated product status copy:
- `frontend/src/api/types.ts`
- `frontend/src/pages/Sensor.tsx`
- `frontend/src/pages/ProductSite.tsx`

Tests:
- `tests/unit/test_sensor_service.py`
- `tests/unit/test_sensor_runtime_model.py`
- `tests/unit/test_security.py`
- `tests/integration/test_rw2_service_delivery.py`
- `tests/integration/test_rw2_signals.py`
- `frontend/src/__tests__/sensor-health.test.tsx`

Documentation:
- `README.md`
- `docs/live_sensor.md`
- `docs/rw2-continuous-sensor.md`
- `docs/rw2-scientific-integrity.json`
- `docs/rw2-completion.md`

No dependencies were added or removed.

**GO FOR RW-3** — lifecycle, idle/busy shutdown, durable ordering, failure visibility, replay regressions, scientific-code preservation and all required automated gates pass. This is approval to proceed with the next engineering phase, not a production-deployment or sustained-resource-readiness claim. An approved fitted artifact and real-interface validation remain deployment prerequisites.
