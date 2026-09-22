# SIH-F3 completion report

**GO FOR SIH-F4** — passive streaming evidence, bounded state, explicit heuristic semantics, durable contract integration, deterministic parity, full regression gates and measured comparisons are complete. This is permission to proceed to a separately scoped DNS phase, not a production-readiness claim. No SIH-F4/F5 implementation was started.

1. **Architecture:** one `StreamingIntelligence` owner inside the shared packet-processing lifecycle observes parsed packets and actual canonical flow creations, then enriches completed ML events with separate behavioral evidence. No separate detector dictionaries, packet histories or runtime training. [Architecture](sih-f3-architecture.md).
2. **Window/state design:** capture-time, epoch-aligned 60-second windows in 1-second buckets by default; total keys capped at 1024, identity membership at 64 per dimension/key, session timestamps at 32. Late in-window data is placed deterministically; older data is counted/excluded. Keys use deterministic LRU eviction. Expiry follows capture watermark, not wall-clock replay age; shutdown clears the owner.
3. **DDoS evidence:** destination-level initial-SYN, UDP packet, UDP flow, total flow-creation and packet rates, plus observed source diversity. Values and centralized operational thresholds are recorded; no flood confirmation follows automatically.
4. **Entropy evidence:** packet-weighted Shannon source-distribution entropy in bits, with window, observation count, unique-source count and definition. Incomplete source membership suppresses entropy rather than computing a misleading censored value. High entropy is not spoofing proof.
5. **C2 periodicity:** bounded source/destination/protocol/destination-port sequences, at least six flow creations/five intervals, interval mean/population variance/stddev/CV, positive mean and concentration requirement. Polling/keepalives and canonical segmentation are explicit alternative explanations; no confirmed C2 classification.
6. **Destination concentration:** observed session counts, distinct destination count, retained destination-frequency distribution and per-evaluated-destination concentration ratio; capped membership/loss is disclosed.
7. **Reconnaissance:** distinct destination-port and host fan-out with source flow rate and window context. Monitoring, discovery, proxies and distributed applications remain plausible explanations. Slow fan-out inside the window and activity outside it have separate controls.
8. **Asymmetry:** existing completed-flow forward/reverse totals, directional byte ratio, minimum dominant volume and repeated direction-heavy flows. Direction is initiator/responder, not assumed protected-network outbound. A single large transfer control does not qualify; repeated legitimate backups can. End-time attribution and horizon limits are explicit.
9. **Policy semantics:** centralized `IntelligenceConfig` and `EvidencePolicy`. Default `enrich_ml`; optional informational disposition or an explicit separate behavioral-review flag on the same event. Heuristic values never replace classifier/anomaly confidence, severity or risk. Contextual ATT&CK mappings reuse existing qualified IDs and establish neither intent nor attribution.
10. **SOC integration:** additive behavioral-evidence table, threshold/window/context details, distinct historical/disabled/error/empty states and bounded-state counters. Existing model evidence, layout and product page remain intact. Actual frozen-runtime synthetic QA evidence rendered at 1440 and 390 px with no page errors or horizontal overflow; no production demo values were fabricated. [Browser checks](sih-f3-validation/browser.json).
11. **Bounded-state proof:** one K-capped map, ≤B buckets/key, ≤M distinct identities/dimension across all buckets of a key, ≤S retained timestamps/session key, fixed detector outputs, and capped timing deques. Tests fill and slide all 60 buckets, force key/member pressure and sample truncation, expire old keys and clear on stop. Temporary session insertion is bounded at S+1. This does not change the accepted growing canonical exact per-flow histories. See the concrete bound formula in the architecture report.
12. **Files changed:** 22 phase-specific code/test/script files listed below, plus SIH-F3 reports/artifacts. The inventory is relative to a pre-F3 snapshot, so it does not misattribute existing uncommitted RW-5B work.
13. **Tests added:** 42 backend cases: 33 deterministic signal/window/policy/semantic cases and 9 shared-runtime parity/failure/score-preservation cases. Five frontend cases cover actual behavioral evidence and honest missingness. Existing RW-5B resource, retention, backpressure and report-validation tests remain green.
14. **Backend total:** **697 passed, 14 warnings**, 68.18 seconds. [Full output](sih-f3-validation/backend.txt). Existing synthetic test fixtures are used by the regression suite; no deployment model was retrained.
15. **Frontend total:** **67 passed across 5 files**. Combined: **764 passing tests**. [Full output](sih-f3-validation/frontend.txt).
16. **TypeScript/build:** strict TypeScript PASS; production Vite build PASS. [Typecheck](sih-f3-validation/typescript.txt), [build](sih-f3-validation/build.txt).
17. **Live/replay intelligence parity:** **7/7 PASS** for SYN rate, UDP rate, entropy, periodicity, port fan-out, host fan-out and asymmetry, including repeat-replay determinism and durable record equality. Original frozen-core **7/7 parity** also passes. Fault isolation and enabled/disabled ML score/evidence preservation pass.
18. **Scientific integrity:** **23/23 files byte-identical** to RW-5B; exact 52-feature ordering and v2.0.0 contract unchanged. Frozen bundle, auth, event-contract and lifecycle regressions pass. [SHA-256 proof](sih-f3-scientific-integrity.json).
19. **Benchmark comparison:** all six 30-second full-path workloads rerun enabled and disabled, with matching archived RW-5B input hashes and frozen-model identity. Enabled mixed replay measured **397.79 packets/s, 50.25 flows/s, 0.4563 Mbps**, versus **398.40 packets/s** disabled and **420.51 packets/s** archived RW-5B. Full p50/p95/p99, RSS, state peaks and measured deltas are in the [performance report](sih-f3-performance-report.md); no statistically established improvement/regression or general capacity guarantee is claimed.
20. **False-positive and deployment risks:** demand bursts, monitoring/polling, proxies, service discovery, uploads and backups can trigger contextual signals. Capacity/idle flow segmentation is not proof of application sessions. Partial windows, capture loss, capped membership, key eviction and late data reduce coverage. Evidence attaches on canonical finalization; old idle-finalized flows can lie outside the intelligence horizon. Benchmarks have low host diversity and short durations. Canonical exact history growth and NOT VERIFIED real-interface/BPF operation remain accepted documented limitations.
21. **Remaining SIH26145 gaps:** DNS/DGA/tunnelling intelligence; TLS/QUIC metadata and appropriate fingerprinting; broader deployment-specific validation, false-positive calibration and real-interface operation. These were not silently implemented or claimed by generic behavioral evidence. No active mitigation or remote probing was added.
22. **Proposed SIH-F4 DNS phase:** separately scope passive DNS observation with bounded transaction/domain caches, parser length/depth/count limits, deterministic event-time expiry and explicit truncated/encrypted/unavailable states. Add contextual domain/diversity/response-pattern evidence with positive and legitimate controls, preserve ML semantics, reuse durable event/SOC contracts, and benchmark its incremental cost. Do not perform DNS lookups or infer confirmed tunnelling/DGA solely from entropy.
23. **Git recommendation:** first preserve/review the existing RW-5B work, then stage only the SIH-F3 delta and commit with a message such as `Add bounded passive streaming behavioral evidence`. Review mixed-file hunks carefully; do not blindly stage the entire workspace. Commit requested JSON/report/test artifacts, not temporary benchmark databases/PCAPs or QA model binaries. No commit was created.

## Phase-specific code inventory

- `frontend/src/__tests__/detection-detail.test.tsx`
- `frontend/src/__tests__/fixtures/f3-event.json`
- `frontend/src/api/types.ts`
- `frontend/src/pages/DetectionDetail.tsx`
- `frontend/src/pages/Sensor.tsx`
- `scripts/rw5b_benchmark.py`
- `scripts/rw5b_environment.py`
- `src/sentinel_net/cli.py`
- `src/sentinel_net/config.py`
- `src/sentinel_net/demo_replay.py`
- `src/sentinel_net/intelligence/__init__.py`
- `src/sentinel_net/intelligence/config.py`
- `src/sentinel_net/intelligence/engine.py`
- `src/sentinel_net/intelligence/policy.py`
- `src/sentinel_net/intelligence/window.py`
- `src/sentinel_net/models/event_record.py`
- `src/sentinel_net/sensor/metrics.py`
- `src/sentinel_net/sensor/operational_health.py`
- `src/sentinel_net/sensor/pipeline.py`
- `src/sentinel_net/sensor/processing.py`
- `tests/unit/test_stream_intelligence.py`
- `tests/unit/test_stream_intelligence_parity.py`

## Artifacts

- [Architecture and state bounds](sih-f3-architecture.md)
- [Full benchmark comparison](sih-f3-performance-report.md)
- [Machine-readable comparison](sih-f3-benchmark-comparison.json)
- [Scientific integrity](sih-f3-scientific-integrity.json)
- [Validation logs and browser result](sih-f3-validation/summary.json)

**GO FOR SIH-F4**
