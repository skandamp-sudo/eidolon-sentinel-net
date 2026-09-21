# EIDOLON // SENTINEL-NET — Roadmap

## Phase 1: Foundation ✅ (Current)

- [x] Project structure with `uv` and Python 3.12
- [x] Pydantic Settings configuration
- [x] Typed data model hierarchy (8 dataclasses, 4 enums)
- [x] Passive PCAP replay (offline file-based)
- [x] Packet parser with Shannon entropy
- [x] SQLite async storage (aiosqlite, WAL mode)
- [x] FastAPI health/readiness endpoints
- [x] API key authentication middleware
- [x] CLI entry point
- [x] 31 unit tests (all passing)
- [x] Deterministic PCAP test fixture
- [x] Documentation (README, ARCHITECTURE, SECURITY, ROADMAP)

## Phase 2: Flow Engine & Feature Extraction ✅

- [x] Flow aggregation engine (`FlowAggregator`)
  - Groups `ParsedPacket` streams into `ObservedFlow` records
  - Configurable idle timeout (default 120s) and max active flows (100K)
  - TCP flag tracking from bitmask (SYN, SYN/ACK, ACK, FIN, RST, PSH)
  - Bidirectional tracking with explicit forward/reverse counters
  - Does NOT fabricate unseen reverse traffic
- [x] Feature extraction pipeline (47 canonical features)
  - Packet size statistics (mean, std, min, max, median, p25, p75, p90)
  - Inter-arrival time statistics (all, forward, reverse)
  - TCP flag counts and ratios
  - Directional packet/byte ratios
  - Protocol identification (TCP/UDP/ICMP, IPv4/IPv6)
  - Payload byte ratios
  - No payload decryption — encrypted traffic treated as opaque
- [x] `ObservedFlow → FeatureVector` transformation
- [x] End-to-end `PcapPipeline` (PCAP → FeatureVector)
- [x] `FeatureVector.to_numpy_array()` for ML consumption
- [x] 90 unit tests (all passing, zero warnings)

## Phase 3: Detection Engine ✅

- [x] Feature audit (52 features verified safe — metadata only)
- [x] Dataset pipeline (scenario-aware splitting, leakage prevention)
- [x] Preprocessing (sklearn Pipeline — NaN/inf handling, StandardScaler)
- [x] Anomaly detection (unsupervised)
  - Isolation Forest baseline
  - Normalized anomaly score [0, 1]
  - `FeatureVector → AnomalyResult`
- [x] Threat classification (supervised)
  - XGBoost classifier (primary)
  - Random Forest baseline
  - Logistic Regression baseline
  - `FeatureVector → ThreatClassification`
- [x] Explainability (implemented in Phase 4)
  - SHAP feature attribution per detection (optional dependency)
  - Human-readable rationale generation
- [x] Detection pipeline integration
  - Full `FeatureVector → DetectionEvent` pipeline
  - Batch inference support
- [x] Model registry (versioned artifacts, SHA-256 checksums)
- [x] Evaluation framework (precision, recall, F1, confusion matrix)
- [x] Threshold configuration (configuration-driven, no hardcoded values)
- [x] Dataset provenance documentation (CIC-IDS2017, UNSW-NB15)

## Phase 4: Intelligence Hardening + Explainable Detection ✅

- [x] Retrospective audit of Phases 1–3
  - 5 genuine defects found and fixed
  - Unused import removal, dead stub removal, ROC-AUC nan handling
- [x] SHAP explainability (optional dependency)
  - `shap>=0.43` as optional extra (`pip install sentinel-net[explainability]`)
  - Lazy import — core detection works without SHAP
  - Graceful degradation when SHAP unavailable
  - evidence_type="model" for genuine SHAP values
- [x] Anomaly explanation
  - Statistical deviation from training distribution
  - evidence_type="statistical" (z-scores, NOT model contributions)
- [x] Structured Evidence model
  - Frozen dataclass with type validation
  - Traceable to actual FeatureVector data
  - Explicit evidence_type/direction/source
- [x] Human-readable rationale generation
  - Template-based, deterministic
  - Never claims "confirmed attack"
  - Always includes encrypted-payload limitation
- [x] MITRE ATT&CK mapping
  - Qualified technique mappings (possible/likely/observed indicators)
  - Static mapping table, no external API calls
  - Clear distinction: model classification ≠ ATT&CK mapping
- [x] ExplainableDetection composite type
  - Wraps DetectionEvent (immutable)
  - Evidence[] + Rationale + ATT&CK mappings
  - Explanation versioning, unique IDs, timestamps
- [x] AST-based security test suite (repository-wide passive verification)
- [x] Performance benchmarks (preprocessing, anomaly, classification, explanation)
- [x] 261 tests passing (zero failures)
- [x] Documentation (ml_architecture.md, explainability.md, threat_intelligence.md)

## Phase 5: Real-Time Passive Sensor + Detection API ✅

- [x] Critical auth bypass fix
  - `hmac.compare_digest()` for constant-time comparison
  - Empty/missing/malformed key → 401
  - Never log credential values
- [x] Passive live capture source (`sensor/capture.py`)
  - `scapy.sniff()` in receive-only mode
  - BPF filter validation (reject shell injection patterns)
  - Bounded packet queue (overflow → drop + metric)
  - `MockCaptureSource` for testing without root
- [x] Sensor lifecycle state machine (`sensor/lifecycle.py`)
  - STOPPED → STARTING → RUNNING → STOPPING → STOPPED + ERROR
  - Thread-safe transitions, signal handling (SIGINT/SIGTERM)
- [x] Thread-safe operational metrics (`sensor/metrics.py`)
  - 15 counters: packets, flows, features, detections, events, errors
  - Increment and gauge operations under lock
- [x] In-process EventBus (`sensor/event_bus.py`)
  - Bounded per-subscriber queues
  - No Redis/Kafka/RabbitMQ dependency
  - Drop-on-full with counter
  - Detection continues with zero subscribers
- [x] Live sensor pipeline (`sensor/pipeline.py`)
  - Reuses PCAP processing components (parser, aggregator, extractor)
  - Deterministic processing parity with offline PCAP
- [x] Extended database schema
  - `threat_type`, `anomaly_score`, `model_version` columns
  - Indexes on timestamp, threat_type, severity
  - Retention cleanup (max count, max age)
  - All queries parameterized (no f-string SQL)
- [x] REST API
  - `GET /api/v1/events` — paginated, filtered (threat_type, severity, flow_id, since)
  - `GET /api/v1/events/{id}` — single event lookup
  - `GET /api/v1/flows` — paginated flow listing
  - `GET /api/v1/flows/{id}` — single flow lookup
  - `GET /api/v1/stats` — aggregate statistics
  - `GET /api/v1/status` — sensor state, metrics, schema version
  - Bounded response sizes (limit 1-200)
  - No stack traces or secrets in error responses
- [x] WebSocket event stream
  - `WS /api/v1/ws/events` — real-time events
  - Auth-message-first flow (constant-time comparison)
  - Optional query-param fallback (disabled by default)
  - Bounded per-client queue, heartbeat pings
  - Graceful disconnect, no credential logging
- [x] Configurable CORS origins (dev = `*`, prod = explicit list)
- [x] AST-based sensor security tests (no subprocess, no send, no shell)
- [x] PCAP ↔ live capture processing parity tests
- [x] 344 tests passing (zero failures, 10.71s)
- [x] Documentation (docs/live_sensor.md, docs/api.md)

## Phase 6: SOC Dashboard ✅

- [x] Retrospective audit (9 backend defects found and fixed)
- [x] Pydantic response schemas (EventResponse, FlowResponse, StatsResponse, StatusResponse, HealthResponse)
- [x] Enriched event storage with explanation data (evidence, ATT&CK mappings in metadata)
- [x] LEFT JOIN flows in events queries (IP/port context for frontend)
- [x] Database indexes (events.flow_id, flows.start_time)
- [x] Pipeline predict() → detect_batch() fix
- [x] React + TypeScript + Vite SOC dashboard (frontend/)
- [x] 8 pages: Overview, Detections, Detection Detail, Flows, Flow Detail, Sensor, Intelligence, Settings
- [x] Typed API client (centralized fetch, API key in closure)
- [x] WebSocket manager (auth-message-first, exponential backoff, bounded buffer 100 events)
- [x] Dark operator interface (WCAG 2.1 AA, keyboard accessible)
- [x] Evidence visualization with contribution bars
- [x] ATT&CK mapping display (backend-sourced only, never frontend-generated)
- [x] Pagination, filtering, empty/error/stale states
- [x] Security: no credential leakage, no eval(), no dangerouslySetInnerHTML, sessionStorage only
- [x] 351 backend tests + 48 frontend tests (zero failures)
- [x] TypeScript strict mode passes, production build passes

## Phase 7: Adversarial Evaluation + Scientific Validation ✅

- [x] Locked evaluation protocol (OPEN → THRESHOLD_LOCKED → FINAL_EVALUATED)
- [x] Experiment manifests for reproducibility
- [x] Validation-based threshold optimizer
- [x] Enhanced evaluation metrics (multi-class ROC-AUC, PR-AUC)
- [x] Scenario-ID disjointness verification
- [x] Model comparison across 4 models
- [x] Class imbalance analysis
- [x] False positive / false negative collection
- [x] Simulated unidirectional feature ablation
- [x] Feature group ablation (7 groups)
- [x] Controlled robustness experiments (5 perturbation types)
- [x] Calibration analysis (NOT for anomaly scores)
- [x] Cross-scenario holdout evaluation
- [x] Model stability (multi-seed variance)
- [x] Out-of-distribution analysis
- [x] Failure taxonomy (F1–F10)
- [x] Score type discipline enforcement
- [x] Synthetic validation pipeline
- [x] Research report generator
- [x] Evaluation documentation and limitations

## Phase 8: Hardening & Production

- [ ] CI/CD pipeline (GitHub Actions)
- [ ] Type checking enforcement (`mypy --strict`)
- [ ] Linting enforcement (`ruff check`)
- [ ] Test coverage thresholds (>80%)
- [ ] Performance benchmarking (packets/sec)
- [ ] Memory profiling for large PCAP files
- [ ] Logging to file with rotation
- [ ] Health monitoring and alerting
- [ ] Deployment documentation

