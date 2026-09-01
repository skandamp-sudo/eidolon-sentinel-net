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

## Phase 2: Flow Engine & Feature Extraction

- [ ] Flow aggregation engine (`FlowAggregator`)
  - Group `ParsedPacket` streams into `ObservedFlow` records
  - Configurable flow timeout and idle timeout
  - TCP state tracking (SYN, FIN, RST)
  - Unidirectional by default, optional bidirectional correlation
- [ ] Feature extraction pipeline
  - Packet size statistics (mean, std, min, max)
  - Inter-arrival time statistics
  - Entropy statistics (payload, packet sizes)
  - TCP flag distributions
  - Byte/packet ratio
  - Flow duration features
- [ ] `ObservedFlow → FeatureVector` transformation
- [ ] Integration tests with larger PCAP files
- [ ] Flow storage in SQLite

## Phase 3: Detection Engine

- [ ] Anomaly detection (unsupervised)
  - Isolation Forest baseline
  - Feature scaling/normalization
  - `FeatureVector → AnomalyResult`
- [ ] Threat classification (supervised)
  - XGBoost / LightGBM classifier
  - Training pipeline with labeled datasets
  - `FeatureVector → ThreatClassification`
- [ ] Explainability
  - SHAP feature attribution per detection
  - Human-readable rationale generation
- [ ] Detection pipeline integration
  - Full `PCAP → DetectionEvent` pipeline
  - End-to-end integration tests
- [ ] Model serialization and versioning

## Phase 4: API Expansion & Live Capture

- [ ] REST API endpoints
  - `GET /api/v1/events` — paginated event listing
  - `GET /api/v1/flows` — flow listing with filters
  - `GET /api/v1/alerts` — alert management
  - `PATCH /api/v1/alerts/{id}/acknowledge`
- [ ] WebSocket alert streaming (`/ws/alerts`)
- [ ] Live packet capture (read-only, requires root)
  - `AsyncSniffer` wrapper with strict passive constraints
  - Interface binding (no promiscuous mode by default)
- [ ] Redis pub/sub for real-time event bus (optional)
- [ ] PostgreSQL/TimescaleDB for production storage (optional)
- [ ] Rate limiting and request validation

## Phase 5: SOC Dashboard

- [ ] React/Next.js dashboard application
  - Real-time alert feed
  - Flow visualization (timeline, Sankey)
  - Detection event details with SHAP waterfall plots
  - IP/port frequency analysis
  - Protocol distribution charts
- [ ] WebSocket integration for live updates
- [ ] Alert acknowledgment UI
- [ ] PCAP upload for ad-hoc analysis

## Phase 6: Hardening & Production

- [ ] CI/CD pipeline (GitHub Actions)
- [ ] Type checking enforcement (`mypy --strict`)
- [ ] Linting enforcement (`ruff check`)
- [ ] Test coverage thresholds (>80%)
- [ ] Performance benchmarking (packets/sec)
- [ ] Memory profiling for large PCAP files
- [ ] Logging to file with rotation
- [ ] Health monitoring and alerting
- [ ] Deployment documentation
