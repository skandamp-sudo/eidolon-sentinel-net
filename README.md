# EIDOLON // SENTINEL-NET

**AI-Powered Passive Cyber Threat Detection System**

A cybersecurity research prototype for AI-based detection of cyber threats in unidirectional IP traffic. The system processes network packet captures (PCAPs) or live traffic through a structured pipeline: passive ingestion → packet parsing → flow aggregation → feature extraction → anomaly detection → threat classification → explainable detection → event storage → REST API / WebSocket stream.

> **Security Principle**: The system is structurally passive — it has NO code path capable of sending packets, probing hosts, or initiating network connections. Live capture uses a receive-only L2 socket and Scapy `AsyncSniffer`. PCAP processing is entirely offline.

## Continuous passive sensor (RW-2)

Run `sentinel-net sensor --interface <interface> --model <model-name/version>` with an approved frozen bundle in `SENTINEL_MODEL_REGISTRY` and private API-key configuration. Replay also requires `--model` and never trains. See [RW-4 operator workflow](docs/rw4-frozen-models.md). The CLI owns capture, processing, storage and graceful SIGINT/SIGTERM shutdown; it does not train models. Live health distinguishes RUNNING, DEGRADED and FAILED from recorded replay.

See the [RW-2 operator guide](docs/rw2-continuous-sensor.md) for artifact prerequisites, metrics, shutdown guarantees, remaining resource risks and manual interface validation. No deployed model artifact is included. Historical evaluation results have not been reproduced for the RW-1 segmentation corrections.

## Earlier implementation phases

### Phase 1 ✅
✅ Project foundation and configuration  
✅ Typed data model hierarchy (8 dataclasses, 4 enums)  
✅ Passive PCAP ingestion and parsing  
✅ SQLite event storage  
✅ FastAPI health endpoint  
✅ Structured logging  

### Phase 2 ✅
✅ Flow aggregation engine (FlowAggregator)  
✅ Feature extraction (52-feature schema)  
✅ End-to-end pipeline: PCAP → ParsedPacket → ObservedFlow → FeatureVector  
✅ Bidirectional flow tracking with directional counters  
✅ TCP flag counting from bitmask  
✅ Packet size and inter-arrival time statistics  
✅ Configurable idle timeout and bounded memory  
✅ Deterministic feature ordering for ML consumption  

### Phase 3 ✅
✅ Feature audit (52 features verified safe — metadata only, no payload inspection)  
✅ Dataset pipeline with scenario-aware splitting (anti-leakage)  
✅ Preprocessing (sklearn Pipeline — NaN/inf imputer + StandardScaler)  
✅ Anomaly detection (Isolation Forest, normalized [0,1] scores)  
✅ Threat classification (XGBoost, Random Forest, Logistic Regression)  
✅ Detection pipeline: FeatureVector → DetectionEvent  
✅ Model registry with SHA-256 checksum verification  
✅ Evaluation framework (precision, recall, F1, confusion matrix, ROC-AUC)  

### Phase 4 ✅
✅ Retrospective audit of Phases 1–3 (5 defects found and fixed)  
✅ SHAP explainability (optional dependency, lazy import, graceful degradation)  
✅ Anomaly explanation (statistical deviation, evidence_type="statistical")  
✅ Structured Evidence model with type validation  
✅ Human-readable rationale generation  
✅ MITRE ATT&CK mapping with qualification levels  
✅ ExplainableDetection composite type  
✅ AST-based security test suite  
✅ Performance benchmarks  

### Phase 5 ✅
✅ Critical auth bypass fix (hmac.compare_digest)  
✅ Passive live capture source (scapy.sniff, receive-only)  
✅ BPF filter validation (shell injection prevention)  
✅ Sensor lifecycle state machine (STOPPED→STARTING→RUNNING→STOPPING)  
✅ Thread-safe operational metrics (15 counters)  
✅ In-process EventBus (bounded pub/sub, no Redis/Kafka)  
✅ Live sensor pipeline (reuses PCAP processing components)  
✅ PCAP ↔ live capture processing parity  
✅ Extended database schema (threat_type, anomaly_score, model_version indexes)  
✅ REST API: events, flows, stats, status (paginated, filtered, authenticated)  
✅ WebSocket event stream (auth-message-first, heartbeat, bounded queues)  
✅ Event retention (max count, max age, configurable cleanup)  
✅ Configurable CORS origins  
✅ No stack traces or secrets in error responses  
✅ AST-based sensor security tests  

### Phase 6 ✅
✅ Retrospective audit (9 backend defects found and fixed)  
✅ Pydantic response schemas for all API endpoints  
✅ Event storage enriched with explanation data (evidence, ATT&CK mappings)  
✅ LEFT JOIN flows in events queries (IP/port context)  
✅ Database indexes (events.flow_id, flows.start_time)  
✅ Pipeline predict() method fixed → detect_batch()  
✅ Version consistency (health → 0.6.0)  
✅ React + TypeScript + Vite SOC dashboard  
✅ 8 pages: Overview, Detections, Detection Detail, Flows, Flow Detail, Sensor, Intelligence, Settings  
✅ Typed API client with centralized fetch  
✅ WebSocket manager (auth-message-first, exponential backoff, bounded buffer)  
✅ Dark operator interface (WCAG 2.1 AA contrast, keyboard accessible)  
✅ Evidence visualization with contribution bars  
✅ ATT&CK mapping display (backend-sourced only)  
✅ Pagination, filtering, empty/error states  
✅ No credential leakage, no eval(), no dangerouslySetInnerHTML  
✅ No Redux, no second HTTP client, no unnecessary dependencies  

### Phase 7 ✅
✅ Locked evaluation protocol (OPEN → THRESHOLD_LOCKED → FINAL_EVALUATED)  
✅ Experiment manifests for full reproducibility  
✅ Validation-based threshold optimizer (VALIDATION data only)  
✅ Enhanced metrics (multi-class OVR ROC-AUC, PR-AUC, class imbalance)  
✅ Scenario-ID disjointness verification in dataset splits  
✅ Model comparison (all 4 models on identical partitions)  
✅ Class imbalance analysis  
✅ False positive / false negative collection and categorization  
✅ Simulated unidirectional feature ablation (correctly labeled, not real unidirectional)  
✅ Feature group ablation (7 groups, model dependence measurement)  
✅ Controlled robustness experiments (timing jitter, packet size, flow duration, directional, missing metadata)  
✅ Calibration analysis (Brier, ECE, reliability diagrams — NOT for IForest anomaly scores)  
✅ Cross-scenario holdout evaluation  
✅ Model stability (multi-seed variance)  
✅ OOD analysis (synthetic inputs, novelty vs malice distinction)  
✅ Failure taxonomy (F1–F10, evidence-based classification)  
✅ Score type discipline (anomaly score ≠ classification score ≠ probability)  
✅ Synthetic validation pipeline  
✅ Research report generator  
✅ Experiment artifacts directory structure  
✅ CICIDS2017 dataset adapter (29 DIRECT + 12 DERIVED + 11 MISSING = 52 features)  
✅ UNSW-NB15 dataset adapter (6 DIRECT + 8 DERIVED + 3 PROXY + 35 MISSING = 52 features)  
✅ Feature availability matrices for both datasets  
✅ Label mapping with encoding-variant handling (mojibake, en-dash)  
✅ Preprocessing compatibility audit  
✅ 432 backend tests + 48 frontend tests (zero failures)  
✅ Documentation: evaluation methodology, dataset adapters, feature availability, limitations  

## Quick Start

### Prerequisites

- macOS (tested on 26.x)
- Python 3.12+
- [uv](https://docs.astral.sh/uv/) package manager

### Setup

```bash
# Clone the repository
cd "Eidolon Sentinel-NET"

# Install dependencies and create virtualenv
uv sync

# Install optional explainability dependencies (SHAP)
uv pip install -e ".[explainability]"

# Run tests
uv run pytest tests/ -v

# Start the API server
uv run sentinel-net
# or: uv run uvicorn sentinel_net.api.main:app --host 127.0.0.1 --port 8000
```

### Configuration

Copy `.env.example` to `.env` and configure:

```bash
cp .env.example .env
```

| Variable | Default | Description |
|----------|---------|-------------|
| `SENTINEL_ENV` | `development` | Environment name |
| `SENTINEL_DATABASE_PATH` | `data/sentinel_net.db` | SQLite database file path |
| `SENTINEL_API_HOST` | `127.0.0.1` | API bind address |
| `SENTINEL_API_PORT` | `8000` | API bind port |
| `SENTINEL_API_KEY` | `changeme-dev` | API authentication key |
| `SENTINEL_LOG_LEVEL` | `INFO` | Logging level |
| `SENTINEL_PCAP_DIR` | `data/pcaps` | Directory for PCAP files |

### PCAP Replay

```python
from pathlib import Path
from sentinel_net.ingestion.replay import PcapReplay, PcapReplayConfig

config = PcapReplayConfig(pcap_path=Path("capture.pcap"))
replay = PcapReplay(config)

# Synchronous
packets = replay.replay_sync()
print(f"Parsed {replay.parsed_count}/{replay.packet_count} packets")

# Asynchronous
async for packet in replay.replay():
    print(f"{packet.src_ip}:{packet.src_port} -> {packet.dst_ip}:{packet.dst_port}")
```

## Data Model Hierarchy

```
RawPacket          → Raw bytes + capture metadata
  ↓
ParsedPacket       → Structured fields (IP, TCP/UDP, entropy)
  ↓
ObservedFlow       → Aggregated bidirectional flow record (observed traffic only)
  ↓
FeatureVector      → 47 statistical features (deterministic schema)
  ↓
AnomalyResult      → Anomaly detection output (Phase 3)
  ↓
ThreatClassification → Threat label + confidence (Phase 3)
  ↓
DetectionEvent     → Complete event for storage/API
```

> **Observation Rule**: If only one direction is observed, the other direction's counters remain at zero. The system does NOT fabricate or infer unseen reverse traffic.

### Pipeline Usage (Phase 2)

```python
from pathlib import Path
from sentinel_net.pipeline import PcapPipeline

pipeline = PcapPipeline()
result = pipeline.process(Path("capture.pcap"))

print(f"{result.total_packets} packets → {result.total_flows} flows")
for fv in result.feature_vectors:
    arr = fv.to_numpy_array()  # Ready for future ML models
    print(f"  Flow: {fv.flow_key.unidirectional_key} → {len(arr)} features")
```

## Project Structure

```
src/sentinel_net/
├── __init__.py           # Package version
├── config.py             # Pydantic Settings configuration
├── cli.py                # CLI entry point
├── pipeline.py           # End-to-end PCAP → FeatureVector pipeline
├── models/
│   ├── types.py          # 8 typed dataclasses + TCP flag constants
│   └── enums.py          # Severity, ThreatType, Direction, Protocol
├── ingestion/
│   ├── parser.py         # Passive packet parsing (READ-ONLY)
│   └── replay.py         # Offline PCAP file replay
├── flow/
│   └── aggregator.py     # Flow aggregation engine
├── features/
│   ├── schema.py         # Canonical 47-feature schema
│   └── extractor.py      # ObservedFlow → FeatureVector extraction
├── storage/
│   └── database.py       # SQLite async storage (aiosqlite)
└── api/
    ├── main.py           # FastAPI application factory
    ├── auth.py           # API key middleware
    └── routes/
        └── health.py     # Health/readiness endpoints
```

## Testing

```bash
# Run all tests
uv run pytest tests/ -v

# With coverage
uv run pytest tests/ --cov=sentinel_net --cov-report=term-missing

# Generate test PCAP fixture
uv run python tests/fixtures/generate_test_pcap.py
```

## License

MIT — See [LICENSE](LICENSE) for details.

## Security

See [SECURITY.md](SECURITY.md) for the passive ingestion security model and threat analysis.
