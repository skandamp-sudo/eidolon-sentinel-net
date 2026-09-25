# EIDOLON // SENTINEL-NET — Architecture


> Release scope: the diagram below records earlier implementation layers. The current path adds F3 behavioral, F4 DNS, F5 TLS/QUIC and F6 investigation/export; see [current README](README.md), [F6 architecture](docs/sih-f6-architecture.md) and [release artifact policy](docs/release-artifact-policy.md). Runtime QA and evaluated candidate are distinct. Native capture and physical diode remain NOT VERIFIED.

## System Overview

SENTINEL-NET is a passive cyber threat detection prototype that processes unidirectional IP traffic through a structured, typed pipeline. The system supports both offline PCAP analysis and real-time passive traffic observation via a REST API and WebSocket event stream.

## Architecture Diagram

```
┌───────────────────┐    ┌─────────────────────────────┐
│ PCAP FILES        │    │ LIVE TRAFFIC (passive sniff) │
│ (Offline Input)   │    │ sensor/capture.py            │
└─────────┬─────────┘    └──────────────┬──────────────┘
          │                             │
          │  replay.py → RawPacket      │  AsyncSniffer → RawPacket
          └──────────┬──────────────────┘
                     ▼
┌─────────────────────────────────────────────────────────────────┐
│  INGESTION LAYER (Passive observation; operator API separate)        │
│                                                                  │
│  parser.py: extract_raw_packet() → parse_packet()                │
│             RawPacket           → ParsedPacket                   │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│  FLOW ENGINE ✅                                                  │
│                                                                  │
│  FlowAggregator: ParsedPacket → ObservedFlow                    │
│  Canonical FlowKey (sorted endpoints + protocol)                 │
│  Tracks forward/reverse directions from initiator                │
│  Idle timeout, active-flow cap; exact histories grow                       │
│  TCP flag counting, IAT tracking, packet sizes                   │
│  Does NOT infer unseen reverse traffic                           │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│  FEATURE EXTRACTION ✅                                           │
│                                                                  │
│  FeatureExtractor: ObservedFlow → FeatureVector                  │
│  52 canonical features (deterministic ordering)                  │
│  Basic metrics, directional ratios, packet size stats            │
│  IAT statistics, TCP flag counts/ratios, protocol IDs            │
│  No payload decryption — encrypted traffic treated as opaque     │                   │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│  DETECTION ENGINE ✅ (Phase 3)                                   │
│                                                                  │
│  Preprocessing: sklearn Pipeline (imputer + scaler)              │
│  Anomaly Detection: Isolation Forest → [0,1] anomaly score       │
│  Threat Classification: XGBoost / RF / LogReg baselines          │
│  Detection Pipeline: FeatureVector → DetectionEvent              │
│  Model Registry: versioned artifacts with SHA-256 verification   │
│  Evaluation: precision, recall, F1, confusion matrix, ROC-AUC    │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│  EXPLAINABILITY ENGINE ✅ (Phase 4)                              │
│                                                                  │
│  SHAP TreeExplainer (optional): XGBoost/RF → Evidence[model]     │
│  AnomalyExplainer: statistical deviation → Evidence[statistical] │
│  RationaleGenerator: Evidence[] → human-readable rationale       │
│  ATTACKMapper: ThreatType → qualified ATT&CK technique mappings  │
│  ExplainableDetection: DetectionEvent + Evidence + Rationale     │
│  No causal claims — "Feature X contributed to the model decision"│
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│  STORAGE LAYER ✅                                                │
│                                                                  │
│  SQLite (aiosqlite) — WAL mode                                   │
│  Tables: flows (13 cols), events (12 cols + indexes)             │
│  Retention: max count + max age cleanup                          │
│  All queries parameterized (no f-string SQL)                     │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│  API + EVENT BUS ✅ (Phase 5)                                    │
│                                                                  │
│  FastAPI (REST)               │  WebSocket (real-time)           │
│  /health, /readiness          │  WS /api/v1/ws/events            │
│  /api/v1/events (filtered)    │  Auth-message-first flow         │
│  /api/v1/flows (paginated)    │  Bounded per-client queue        │
│  /api/v1/stats (aggregated)   │  Heartbeat pings                 │
│  /api/v1/status (sensor info) │  hmac.compare_digest auth        │
│                               │                                  │
│  EventBus (in-process)        │  Sensor Metrics (15 counters)    │
│  Bounded pub/sub              │  Thread-safe, lockable           │
│  No Redis/Kafka               │  Lifecycle state machine         │
└──────────────┬──────────────────────────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────────────────────────┐
│  SOC FRONTEND ✅ (Phase 6)                                      │
│                                                                  │
│  React + TypeScript + Vite     │  Pure API Consumer              │
│  8 pages:                      │  No ML inference                 │
│  • Overview (SOC Command)      │  No anomaly scoring              │
│  • Detections (filter/page)    │  No threat classification        │
│  • Detection Detail (evidence) │  No ATT&CK inference             │
│  • Flows (paginated)           │  No payload display              │
│  • Flow Detail                 │  No active network ops           │
│  • Sensor (read-only metrics)  │                                  │
│  • Intelligence (ATT&CK view)  │  WebSocket: auth-message-first   │
│  • Settings (connection)       │  Bounded event buffer (100)      │
│                                │  Exponential backoff reconnect   │
│  sessionStorage auth only      │  Duplicate event protection      │
│  WCAG 2.1 AA contrast          │  REST for historical data        │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│  EVALUATION FRAMEWORK ✅ (Phase 7)                              │
│                                                                  │
│  Protocol: OPEN → THRESHOLD_LOCKED → FINAL_EVALUATED            │
│  Manifest: dataset, split, seed, model, threshold, schema ver   │
│  Score discipline: anomaly score ≠ classification ≠ probability │
│                                                                  │
│  Experiments:                  │  Analysis:                       │
│  • Model comparison (4 models) │  • Calibration (NOT for IForest) │
│  • Feature ablation (7 groups) │  • Class imbalance               │
│  • Robustness (5 perturbations)│  • FP/FN collection              │
│  • Unidirectional (simulated)  │  • OOD analysis                  │
│  • Cross-scenario holdout      │  • Failure taxonomy (F1–F10)     │
│  • Model stability (multi-seed)│  • Threshold optimization (val)  │
│                                │                                  │
│  Outputs: experiments/ directory with JSON metrics + MD reports  │
└─────────────────────────────────────────────────────────────────┘
```

## Data Model Pipeline

Every stage of the pipeline has a distinct typed data structure:

| Stage | Type | Description |
|-------|------|-------------|
| Capture | `RawPacket` | Raw bytes + pcap metadata |
| Parsing | `ParsedPacket` | Structured IP/transport fields |
| Aggregation | `ObservedFlow` | Unidirectional flow record |
| Features | `FeatureVector` | Statistical feature set |
| Anomaly | `AnomalyResult` | Unsupervised detection output |
| Classification | `ThreatClassification` | Supervised threat label |
| Event | `DetectionEvent` | Complete record for storage |
| Explanation | `ExplainableDetection` | Event + Evidence + Rationale + ATT&CK |

## Design Principles

### 1. Structural Passivity
The ingestion layer cannot send packets by design — it imports only read functions from scapy, never active send/probe operations. Live capture uses `AsyncSniffer` over a receive-only L2 listen socket.

### 2. Unidirectional Fidelity
If only one direction of a flow is observed, the system represents exactly that. There is no inference of reverse traffic.

### 3. Typed Pipeline
Core processing stages have typed records; event metadata and analyst projections also use validated dictionaries.

### 4. Offline-First
Recorded processing works from PCAP files. Live capture architecture exists behind the shared passive-source interface; native-interface validation remains deployment-specific and NOT VERIFIED.

## Flow Lifecycle

```
ParsedPacket arrives
  ↓
FlowAggregator.ingest()
  ↓
Compute canonical FlowKey (direction_key — sorted endpoints + protocol)
  ↓
Match to existing _ActiveFlow? ──No──→ Create new _ActiveFlow (first packet = initiator)
  ↓ Yes                                       ↓
Update counters                      Check max_active_flows → evict oldest if full
  ↓
Classify direction (forward if src matches initiator, else reverse)
  ↓
Update: fwd/rev packet+byte counts, TCP flags, IATs, packet sizes
  ↓
Flow completes when: idle_timeout expires │ TCP FIN/RST seen │ flush_all() called
  ↓
_ActiveFlow → finalized ObservedFlow (immutable)
  ↓
Queued in completed list (sorted by start_time for deterministic output)
```

**Timeout Configuration:**
- `idle_timeout_sec` (default 120s): Flow expires after N seconds of inactivity
- `max_active_flows` (default 100,000): Oldest flow evicted when limit reached

## Feature Schema (52 Features)

| Category | Features | Count |
|----------|----------|-------|
| Basic | duration, total_packets/bytes, packets/bytes per sec | 5 |
| Directional | fwd/rev packets/bytes, fwd/rev ratios | 6 |
| Packet Size | mean, std, min, max, median, p25, p75, p90 | 8 |
| IAT (all) | mean, std, min, max, median | 5 |
| IAT (forward) | mean, std, min, max | 4 |
| IAT (reverse) | mean, std, min, max | 4 |
| TCP Flags | SYN/SYN-ACK/ACK/FIN/RST/PSH counts + ratios | 11 |
| Protocol | protocol number, ip_version, is_tcp/udp/icmp | 5 |
| Payload | total/fwd/rev payload bytes, payload ratio | 4 |

Features are deterministically ordered. New features are only appended, never reordered. `FeatureVector.to_numpy_array()` returns a float64 array in canonical order.

## Technology Stack

| Component | Technology | Rationale |
|-----------|-----------|-----------|
| Language | Python 3.12+ | Mature ecosystem for ML + networking |
| Package Manager | uv | Fast, reproducible dependency resolution |
| Packet Parsing | scapy | Industry standard, no external binary deps |
| Storage | SQLite (aiosqlite) | Zero-config, embedded, WAL for concurrency |
| API Framework | FastAPI | Async, auto-docs, Pydantic integration |
| Config | pydantic-settings | Type-safe env var config |
| Testing | pytest + pytest-asyncio | Async test support |

## Phase Plan

| Phase | Scope | Status |
|-------|-------|--------|
| 1 | Foundation, ingestion, parsing, storage, health API, tests | ✅ Complete |
| 2 | Flow aggregation engine, feature extraction, pipeline | ✅ Complete |
| 3 | Anomaly detection, threat classification, model registry | ✅ Complete |
| 4 | Explainability, SHAP, ATT&CK mapping, intelligence hardening | ✅ Complete |
| 5 | Expanded API, live capture (read-only), WebSocket alerts | 🔲 Planned |
| 6 | SOC Dashboard (React/Next.js) | 🔲 Planned |
| 7 | Hardening, performance, CI/CD | 🔲 Planned |
