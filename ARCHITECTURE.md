# EIDOLON // SENTINEL-NET — Architecture

## System Overview

SENTINEL-NET is a passive cyber threat detection prototype that processes unidirectional IP traffic through a structured, typed pipeline. The system is designed for offline analysis of PCAP files with no live network interaction.

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                    PCAP FILES (Offline Input)                    │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│  INGESTION LAYER (Structurally Passive — No Network I/O)        │
│                                                                  │
│  replay.py ──→ parser.py                                         │
│  PcapReader     extract_raw_packet() → parse_packet()            │
│  (read-only)    RawPacket           → ParsedPacket               │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│  FLOW ENGINE (Phase 2)                                           │
│                                                                  │
│  FlowKey → ObservedFlow aggregation                              │
│  Unidirectional — does NOT infer reverse traffic                 │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│  FEATURE EXTRACTION (Phase 2)                                    │
│                                                                  │
│  ObservedFlow → FeatureVector                                    │
│  Statistical features, entropy, timing metrics                   │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│  DETECTION ENGINE (Phase 3)                                      │
│                                                                  │
│  Anomaly Detection: FeatureVector → AnomalyResult                │
│  Threat Classification: FeatureVector → ThreatClassification     │
│  Explainability: SHAP-based feature attribution                  │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│  STORAGE LAYER                                                   │
│                                                                  │
│  SQLite (aiosqlite) — WAL mode                                   │
│  Tables: flows, events                                           │
│  DetectionEvent serialization                                    │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│  API / DASHBOARD                                                 │
│                                                                  │
│  FastAPI (REST)          │  SOC Dashboard (Phase 5)              │
│  /health, /readiness     │  React/Next.js                       │
│  /api/v1/events          │  Real-time alert feed                │
│  /api/v1/flows           │  Flow visualization                  │
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

## Design Principles

### 1. Structural Passivity
The ingestion layer cannot send packets by design — it imports only read functions from scapy, never `send`, `sendp`, `sr`, `sr1`, or `AsyncSniffer`.

### 2. Unidirectional Fidelity
If only one direction of a flow is observed, the system represents exactly that. There is no inference of reverse traffic.

### 3. Typed Pipeline
Each processing stage has a dedicated dataclass. No dynamic dictionaries flowing through the pipeline.

### 4. Offline-First
All processing works from PCAP files. Live capture is a future extension (Phase 4+), isolated behind a strict read-only interface.

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
| 2 | Flow aggregation engine, feature extraction | 🔲 Planned |
| 3 | Anomaly detection, threat classification, SHAP | 🔲 Planned |
| 4 | Expanded API, live capture (read-only), WebSocket alerts | 🔲 Planned |
| 5 | SOC Dashboard (React/Next.js) | 🔲 Planned |
| 6 | Hardening, performance, CI/CD | 🔲 Planned |
