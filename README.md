# EIDOLON // SENTINEL-NET

**AI-Powered Passive Cyber Threat Detection System**

A cybersecurity research prototype for AI-based detection of cyber threats in unidirectional IP traffic. The system processes network packet captures (PCAPs) through a structured pipeline: passive ingestion → packet parsing → flow aggregation → feature extraction → anomaly detection → threat classification → event storage → API/dashboard.

> **Security Principle**: The ingestion layer is structurally passive — it has NO code path capable of sending packets, probing hosts, or initiating network connections. PCAP processing is entirely offline.

## Current Status: Phase 1 — Foundation

✅ Project foundation and configuration  
✅ Typed data model hierarchy (7 distinct types)  
✅ Passive PCAP ingestion and parsing  
✅ SQLite event storage  
✅ FastAPI health endpoint  
✅ Structured logging  
✅ Unit test suite (31 tests)  
✅ Deterministic PCAP test fixtures  

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
ObservedFlow       → Aggregated unidirectional flow record
  ↓
FeatureVector      → Statistical features (Phase 2)
  ↓
AnomalyResult      → Anomaly detection output (Phase 3)
  ↓
ThreatClassification → Threat label + confidence (Phase 3)
  ↓
DetectionEvent     → Complete event for storage/API
```

> **Unidirectional Rule**: If only one direction is observed, it is represented explicitly. The system does NOT infer unseen reverse traffic.

## Project Structure

```
src/sentinel_net/
├── __init__.py           # Package version
├── config.py             # Pydantic Settings configuration
├── cli.py                # CLI entry point
├── models/
│   ├── types.py          # 8 typed dataclasses
│   └── enums.py          # Severity, ThreatType, Direction, Protocol
├── ingestion/
│   ├── parser.py         # Passive packet parsing (READ-ONLY)
│   └── replay.py         # Offline PCAP file replay
├── flow/                 # Flow aggregation (Phase 2)
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
