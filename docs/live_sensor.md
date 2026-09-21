# Live Sensor and Detection API

For the CLI-owned continuous service, current lifecycle, startup/shutdown ordering, and limitations, use the [RW-2 operator guide](rw2-continuous-sensor.md). The component overview below records the earlier Phase 5 architecture.

## Overview

Phase 5 extends SENTINEL-NET from offline PCAP replay to real-time passive traffic observation
with a REST API and WebSocket event stream.

```
LIVE TRAFFIC or PCAP
        ↓
  Passive Capture (scapy.sniff, read-only)
        ↓
  RawPacket → ParsedPacket
        ↓
  FlowAggregator (reused from Phase 2)
        ↓
  FeatureExtractor → 52-feature FeatureVector
        ↓
  DetectionPipeline (IF + XGBoost)
        ↓
  ExplainableDetection (SHAP + evidence)
        ↓
  SQLite commit → EventBus → REST API / WebSocket stream
```

## Architecture

### Passive Capture (`sensor/capture.py`)

**SECURITY**: The capture module ONLY receives packets. It has no code path for:
- Sending, injecting, or modifying packets
- Active probing or scanning
- Shell command execution
- Privilege escalation

The `PassiveCaptureSource` now uses a receive-only L2 socket and `AsyncSniffer` with:
- Configurable BPF filter (validated against shell injection)
- Bounded packet queue (overflow → drop + metric increment)
- Thread-isolated capture loop
- Descriptive PermissionError messages

BPF filter validation rejects: `;`, `|`, `` ` ``, `$()`, `>`, `<`, `&`, `!`

A `MockCaptureSource` is provided for testing without root/pcap permissions.

### Sensor Pipeline (`sensor/pipeline.py`)

Reuses **the same** processing components as offline PCAP analysis:
- `parse_packet()` from `ingestion/parser.py`
- `FlowAggregator` from `flow/aggregator.py`
- `FeatureExtractor` from `features/extractor.py`
- `DetectionPipeline` from `detection/inference.py` (required for the live service)

This ensures PCAP and live-capture results are deterministically equivalent.

### Event Bus (`sensor/event_bus.py`)

Lightweight in-process pub/sub with bounded per-subscriber queues:
- No Redis, Kafka, or RabbitMQ required
- Each WebSocket client gets its own bounded queue
- Full queue → event dropped for that subscriber (counter incremented)
- Detection pipeline continues with zero subscribers
- Thread-safe publish/subscribe

### Sensor Lifecycle (`sensor/lifecycle.py`)

State machine: `STOPPED → STARTING → RUNNING → STOPPING → STOPPED`

- Thread-safe transitions validated against allowed transition table
- `ERROR` state reachable from STARTING, RUNNING, STOPPING
- Recovery: `ERROR → STARTING` or `ERROR → STOPPED`
- SIGINT/SIGTERM signal handlers trigger graceful shutdown

### Metrics (`sensor/metrics.py`)

Thread-safe operational counters:
- `packets_observed`, `packets_parsed`, `packets_malformed`, `packets_dropped`
- `flows_active`, `flows_completed`, `flows_evicted`
- `features_generated`, `detections_generated`
- `events_persisted`, `events_dropped`
- `capture_errors`, queue depths, uptime

## REST API

All endpoints (except health/readiness) require `X-API-Key` header authentication.

### Public Endpoints
| Endpoint | Description |
|---|---|
| `GET /health` | Liveness check |
| `GET /readiness` | DB connectivity check |

### Protected Endpoints
| Endpoint | Description |
|---|---|
| `GET /api/v1/events` | Paginated, filterable event list |
| `GET /api/v1/events/{id}` | Single event lookup |
| `GET /api/v1/flows` | Paginated flow list |
| `GET /api/v1/flows/{id}` | Single flow lookup |
| `GET /api/v1/stats` | Aggregate statistics |
| `GET /api/v1/status` | Sensor state, metrics, schema version |
| `WS /api/v1/ws/events` | Real-time event stream |

### Filtering

Events support query parameters:
- `limit` (1-200, default 50)
- `offset` (≥0, default 0)
- `threat_type` (e.g., `ddos`, `c2`, `benign`)
- `severity` (e.g., `high`, `medium`, `info`)
- `since` (Unix epoch timestamp)
- `flow_id` (associated flow)

## WebSocket Authentication

**Primary** (auth-message flow):
```json
→ {"type": "auth", "api_key": "your-key"}
← {"type": "auth_ok"}     // success
← {"type": "auth_failed"}  // failure → close(1008)
```

**Fallback** (query-param, disabled by default):
Set `SENTINEL_WS_QUERY_PARAM_AUTH=true` to enable.

> **WARNING**: Query-param auth exposes credentials in URLs, logs, and browser history.
> Use only when client constraints prevent message-based auth.

Credentials are:
- Never logged
- Never persisted
- Never included in event payloads
- Never in error messages
- Compared with `hmac.compare_digest()`

## Configuration

All settings via environment variables with `SENTINEL_` prefix:

| Variable | Default | Description |
|---|---|---|
| `SENTINEL_CAPTURE_INTERFACE` | `""` | Network interface for live capture |
| `SENTINEL_CAPTURE_FILTER` | `""` | BPF filter |
| `SENTINEL_CAPTURE_QUEUE_SIZE` | `10000` | Bounded capture queue |
| `SENTINEL_DETECTION_QUEUE_SIZE` | `5000` | Detection pipeline queue |
| `SENTINEL_EVENT_QUEUE_SIZE` | `1000` | Per-subscriber event queue |
| `SENTINEL_MAX_EVENTS` | `100000` | Max events in DB |
| `SENTINEL_RETENTION_HOURS` | `168` | Event retention (7 days) |
| `SENTINEL_WS_AUTH_TIMEOUT_SEC` | `10` | WebSocket auth timeout |
| `SENTINEL_WS_HEARTBEAT_INTERVAL_SEC` | `30` | Heartbeat interval |
| `SENTINEL_WS_QUERY_PARAM_AUTH` | `false` | Enable query-param auth |
| `SENTINEL_CORS_ORIGINS` | `""` | Comma-separated CORS origins |

## Capture Permissions

Live capture requires either:
1. Run as root (not recommended)
2. `CAP_NET_RAW` capability: `sudo setcap cap_net_raw=ep $(which python3)`
3. Add user to pcap group on macOS

PCAP replay requires no special permissions.

## Event Retention

Bounded storage with configurable limits:
- `max_events`: Maximum number of events retained
- `retention_hours`: Maximum age of events
- Cleanup runs periodically (configurable interval)
- Oldest events deleted first

## Error Handling

- API never exposes internal stack traces
- API never exposes secrets or configuration values
- Invalid requests return structured error responses
- Detection pipeline continues despite individual flow processing failures
- Capture continues despite parser errors
