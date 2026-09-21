# API Reference

## Authentication

All protected endpoints require the `X-API-Key` header:

```
X-API-Key: your-api-key-here
```

Set the API key via environment variable:
```bash
export SENTINEL_API_KEY="your-secret-key"
```

> **SECURITY**: The default key (`changeme-dev`) is for development only.
> Always set a strong, unique key in production.

Unauthorized requests return:
```json
HTTP 401
{"detail": "Unauthorized"}
```

---

## Public Endpoints

### GET /health

Liveness check. No authentication required.

**Response 200**:
```json
{"status": "healthy"}
```

### GET /readiness

Readiness check (verifies database connectivity). No authentication required.

**Response 200**:
```json
{"status": "ready"}
```

**Response 503**:
```json
{"status": "not_ready"}
```

---

## Protected Endpoints

### GET /api/v1/events

List detection events with optional filtering and pagination.

**Query Parameters**:
| Parameter | Type | Default | Constraints |
|---|---|---|---|
| `limit` | int | 50 | 1–200 |
| `offset` | int | 0 | ≥ 0 |
| `threat_type` | string | — | e.g., `ddos`, `c2`, `benign` |
| `severity` | string | — | e.g., `critical`, `high`, `medium`, `low`, `info` |
| `since` | float | — | Unix epoch timestamp |
| `flow_id` | string | — | Associated flow UUID |

**Response 200**:
```json
{
    "events": [
        {
            "id": "evt-abc123",
            "timestamp": 1693500000.0,
            "flow_id": "flow-def456",
            "severity": "high",
            "threat_type": "ddos",
            "anomaly_score": 0.87,
            "model_version": "1.0",
            "feature_schema_version": "2.0.0",
            "rationale": "Anomalous traffic pattern...",
            "metadata": "{}",
            "created_at": 1693500001.0
        }
    ],
    "total": 42,
    "limit": 50,
    "offset": 0
}
```

### GET /api/v1/events/{event_id}

Retrieve a specific event by its ID.

**Response 200**: Single event object.
**Response 404**: `{"detail": "Event not found"}`

### GET /api/v1/flows

List observed network flows.

**Query Parameters**:
| Parameter | Type | Default | Constraints |
|---|---|---|---|
| `limit` | int | 50 | 1–200 |
| `offset` | int | 0 | ≥ 0 |
| `since` | float | — | Unix epoch timestamp |

**Response 200**:
```json
{
    "flows": [
        {
            "id": "flow-abc123",
            "flow_key": "10.0.0.1:1234->10.0.0.2:80/TCP",
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "src_port": 1234,
            "dst_port": 80,
            "protocol": 6,
            "direction": "forward",
            "packet_count": 42,
            "byte_count": 12500,
            "duration_sec": 2.5
        }
    ],
    "limit": 50,
    "offset": 0
}
```

### GET /api/v1/flows/{flow_id}

Retrieve a specific flow. Returns 404 if not found.

### GET /api/v1/stats

Aggregate detection statistics.

**Response 200**:
```json
{
    "threat_types": {"ddos": 5, "benign": 100, "c2": 2},
    "severities": {"high": 3, "medium": 4, "info": 100},
    "total_events": 107
}
```

### GET /api/v1/status

Sensor operational status.

**Response 200**:
```json
{
    "sensor_state": "running",
    "metrics": {
        "packets_observed": 50000,
        "packets_parsed": 49800,
        "packets_malformed": 200,
        "flows_active": 150,
        "detections_generated": 42
    },
    "uptime_sec": 3600.5,
    "feature_schema_version": "2.0.0",
    "feature_count": 52,
    "websocket_subscribers": 2
}
```

---

## WebSocket

### WS /api/v1/ws/events

Real-time detection event stream. Requires authentication via first message.

**Authentication Flow**:
```
Client → Server:  {"type": "auth", "api_key": "your-key"}
Server → Client:  {"type": "auth_ok"}  // or {"type": "auth_failed"}
```

**Event Messages**:
```json
{"type": "event", "data": {"id": "evt-123", "severity": "high", ...}}
```

**Heartbeat**:
```json
{"type": "ping"}
```

**Connection codes**:
- `1008`: Authentication failed
- `1011`: Internal error (EventBus unavailable)
