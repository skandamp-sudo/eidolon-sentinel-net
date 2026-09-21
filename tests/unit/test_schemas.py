import pytest
from pydantic import ValidationError
from sentinel_net.api.schemas import (
    EventResponse, EventListResponse, FlowResponse, FlowListResponse,
    StatsResponse, StatusResponse, HealthResponse, EvidenceItemResponse,
    ATTACKMappingResponse, WebSocketEventMessage
)

def test_event_response_schema():
    data = {
        "id": "event-123",
        "timestamp": 123456789.0,
        "severity": "high",
        "created_at": 123456789.0,
        "metadata": {"some_key": "some_value"}
    }
    event = EventResponse(**data)
    assert event.id == "event-123"
    assert event.metadata == {"some_key": "some_value"}

def test_event_response_schema_enriched():
    data = {
        "id": "event-123",
        "timestamp": 123456789.0,
        "severity": "high",
        "created_at": 123456789.0,
        "metadata": {"some_key": "some_value", "explanation": "test"},
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "protocol": 6
    }
    event = EventResponse(**data)
    assert event.src_ip == "10.0.0.1"
    assert event.metadata["explanation"] == "test"

def test_flow_list_response():
    data = {
        "flows": [
            {
                "id": "flow-123",
                "flow_key": "10.0.0.1:1234-10.0.0.2:80-6",
                "src_ip": "10.0.0.1",
                "dst_ip": "10.0.0.2",
                "src_port": 1234,
                "dst_port": 80,
                "protocol": 6,
                "direction": "forward",
                "start_time": 123.0,
                "end_time": 124.0,
                "duration_sec": 1.0,
                "packet_count": 10,
                "byte_count": 1000,
                "payload_byte_count": 800,
                "created_at": 125.0
            }
        ],
        "total": 100,
        "limit": 50,
        "offset": 0
    }
    resp = FlowListResponse(**data)
    assert resp.total == 100
    assert len(resp.flows) == 1
    assert resp.flows[0].src_ip == "10.0.0.1"

def test_status_response_schema():
    data = {
        "sensor_state": "running",
        "metrics": {"packets": 10},
        "uptime_sec": 60.0,
        "feature_schema_version": "2.0.0",
        "feature_count": 52,
        "websocket_subscribers": 1
    }
    status = StatusResponse(**data)
    assert status.feature_count == 52

def test_evidence_item_response_schema():
    data = {
        "feature_name": "fwd_pkts",
        "observed_value": 10.0,
        "reference_value": 2.0,
        "contribution": 0.5,
        "direction": "higher",
        "evidence_type": "shap",
        "source": "model",
        "model_name": "rf",
        "model_version": "1.0",
        "feature_schema_version": "2.0.0"
    }
    item = EvidenceItemResponse(**data)
    assert item.contribution == 0.5

def test_attack_mapping_response_schema():
    data = {
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "rationale": "High traffic on unknown port",
        "applicability": "high",
        "qualification": "Likely"
    }
    mapping = ATTACKMappingResponse(**data)
    assert mapping.technique_id == "T1071"

def test_websocket_event_message_schema():
    data = {
        "type": "event",
        "data": {"id": "123"}
    }
    msg = WebSocketEventMessage(**data)
    assert msg.type == "event"
