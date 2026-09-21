from typing import Any

from pydantic import BaseModel, Field

class StatusResponse(BaseModel):
    sensor_state: str
    metrics: dict[str, Any]
    uptime_sec: float
    feature_schema_version: str
    feature_count: int
    websocket_subscribers: int
    model_identity: dict[str, str] | None = None
    capture_interface: str | None = None
    sensor_mode: str = 'standby'
    operational_health: dict[str, Any] = Field(default_factory=dict)

class HealthResponse(BaseModel):
    status: str
    version: str
    timestamp: str
    sensor: dict[str, Any] | None = None

from sentinel_net.models.event_record import EventRecord

EventResponse = EventRecord

class EventListResponse(BaseModel):
    events: list[EventResponse]
    total: int
    limit: int
    offset: int

class FlowResponse(BaseModel):
    id: str
    flow_key: str
    src_ip: str
    dst_ip: str
    src_port: int | None = None
    dst_port: int | None = None
    protocol: int
    direction: str
    start_time: float
    end_time: float
    duration_sec: float
    packet_count: int
    byte_count: int
    payload_byte_count: int
    created_at: float

    model_config = {"extra": "allow"}

class FlowListResponse(BaseModel):
    flows: list[FlowResponse]
    total: int
    limit: int
    offset: int

class StatsResponse(BaseModel):
    threat_types: dict[str, int]
    severities: dict[str, int]
    total_events: int

class EvidenceItemResponse(BaseModel):
    feature_name: str
    observed_value: float
    reference_value: float | None
    contribution: float
    direction: str
    evidence_type: str
    source: str
    model_name: str
    model_version: str
    feature_schema_version: str

class ATTACKMappingResponse(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str
    rationale: str
    applicability: str
    qualification: str

class WebSocketEventMessage(BaseModel):
    type: str
    data: dict[str, Any]
