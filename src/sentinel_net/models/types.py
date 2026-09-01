from dataclasses import dataclass, field
from typing import Any

@dataclass
class RawPacket:
    """Raw bytes and metadata from PCAP capture."""
    timestamp: float
    raw_bytes: bytes
    wire_length: int
    capture_length: int
    interface: str = 'pcap'

@dataclass
class ParsedPacket:
    """Structured fields extracted from raw packet."""
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int | None
    dst_port: int | None
    protocol: int
    protocol_name: str
    ip_version: int
    ttl: int
    ip_total_length: int
    tcp_flags: int | None
    tcp_window: int | None
    tcp_seq: int | None
    tcp_ack_num: int | None
    payload_size: int
    payload_entropy: float
    raw_packet: RawPacket | None = None

@dataclass(frozen=True)
class FlowKey:
    """Hashable key identifying a flow."""
    src_ip: str
    dst_ip: str
    src_port: int | None
    dst_port: int | None
    protocol: int

    @property
    def direction_key(self) -> str:
        """Canonical sorted key for bidirectional matching."""
        endpoints = sorted([
            (self.src_ip, self.src_port if self.src_port is not None else -1),
            (self.dst_ip, self.dst_port if self.dst_port is not None else -1)
        ])
        return f"{endpoints[0][0]}:{endpoints[0][1]}-{endpoints[1][0]}:{endpoints[1][1]}-{self.protocol}"

    @property
    def unidirectional_key(self) -> str:
        """Exact directional key."""
        return f"{self.src_ip}:{self.src_port}-{self.dst_ip}:{self.dst_port}-{self.protocol}"

@dataclass
class ObservedFlow:
    """
    Represents a SINGLE OBSERVED DIRECTION of a flow. Does NOT infer reverse traffic.
    """
    flow_key: FlowKey
    direction: str
    start_time: float
    end_time: float
    duration_sec: float
    packet_count: int
    byte_count: int
    payload_byte_count: int
    packets: list[ParsedPacket] = field(default_factory=list)
    tcp_flag_counts: dict[str, int] = field(default_factory=dict)
    is_complete: bool = False

@dataclass
class FeatureVector:
    """Phase 2 — computed statistical features from an ObservedFlow"""
    flow_key: FlowKey
    timestamp: float
    features: dict[str, float]
    feature_names: list[str]
    values: list[float]

@dataclass
class AnomalyResult:
    """Phase 3 — output from unsupervised anomaly detection"""
    flow_key: FlowKey
    timestamp: float
    anomaly_score: float
    is_anomalous: bool
    model_name: str
    model_version: str

@dataclass
class ThreatClassification:
    """Phase 3 — output from supervised threat classifier"""
    flow_key: FlowKey
    timestamp: float
    threat_type: str
    confidence: float
    model_name: str
    model_version: str

@dataclass
class DetectionEvent:
    """Complete event record for storage/API"""
    id: str
    timestamp: float
    flow_key: FlowKey
    observed_flow: ObservedFlow
    feature_vector: FeatureVector | None = None
    anomaly_result: AnomalyResult | None = None
    threat_classification: ThreatClassification | None = None
    severity: str = 'info'
    rationale: str = ''
    metadata: dict[str, Any] = field(default_factory=dict)
