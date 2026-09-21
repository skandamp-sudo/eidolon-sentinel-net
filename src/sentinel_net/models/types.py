"""
Domain data models for EIDOLON // SENTINEL-NET.

Provides the complete typed data model hierarchy:
RawPacket → ParsedPacket → ObservedFlow → FeatureVector → AnomalyResult
→ ThreatClassification → DetectionEvent

All types are pure Python dataclasses with full type annotations.
No database ORM or SQLAlchemy types are used here.
"""

from dataclasses import dataclass, field
from typing import Any
from uuid import uuid4


# ─── TCP Flag Constants ───────────────────────────────────────────────
TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10
TCP_URG = 0x20
TCP_ECE = 0x40
TCP_CWR = 0x80


@dataclass
class RawPacket:
    """Raw bytes and metadata from PCAP capture."""

    timestamp: float
    raw_bytes: bytes
    wire_length: int
    capture_length: int
    interface: str = "pcap"


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
    """Hashable 5-tuple key identifying a network flow.

    Supports IPv4 and IPv6 addresses. For protocols without ports
    (e.g., ICMP), src_port and dst_port are None.
    """

    src_ip: str
    dst_ip: str
    src_port: int | None
    dst_port: int | None
    protocol: int

    @property
    def direction_key(self) -> str:
        """Canonical sorted key for bidirectional matching.

        Returns the same string regardless of which endpoint is src/dst,
        allowing forward and reverse packets to map to the same conversation.
        """
        endpoints = sorted([
            (self.src_ip, self.src_port if self.src_port is not None else -1),
            (self.dst_ip, self.dst_port if self.dst_port is not None else -1),
        ])
        return (
            f"{endpoints[0][0]}:{endpoints[0][1]}-"
            f"{endpoints[1][0]}:{endpoints[1][1]}-{self.protocol}"
        )

    @property
    def unidirectional_key(self) -> str:
        """Exact directional key preserving src→dst ordering."""
        return f"{self.src_ip}:{self.src_port}-{self.dst_ip}:{self.dst_port}-{self.protocol}"


@dataclass
class ObservedFlow:
    """Aggregated flow record representing an observed network conversation.

    Represents traffic ACTUALLY OBSERVED by the sensor. If only one
    direction is captured, the other direction's counters remain at zero.
    Does NOT fabricate or infer unseen reverse-direction traffic.

    The 'initiator' (forward direction) is defined as the source of the
    first packet seen for this flow.
    """

    flow_key: FlowKey
    direction: str  # 'forward', 'reverse', or 'unknown'
    start_time: float
    end_time: float
    duration_sec: float
    packet_count: int
    byte_count: int
    payload_byte_count: int
    packets: list[ParsedPacket] = field(default_factory=list)
    tcp_flag_counts: dict[str, int] = field(default_factory=dict)
    is_complete: bool = False

    # ── Phase 2 directional counters ──
    forward_packet_count: int = 0
    reverse_packet_count: int = 0
    forward_bytes: int = 0
    reverse_bytes: int = 0
    forward_payload_bytes: int = 0
    reverse_payload_bytes: int = 0

    # ── Phase 2 TCP flag counters (from bitmask) ──
    syn_count: int = 0
    syn_ack_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    psh_count: int = 0

    # ── Phase 2 timing ──
    forward_iats: list[float] = field(default_factory=list)
    reverse_iats: list[float] = field(default_factory=list)
    packet_sizes: list[int] = field(default_factory=list)

    # ── Initiator identification ──
    initiator_ip: str = ""
    initiator_port: int | None = None
    id: str = field(default_factory=lambda: str(uuid4()))

    @property
    def total_packets(self) -> int:
        """Total packets observed in both directions."""
        return self.forward_packet_count + self.reverse_packet_count

    @property
    def total_bytes(self) -> int:
        """Total bytes observed in both directions."""
        return self.forward_bytes + self.reverse_bytes


@dataclass
class FeatureVector:
    """Computed statistical features from an ObservedFlow.

    Provides a stable, deterministically-ordered feature set suitable
    for future ML model consumption. Features are stored as both a
    name→value dict and ordered lists for numpy conversion.
    """

    flow_key: FlowKey
    timestamp: float
    features: dict[str, float] = field(default_factory=dict)
    feature_names: list[str] = field(default_factory=list)
    values: list[float] = field(default_factory=list)

    def to_numpy_array(self) -> "numpy.ndarray":
        """Convert feature values to a numpy array.

        Returns:
            1-D numpy array of feature values in canonical order.
        """
        import numpy as np

        return np.array(self.values, dtype=np.float64)

    def validate(self) -> bool:
        """Validate internal consistency.

        Returns:
            True if feature_names and values are consistent with features dict.
        """
        if len(self.feature_names) != len(self.values):
            return False
        if len(self.features) != len(self.feature_names):
            return False
        for name, val in zip(self.feature_names, self.values):
            if name not in self.features:
                return False
            if self.features[name] != val:
                return False
        return True


@dataclass
class AnomalyResult:
    """Phase 3 — output from unsupervised anomaly detection."""

    flow_key: FlowKey
    timestamp: float
    anomaly_score: float
    is_anomalous: bool
    model_name: str
    model_version: str


@dataclass
class ThreatClassification:
    """Phase 3 — output from supervised threat classifier."""

    flow_key: FlowKey
    timestamp: float
    threat_type: str
    confidence: float
    model_name: str
    model_version: str


@dataclass
class DetectionEvent:
    """Complete event record for storage/API."""

    id: str
    timestamp: float
    flow_key: FlowKey
    observed_flow: ObservedFlow | None
    feature_vector: FeatureVector | None = None
    anomaly_result: AnomalyResult | None = None
    threat_classification: ThreatClassification | None = None
    severity: str = "info"
    rationale: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    flow_id: str | None = None

    def __post_init__(self) -> None:
        if self.observed_flow is not None:
            if self.flow_id is not None and self.flow_id != self.observed_flow.id:
                raise ValueError('Event flow_id must match observed flow')
            self.flow_id = self.observed_flow.id

    def to_dict(self) -> dict[str, Any]:
        """Serialize the same flat record for every delivery path; never packet bytes."""
        from sentinel_net.models.event_record import EventRecord, metadata_evidence

        tc, ar = self.threat_classification, self.anomaly_result
        explanation = self.metadata.get('explanation', {})
        if not isinstance(explanation, dict):
            explanation = {}
        data = {
            'event_schema_version': '2.0.0',
            'id': self.id, 'event_id': self.id, 'timestamp': self.timestamp,
            'created_at': self.timestamp, 'flow_id': self.flow_id,
            'severity': self.severity, 'threat_type': tc.threat_type if tc else 'unknown',
            'classification_score': tc.confidence if tc else None,
            'classification_score_type': 'uncalibrated_classifier_score' if tc else None,
            'classification_score_class': self.metadata.get('classification_score_class', tc.threat_type if tc else None),
            'anomaly_score': ar.anomaly_score if ar else None,
            'anomaly_score_type': 'normalized_anomaly_score' if ar else None,
            'detection_source': (['ml_classifier'] if tc else []) + (['anomaly_detector'] if ar else []),
            'model_version': tc.model_version if tc else (ar.model_version if ar else None),
            'anomaly_model_version': ar.model_version if ar else None,
            'feature_schema_version': self.metadata.get('feature_schema_version'),
            'explanation_version': explanation.get('explanation_version', self.metadata.get('explanation_version')),
            'rationale': self.rationale, 'metadata': self.metadata,
            'src_ip': self.flow_key.src_ip, 'dst_ip': self.flow_key.dst_ip,
            'src_port': self.flow_key.src_port, 'dst_port': self.flow_key.dst_port,
            'protocol': self.flow_key.protocol,
        }
        data['evidence'] = metadata_evidence(self.metadata)
        return EventRecord.model_validate(data).model_dump(mode='json')
