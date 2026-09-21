"""
Domain data models for EIDOLON // SENTINEL-NET.

Provides the complete typed data model hierarchy:
RawPacket -> ParsedPacket -> ObservedFlow -> FeatureVector -> AnomalyResult
-> ThreatClassification -> DetectionEvent
"""

from sentinel_net.models.enums import Direction, Protocol, Severity, ThreatType
from sentinel_net.models.types import (
    TCP_ACK,
    TCP_CWR,
    TCP_ECE,
    TCP_FIN,
    TCP_PSH,
    TCP_RST,
    TCP_SYN,
    TCP_URG,
    AnomalyResult,
    DetectionEvent,
    FeatureVector,
    FlowKey,
    ObservedFlow,
    ParsedPacket,
    RawPacket,
    ThreatClassification,
)

__all__ = [
    "RawPacket",
    "ParsedPacket",
    "FlowKey",
    "ObservedFlow",
    "FeatureVector",
    "AnomalyResult",
    "ThreatClassification",
    "DetectionEvent",
    "Severity",
    "ThreatType",
    "Direction",
    "Protocol",
]
