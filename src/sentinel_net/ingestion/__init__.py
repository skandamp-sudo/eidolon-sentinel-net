"""
Ingestion layer for EIDOLON // SENTINEL-NET.
"""

from sentinel_net.ingestion.parser import parse_packet, compute_entropy
from sentinel_net.ingestion.replay import PcapReplay, PcapReplayConfig

__all__ = [
    "parse_packet",
    "compute_entropy",
    "PcapReplay",
    "PcapReplayConfig",
]
