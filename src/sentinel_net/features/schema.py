"""
Feature schema for EIDOLON // SENTINEL-NET.

Defines the canonical, deterministically-ordered feature names that make up
a FeatureVector. This schema is the contract between the feature extractor
and any future ML model: models consume FeatureVector.values in this order
without needing to know how features were extracted.

All feature names are lowercase with underscores. The ordering is stable
across versions — new features are appended, never inserted.
"""

# ─── Canonical Feature Schema ─────────────────────────────────────────
# Order matters. Do NOT reorder existing features.
# Append new features at the end to maintain backward compatibility.

FEATURE_SCHEMA: tuple[str, ...] = (
    # ── Basic flow metrics ──
    "duration_sec",
    "total_packets",
    "total_bytes",
    "packets_per_sec",
    "bytes_per_sec",
    # ── Directional counters ──
    "forward_packets",
    "reverse_packets",
    "forward_bytes",
    "reverse_bytes",
    "fwd_rev_packet_ratio",
    "fwd_rev_byte_ratio",
    # ── Packet size statistics ──
    "pkt_size_mean",
    "pkt_size_std",
    "pkt_size_min",
    "pkt_size_max",
    "pkt_size_median",
    "pkt_size_p25",
    "pkt_size_p75",
    "pkt_size_p90",
    # ── Inter-arrival time statistics ──
    "iat_mean",
    "iat_std",
    "iat_min",
    "iat_max",
    "iat_median",
    # ── Forward IAT ──
    "fwd_iat_mean",
    "fwd_iat_std",
    "fwd_iat_min",
    "fwd_iat_max",
    # ── Reverse IAT ──
    "rev_iat_mean",
    "rev_iat_std",
    "rev_iat_min",
    "rev_iat_max",
    # ── TCP flags ──
    "syn_count",
    "syn_ack_count",
    "ack_count",
    "fin_count",
    "rst_count",
    "psh_count",
    "syn_ratio",
    "ack_ratio",
    "fin_ratio",
    "rst_ratio",
    "psh_ratio",
    # ── Protocol ──
    "protocol",
    "ip_version",
    "is_tcp",
    "is_udp",
    "is_icmp",
    # ── Payload ──
    "payload_bytes_total",
    "forward_payload_bytes",
    "reverse_payload_bytes",
    "payload_ratio",
)

FEATURE_COUNT: int = len(FEATURE_SCHEMA)
FEATURE_NAME_SET: frozenset[str] = frozenset(FEATURE_SCHEMA)
FEATURE_SCHEMA_VERSION: str = "2.0.0"
