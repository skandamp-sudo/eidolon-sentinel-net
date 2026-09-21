"""
Feature extraction engine for EIDOLON // SENTINEL-NET.

Converts ObservedFlow records into FeatureVector records using the
canonical feature schema. All features are numeric (float64) and
computed from observable metadata — packet sizes, timing, protocol,
TCP flags, directionality.

SECURITY: This module performs NO network I/O. It is a pure computation
engine. No traffic is decrypted — encrypted payloads are treated as
opaque and only metadata features (sizes, timing, flags) are used.
"""

import logging
import math
from typing import Sequence

import numpy as np

from sentinel_net.features.schema import FEATURE_COUNT, FEATURE_SCHEMA
from sentinel_net.models.types import FeatureVector, ObservedFlow

logger = logging.getLogger(__name__)


def _safe_ratio(numerator: float, denominator: float) -> float:
    """Compute ratio, returning 0.0 when denominator is zero."""
    if denominator == 0.0:
        return 0.0
    return numerator / denominator


def _stats(values: Sequence[float | int]) -> dict[str, float]:
    """Compute descriptive statistics for a sequence of numeric values.

    Returns dict with keys: mean, std, min, max, median, p25, p75, p90.
    Returns all zeros for empty input.
    """
    if not values:
        return {
            "mean": 0.0,
            "std": 0.0,
            "min": 0.0,
            "max": 0.0,
            "median": 0.0,
            "p25": 0.0,
            "p75": 0.0,
            "p90": 0.0,
        }
    arr = np.array(values, dtype=np.float64)
    return {
        "mean": float(np.mean(arr)),
        "std": float(np.std(arr, ddof=0)),
        "min": float(np.min(arr)),
        "max": float(np.max(arr)),
        "median": float(np.median(arr)),
        "p25": float(np.percentile(arr, 25)),
        "p75": float(np.percentile(arr, 75)),
        "p90": float(np.percentile(arr, 90)),
    }


def _iat_stats(iats: list[float]) -> dict[str, float]:
    """Compute inter-arrival time statistics.

    Returns dict with keys: mean, std, min, max.
    Returns all zeros for empty input.
    """
    if not iats:
        return {"mean": 0.0, "std": 0.0, "min": 0.0, "max": 0.0}
    arr = np.array(iats, dtype=np.float64)
    return {
        "mean": float(np.mean(arr)),
        "std": float(np.std(arr, ddof=0)),
        "min": float(np.min(arr)),
        "max": float(np.max(arr)),
    }


def _compute_all_iats(flow: ObservedFlow) -> list[float]:
    """Compute IATs from all packet timestamps (forward + reverse merged)."""
    all_ts = sorted(flow.forward_iats + flow.reverse_iats)
    # forward_iats and reverse_iats are already IATs, not timestamps.
    # We need to merge the original timestamps. Since we don't store them,
    # we merge the per-direction IATs into a combined list for global stats.
    # This is an approximation — true global IATs would need merged timestamps.
    return flow.forward_iats + flow.reverse_iats


class FeatureExtractor:
    """Extracts a canonical FeatureVector from an ObservedFlow.

    Features are computed from observable network metadata:
    - Flow duration, packet counts, byte counts
    - Directional ratios (forward vs reverse)
    - Packet size statistics (mean, std, min, max, percentiles)
    - Inter-arrival time statistics
    - TCP flag counts and ratios
    - Protocol identification
    - Payload byte counts

    Encrypted payload content is NEVER examined. Payload entropy features
    are intentionally omitted to avoid creating misleading features for
    encrypted traffic where the payload is opaque.

    SECURITY: No network I/O. No traffic decryption. No key material.
    """

    def extract(self, flow: ObservedFlow) -> FeatureVector:
        """Extract features from a single ObservedFlow.

        Args:
            flow: The aggregated flow record to extract features from.

        Returns:
            A FeatureVector with features in canonical schema order.
        """
        features: dict[str, float] = {}

        # ── Basic flow metrics ──
        duration = flow.duration_sec
        total_pkts = float(flow.packet_count)
        total_bytes = float(flow.byte_count)

        features["duration_sec"] = duration
        features["total_packets"] = total_pkts
        features["total_bytes"] = total_bytes
        features["packets_per_sec"] = _safe_ratio(total_pkts, duration)
        features["bytes_per_sec"] = _safe_ratio(total_bytes, duration)

        # ── Directional counters ──
        fwd_pkts = float(flow.forward_packet_count)
        rev_pkts = float(flow.reverse_packet_count)
        fwd_bytes = float(flow.forward_bytes)
        rev_bytes = float(flow.reverse_bytes)

        features["forward_packets"] = fwd_pkts
        features["reverse_packets"] = rev_pkts
        features["forward_bytes"] = fwd_bytes
        features["reverse_bytes"] = rev_bytes
        features["fwd_rev_packet_ratio"] = _safe_ratio(fwd_pkts, rev_pkts)
        features["fwd_rev_byte_ratio"] = _safe_ratio(fwd_bytes, rev_bytes)

        # ── Packet size statistics ──
        pkt_stats = _stats(flow.packet_sizes)
        features["pkt_size_mean"] = pkt_stats["mean"]
        features["pkt_size_std"] = pkt_stats["std"]
        features["pkt_size_min"] = pkt_stats["min"]
        features["pkt_size_max"] = pkt_stats["max"]
        features["pkt_size_median"] = pkt_stats["median"]
        features["pkt_size_p25"] = pkt_stats["p25"]
        features["pkt_size_p75"] = pkt_stats["p75"]
        features["pkt_size_p90"] = pkt_stats["p90"]

        # ── Inter-arrival time statistics (all directions merged) ──
        all_iats = _compute_all_iats(flow)
        iat_s = _iat_stats(all_iats)
        features["iat_mean"] = iat_s["mean"]
        features["iat_std"] = iat_s["std"]
        features["iat_min"] = iat_s["min"]
        features["iat_max"] = iat_s["max"]
        features["iat_median"] = float(np.median(all_iats)) if all_iats else 0.0

        # ── Forward IAT ──
        fwd_iat_s = _iat_stats(flow.forward_iats)
        features["fwd_iat_mean"] = fwd_iat_s["mean"]
        features["fwd_iat_std"] = fwd_iat_s["std"]
        features["fwd_iat_min"] = fwd_iat_s["min"]
        features["fwd_iat_max"] = fwd_iat_s["max"]

        # ── Reverse IAT ──
        rev_iat_s = _iat_stats(flow.reverse_iats)
        features["rev_iat_mean"] = rev_iat_s["mean"]
        features["rev_iat_std"] = rev_iat_s["std"]
        features["rev_iat_min"] = rev_iat_s["min"]
        features["rev_iat_max"] = rev_iat_s["max"]

        # ── TCP flags ──
        features["syn_count"] = float(flow.syn_count)
        features["syn_ack_count"] = float(flow.syn_ack_count)
        features["ack_count"] = float(flow.ack_count)
        features["fin_count"] = float(flow.fin_count)
        features["rst_count"] = float(flow.rst_count)
        features["psh_count"] = float(flow.psh_count)

        # Flag ratios (relative to total packets)
        features["syn_ratio"] = _safe_ratio(float(flow.syn_count), total_pkts)
        features["ack_ratio"] = _safe_ratio(float(flow.ack_count), total_pkts)
        features["fin_ratio"] = _safe_ratio(float(flow.fin_count), total_pkts)
        features["rst_ratio"] = _safe_ratio(float(flow.rst_count), total_pkts)
        features["psh_ratio"] = _safe_ratio(float(flow.psh_count), total_pkts)

        # ── Protocol ──
        features["protocol"] = float(flow.flow_key.protocol)
        # Determine IP version from initiator IP
        ip_ver = 6.0 if ":" in flow.initiator_ip else 4.0
        features["ip_version"] = ip_ver
        features["is_tcp"] = 1.0 if flow.flow_key.protocol == 6 else 0.0
        features["is_udp"] = 1.0 if flow.flow_key.protocol == 17 else 0.0
        features["is_icmp"] = 1.0 if flow.flow_key.protocol in (1, 58) else 0.0

        # ── Payload ──
        features["payload_bytes_total"] = float(flow.payload_byte_count)
        features["forward_payload_bytes"] = float(flow.forward_payload_bytes)
        features["reverse_payload_bytes"] = float(flow.reverse_payload_bytes)
        features["payload_ratio"] = _safe_ratio(
            float(flow.payload_byte_count), total_bytes
        )

        # ── Build ordered values list from schema ──
        values = [features.get(name, 0.0) for name in FEATURE_SCHEMA]
        feature_names = list(FEATURE_SCHEMA)

        return FeatureVector(
            flow_key=flow.flow_key,
            timestamp=flow.start_time,
            features=features,
            feature_names=feature_names,
            values=values,
        )

    def extract_batch(self, flows: list[ObservedFlow]) -> list[FeatureVector]:
        """Extract features from multiple flows.

        Args:
            flows: List of ObservedFlow records.

        Returns:
            List of FeatureVector records in the same order.
        """
        return [self.extract(flow) for flow in flows]
