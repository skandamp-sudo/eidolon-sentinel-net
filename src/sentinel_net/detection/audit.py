"""
Feature audit for EIDOLON // SENTINEL-NET.

Classifies every feature in the canonical 52-feature schema for ML suitability.
This module is the authoritative reference for feature safety, redundancy, and
model-type compatibility.

SECURITY: All 52 features are derived from observable network metadata
(packet sizes, timing, flags, protocol identifiers). None inspect payload
content, decrypt traffic, or require cryptographic keys.
"""

from sentinel_net.features.schema import FEATURE_SCHEMA, FEATURE_COUNT

# ─── Feature Classification ──────────────────────────────────────────

# Nominal features: integer-coded categories, not meaningful as continuous values.
# Tree models handle these natively; linear models misinterpret ordinal distances.
NOMINAL_FEATURES: tuple[str, ...] = ("protocol", "ip_version")

# Redundant features: linear dependencies between feature groups.
# Tree models tolerate redundancy; linear models may exhibit multicollinearity.
# Documented for awareness — NOT excluded from tree models.
REDUNDANT_FEATURES: tuple[str, ...] = (
    "total_packets",       # = forward_packets + reverse_packets
    "total_bytes",         # = forward_bytes + reverse_bytes
    "payload_bytes_total", # = forward_payload_bytes + reverse_payload_bytes
    "protocol",            # overlaps with is_tcp, is_udp, is_icmp
)

# All 52 features are safe for ML (metadata only, no payload inspection)
ML_SAFE_FEATURES: tuple[str, ...] = tuple(FEATURE_SCHEMA)

# Features suitable for tree-based models (all 52)
TREE_MODEL_FEATURES: tuple[str, ...] = ML_SAFE_FEATURES

# Features suitable for linear models (52 - 2 nominal = 50)
LINEAR_MODEL_FEATURES: tuple[str, ...] = tuple(
    f for f in ML_SAFE_FEATURES if f not in NOMINAL_FEATURES
)

# ─── Per-Feature Audit ────────────────────────────────────────────────

_CAVEAT_FEATURES = {
    "fwd_rev_packet_ratio": (
        "caveat",
        "Returns 0.0 when reverse_packets=0 (not inf). Conflates 'no reverse "
        "traffic' with 'equal ratio'. Tree models handle this; linear models may not."
    ),
    "fwd_rev_byte_ratio": (
        "caveat",
        "Returns 0.0 when reverse_bytes=0. Same concern as fwd_rev_packet_ratio."
    ),
    "protocol": (
        "caveat",
        "Nominal integer (6/17/1/58). Tree models handle natively; excluded from "
        "linear models. Redundant with is_tcp/is_udp/is_icmp."
    ),
    "ip_version": (
        "caveat",
        "Nominal integer (4 or 6). Excluded from linear models."
    ),
}

_PAYLOAD_FEATURES = {
    "payload_bytes_total",
    "forward_payload_bytes",
    "reverse_payload_bytes",
    "payload_ratio",
}

FEATURE_AUDIT: dict[str, dict[str, str]] = {}
for _fname in FEATURE_SCHEMA:
    if _fname in _CAVEAT_FEATURES:
        _status, _notes = _CAVEAT_FEATURES[_fname]
    elif _fname in _PAYLOAD_FEATURES:
        _status = "safe"
        _notes = (
            "Metadata only — byte counts, NOT payload content inspection. "
            "No TLS/QUIC decryption. No cryptographic keys."
        )
    else:
        _status = "safe"
        _notes = "Safe metadata feature derived from observable network telemetry."

    # Determine category
    if _fname.startswith(("pkt_size_",)):
        _cat = "packet_size_stats"
    elif _fname.startswith(("iat_", "fwd_iat_", "rev_iat_")):
        _cat = "inter_arrival_time"
    elif _fname.startswith(("syn_", "ack_", "fin_", "rst_", "psh_")):
        _cat = "tcp_flags"
    elif _fname in ("protocol", "ip_version", "is_tcp", "is_udp", "is_icmp"):
        _cat = "protocol"
    elif _fname in _PAYLOAD_FEATURES:
        _cat = "payload_metadata"
    elif _fname.startswith(("forward_", "reverse_", "fwd_rev_")):
        _cat = "directional"
    else:
        _cat = "basic"

    FEATURE_AUDIT[_fname] = {
        "status": _status,
        "category": _cat,
        "notes": _notes,
    }


def verify_feature_audit() -> None:
    """Verify that the audit covers all canonical features exactly.

    Raises AssertionError if the audit is incomplete or mismatched.
    """
    assert len(ML_SAFE_FEATURES) == FEATURE_COUNT, (
        f"ML_SAFE_FEATURES has {len(ML_SAFE_FEATURES)} entries but "
        f"FEATURE_COUNT is {FEATURE_COUNT}"
    )
    assert len(FEATURE_AUDIT) == FEATURE_COUNT, (
        f"FEATURE_AUDIT has {len(FEATURE_AUDIT)} entries but "
        f"FEATURE_COUNT is {FEATURE_COUNT}"
    )
    schema_set = set(FEATURE_SCHEMA)
    for name in ML_SAFE_FEATURES:
        assert name in schema_set, f"Feature '{name}' not in FEATURE_SCHEMA"
    for name in FEATURE_AUDIT:
        assert name in schema_set, f"Audited feature '{name}' not in FEATURE_SCHEMA"
    assert len(LINEAR_MODEL_FEATURES) == FEATURE_COUNT - len(NOMINAL_FEATURES), (
        f"LINEAR_MODEL_FEATURES should have {FEATURE_COUNT - len(NOMINAL_FEATURES)} "
        f"features but has {len(LINEAR_MODEL_FEATURES)}"
    )
