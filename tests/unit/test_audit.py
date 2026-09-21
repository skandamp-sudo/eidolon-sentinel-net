"""Tests for the feature audit module."""

import pytest

from sentinel_net.detection.audit import (
    FEATURE_AUDIT,
    LINEAR_MODEL_FEATURES,
    ML_SAFE_FEATURES,
    NOMINAL_FEATURES,
    REDUNDANT_FEATURES,
    TREE_MODEL_FEATURES,
    verify_feature_audit,
)
from sentinel_net.features.schema import FEATURE_COUNT, FEATURE_SCHEMA


class TestFeatureAudit:
    """Test feature audit constants and verification."""

    def test_verify_feature_audit_passes(self):
        """Audit verification must pass with no assertion errors."""
        verify_feature_audit()

    def test_ml_safe_features_count_matches_schema(self):
        """ML_SAFE_FEATURES must have exactly FEATURE_COUNT entries."""
        assert len(ML_SAFE_FEATURES) == FEATURE_COUNT

    def test_feature_count_is_52(self):
        """Canonical feature count is 52."""
        assert FEATURE_COUNT == 52

    def test_feature_schema_length_matches_count(self):
        """len(FEATURE_SCHEMA) == FEATURE_COUNT."""
        assert len(FEATURE_SCHEMA) == FEATURE_COUNT

    def test_all_features_unique(self):
        """No duplicate feature names."""
        assert len(set(FEATURE_SCHEMA)) == FEATURE_COUNT

    def test_ml_safe_features_matches_schema(self):
        """ML_SAFE_FEATURES must contain exactly the same names as FEATURE_SCHEMA."""
        assert set(ML_SAFE_FEATURES) == set(FEATURE_SCHEMA)

    def test_tree_model_features_is_all_52(self):
        """Tree models use all 52 features."""
        assert TREE_MODEL_FEATURES == ML_SAFE_FEATURES
        assert len(TREE_MODEL_FEATURES) == 52

    def test_linear_model_features_excludes_nominal(self):
        """Linear models exclude nominal features."""
        assert len(LINEAR_MODEL_FEATURES) == FEATURE_COUNT - len(NOMINAL_FEATURES)
        assert len(LINEAR_MODEL_FEATURES) == 50
        for f in NOMINAL_FEATURES:
            assert f not in LINEAR_MODEL_FEATURES

    def test_nominal_features_identified(self):
        """Nominal features are protocol and ip_version."""
        assert "protocol" in NOMINAL_FEATURES
        assert "ip_version" in NOMINAL_FEATURES

    def test_redundant_features_documented(self):
        """Redundant features are documented."""
        assert "total_packets" in REDUNDANT_FEATURES
        assert "total_bytes" in REDUNDANT_FEATURES

    def test_every_feature_audited(self):
        """Every feature in schema must have an audit entry."""
        assert len(FEATURE_AUDIT) == FEATURE_COUNT
        for fname in FEATURE_SCHEMA:
            assert fname in FEATURE_AUDIT
            audit = FEATURE_AUDIT[fname]
            assert "status" in audit
            assert "category" in audit
            assert "notes" in audit
            assert audit["status"] in ("safe", "caveat")

    def test_payload_features_documented_as_metadata(self):
        """Payload features must be documented as metadata-only."""
        payload_features = [
            "payload_bytes_total",
            "forward_payload_bytes",
            "reverse_payload_bytes",
            "payload_ratio",
        ]
        for f in payload_features:
            audit = FEATURE_AUDIT[f]
            assert "metadata" in audit["notes"].lower() or "byte count" in audit["notes"].lower()
            assert audit["category"] == "payload_metadata"

    def test_feature_ordering_is_deterministic(self):
        """Feature ordering must be deterministic across accesses."""
        first = tuple(FEATURE_SCHEMA)
        second = tuple(FEATURE_SCHEMA)
        assert first == second

    def test_feature_vector_dimensionality_matches_schema(self):
        """FeatureVector.values length must match canonical schema length."""
        import numpy as np
        from sentinel_net.models.types import FeatureVector, FlowKey

        fk = FlowKey("1.2.3.4", "5.6.7.8", 12345, 80, 6)
        values = [0.0] * FEATURE_COUNT
        fv = FeatureVector(
            flow_key=fk,
            timestamp=0.0,
            features={name: 0.0 for name in FEATURE_SCHEMA},
            feature_names=list(FEATURE_SCHEMA),
            values=values,
        )
        assert len(fv.values) == FEATURE_COUNT
        assert len(fv.feature_names) == FEATURE_COUNT
        arr = fv.to_numpy_array()
        assert arr.shape == (FEATURE_COUNT,)
