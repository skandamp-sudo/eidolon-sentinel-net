"""Tests for dataset adapters — CICIDS2017 and UNSW-NB15.

These tests validate:
- Feature matrix structure and ordering
- Feature availability classification
- Label mapping completeness
- Scenario extraction
- Unit conversions
- NaN handling for missing features
- Deterministic transformation
- No fabricated values
"""
import pytest
import numpy as np
import pandas as pd
from pathlib import Path
from unittest.mock import patch

from sentinel_net.features.schema import FEATURE_SCHEMA, FEATURE_COUNT
from sentinel_net.evaluation.adapters import (
    CICIDSAdapter,
    UNSWAdapter,
    FeatureAvailability,
    FeatureMapping,
    get_cicids_availability_summary,
    get_unsw_availability_summary,
)
from sentinel_net.detection.dataset import LabelMapper, DatasetBuilder


# ═══════════════════════════════════════════════════════════════════════
# CICIDS2017 Feature Matrix Tests
# ═══════════════════════════════════════════════════════════════════════

class TestCICIDSFeatureMatrix:
    """Tests for the CICIDS2017 feature availability matrix."""

    def test_feature_count_is_52(self):
        matrix = CICIDSAdapter.get_feature_matrix()
        assert len(matrix) == FEATURE_COUNT == 52

    def test_feature_order_matches_schema(self):
        matrix = CICIDSAdapter.get_feature_matrix()
        for i, (mapping, expected) in enumerate(zip(matrix, FEATURE_SCHEMA)):
            assert mapping.sentinel_name == expected, (
                f"Feature {i}: got '{mapping.sentinel_name}', expected '{expected}'"
            )

    def test_every_feature_has_availability(self):
        matrix = CICIDSAdapter.get_feature_matrix()
        for m in matrix:
            assert isinstance(m.availability, FeatureAvailability)

    def test_every_feature_has_justification(self):
        matrix = CICIDSAdapter.get_feature_matrix()
        for m in matrix:
            assert m.justification, f"Feature '{m.sentinel_name}' has empty justification"

    def test_missing_features_have_nan_behavior(self):
        matrix = CICIDSAdapter.get_feature_matrix()
        for m in matrix:
            if m.availability == FeatureAvailability.MISSING:
                assert "nan" in m.missing_behavior.lower(), (
                    f"MISSING feature '{m.sentinel_name}' should specify NaN behavior"
                )

    def test_direct_features_have_source_columns(self):
        matrix = CICIDSAdapter.get_feature_matrix()
        for m in matrix:
            if m.availability == FeatureAvailability.DIRECT:
                assert len(m.source_columns) > 0, (
                    f"DIRECT feature '{m.sentinel_name}' has no source columns"
                )

    def test_availability_summary(self):
        summary = get_cicids_availability_summary()
        total = sum(summary.values())
        assert total == 52
        assert summary.get("MISSING", 0) > 0
        assert summary.get("DIRECT", 0) > 0
        assert summary.get("DERIVED", 0) > 0


# ═══════════════════════════════════════════════════════════════════════
# CICIDS2017 Transformation Tests (synthetic data)
# ═══════════════════════════════════════════════════════════════════════

class TestCICIDSTransformations:
    """Tests transformations using synthetic DataFrame."""

    @pytest.fixture
    def sample_df(self):
        """Minimal CICIDS2017-like DataFrame for testing transformations."""
        return pd.DataFrame({
            "Protocol": [6, 17, 1],
            "Flow Duration": [1_000_000, 2_000_000, 500_000],  # microseconds
            "Total Fwd Packets": [10, 20, 5],
            "Total Backward Packets": [8, 0, 3],
            "Fwd Packets Length Total": [1000, 2000, 500],
            "Bwd Packets Length Total": [800, 0, 300],
            "Flow Packets/s": [100.0, 200.0, 50.0],
            "Flow Bytes/s": [10000.0, 20000.0, 5000.0],
            "Packet Length Mean": [100.0, 150.0, 80.0],
            "Packet Length Std": [10.0, 15.0, 8.0],
            "Packet Length Min": [50, 60, 30],
            "Packet Length Max": [200, 300, 150],
            "Flow IAT Mean": [50000.0, 100000.0, 25000.0],  # microseconds
            "Flow IAT Std": [5000.0, 10000.0, 2500.0],
            "Flow IAT Min": [1000, 2000, 500],
            "Flow IAT Max": [100000, 200000, 50000],
            "Fwd IAT Mean": [60000.0, 120000.0, 30000.0],
            "Fwd IAT Std": [6000.0, 12000.0, 3000.0],
            "Fwd IAT Min": [1200, 2400, 600],
            "Fwd IAT Max": [120000, 240000, 60000],
            "Bwd IAT Mean": [70000.0, 0.0, 35000.0],
            "Bwd IAT Std": [7000.0, 0.0, 3500.0],
            "Bwd IAT Min": [1400, 0, 700],
            "Bwd IAT Max": [140000, 0, 70000],
            "SYN Flag Count": [1, 2, 0],
            "ACK Flag Count": [5, 10, 2],
            "FIN Flag Count": [1, 0, 1],
            "RST Flag Count": [0, 0, 0],
            "PSH Flag Count": [3, 5, 1],
            "Label": ["Benign", "DDoS", "Bot"],
        })

    def test_duration_microseconds_to_seconds(self, sample_df):
        matrix = CICIDSAdapter.get_feature_matrix()
        dur_mapping = matrix[0]
        assert dur_mapping.sentinel_name == "duration_sec"
        result = dur_mapping.transformation(sample_df)
        np.testing.assert_allclose(result.values, [1.0, 2.0, 0.5])

    def test_total_packets_derived(self, sample_df):
        matrix = CICIDSAdapter.get_feature_matrix()
        tp_mapping = matrix[1]
        result = tp_mapping.transformation(sample_df)
        np.testing.assert_array_equal(result.values, [18, 20, 8])

    def test_total_bytes_derived(self, sample_df):
        matrix = CICIDSAdapter.get_feature_matrix()
        tb_mapping = matrix[2]
        result = tb_mapping.transformation(sample_df)
        np.testing.assert_array_equal(result.values, [1800, 2000, 800])

    def test_fwd_rev_packet_ratio_handles_zero_denominator(self, sample_df):
        matrix = CICIDSAdapter.get_feature_matrix()
        ratio_mapping = matrix[9]  # fwd_rev_packet_ratio
        result = ratio_mapping.transformation(sample_df)
        # Row 1: 20/max(0,1) = 20.0
        assert result.iloc[1] == 20.0

    def test_iat_mean_converted_to_seconds(self, sample_df):
        matrix = CICIDSAdapter.get_feature_matrix()
        iat_mapping = matrix[19]  # iat_mean
        result = iat_mapping.transformation(sample_df)
        np.testing.assert_allclose(result.values, [0.05, 0.1, 0.025])

    def test_missing_features_are_nan(self, sample_df):
        matrix = CICIDSAdapter.get_feature_matrix()
        missing_features = [m for m in matrix if m.availability == FeatureAvailability.MISSING]
        for m in missing_features:
            result = m.transformation(sample_df)
            assert result.isna().all(), f"MISSING feature '{m.sentinel_name}' should be all NaN"

    def test_is_tcp_derived_correctly(self, sample_df):
        matrix = CICIDSAdapter.get_feature_matrix()
        is_tcp = [m for m in matrix if m.sentinel_name == "is_tcp"][0]
        result = is_tcp.transformation(sample_df)
        np.testing.assert_array_equal(result.values, [1.0, 0.0, 0.0])

    def test_is_udp_derived_correctly(self, sample_df):
        matrix = CICIDSAdapter.get_feature_matrix()
        is_udp = [m for m in matrix if m.sentinel_name == "is_udp"][0]
        result = is_udp.transformation(sample_df)
        np.testing.assert_array_equal(result.values, [0.0, 1.0, 0.0])

    def test_is_icmp_derived_correctly(self, sample_df):
        matrix = CICIDSAdapter.get_feature_matrix()
        is_icmp = [m for m in matrix if m.sentinel_name == "is_icmp"][0]
        result = is_icmp.transformation(sample_df)
        np.testing.assert_array_equal(result.values, [0.0, 0.0, 1.0])

    def test_syn_ratio_derived(self, sample_df):
        matrix = CICIDSAdapter.get_feature_matrix()
        syn_ratio = [m for m in matrix if m.sentinel_name == "syn_ratio"][0]
        result = syn_ratio.transformation(sample_df)
        expected = np.array([1/18, 2/20, 0/8])
        np.testing.assert_allclose(result.values, expected)


# ═══════════════════════════════════════════════════════════════════════
# CICIDS2017 Label Mapping Tests
# ═══════════════════════════════════════════════════════════════════════

class TestCICIDSLabelMapping:
    """Tests for CICIDS2017 label mapping."""

    def test_all_raw_labels_mapped(self):
        """All known CICIDS2017 raw labels must produce a non-unknown mapping."""
        raw_labels = [
            "Benign", "BENIGN", "Bot", "DDoS", "DoS GoldenEye", "DoS Hulk",
            "DoS Slowhttptest", "DoS slowloris", "FTP-Patator", "Heartbleed",
            "Infiltration", "PortScan", "SSH-Patator",
            "Web Attack - Brute Force", "Web Attack - XSS", "Web Attack - Sql Injection",
        ]
        mapper = LabelMapper.for_cicids2017()
        for raw in raw_labels:
            mapped = mapper.map(raw)
            assert mapped != "unknown", f"Label '{raw}' mapped to 'unknown'"

    def test_mojibake_web_attack_labels_mapped(self):
        """Web Attack labels with replacement character must be handled."""
        mapper = LabelMapper.for_cicids2017()
        assert mapper.map("Web Attack \ufffd Brute Force") == "other"
        assert mapper.map("Web Attack \ufffd XSS") == "other"
        assert mapper.map("Web Attack \ufffd Sql Injection") == "other"

    def test_en_dash_web_attack_labels_mapped(self):
        """Web Attack labels with en-dash must be handled."""
        mapper = LabelMapper.for_cicids2017()
        assert mapper.map("Web Attack \u2013 Brute Force") == "other"

    def test_label_mapping_dict_complete(self):
        mapping = CICIDSAdapter.get_label_mapping()
        assert isinstance(mapping, dict)
        assert len(mapping) >= 15  # At least the 15 raw labels

    def test_benign_maps_to_benign(self):
        mapper = LabelMapper.for_cicids2017()
        assert mapper.map("Benign") == "benign"
        assert mapper.map("BENIGN") == "benign"


# ═══════════════════════════════════════════════════════════════════════
# CICIDS2017 Scenario Tests
# ═══════════════════════════════════════════════════════════════════════

class TestCICIDSScenarios:
    """Tests for CICIDS2017 scenario extraction."""

    def test_scenario_disjoint_splitting(self):
        """Scenario-aware split must produce disjoint scenario sets."""
        # Create synthetic data with 4 scenarios
        n = 400
        X = np.random.randn(n, 52)
        y = np.array(["benign"] * n)
        scenarios = [f"scenario-{i // 100}" for i in range(n)]
        
        builder = DatasetBuilder()
        split = builder.scenario_aware_split(X, y, scenarios)
        
        train_scens = set(split.provenance.get("train_scenarios", []))
        val_scens = set(split.provenance.get("val_scenarios", []))
        test_scens = set(split.provenance.get("test_scenarios", []))
        
        assert train_scens.isdisjoint(val_scens), "Train and val overlap"
        assert train_scens.isdisjoint(test_scens), "Train and test overlap"
        assert val_scens.isdisjoint(test_scens), "Val and test overlap"


# ═══════════════════════════════════════════════════════════════════════
# UNSW-NB15 Feature Matrix Tests
# ═══════════════════════════════════════════════════════════════════════

class TestUNSWFeatureMatrix:
    """Tests for the UNSW-NB15 feature availability matrix."""

    def test_feature_count_is_52(self):
        matrix = UNSWAdapter.get_feature_matrix()
        assert len(matrix) == FEATURE_COUNT == 52

    def test_feature_order_matches_schema(self):
        matrix = UNSWAdapter.get_feature_matrix()
        for i, (mapping, expected) in enumerate(zip(matrix, FEATURE_SCHEMA)):
            assert mapping.sentinel_name == expected

    def test_availability_summary(self):
        summary = get_unsw_availability_summary()
        total = sum(summary.values())
        assert total == 52
        assert summary.get("MISSING", 0) >= 30  # At least 30 missing
        assert summary.get("PROXY", 0) >= 1     # At least 1 proxy

    def test_proxy_features_documented(self):
        """All PROXY features must have meaningful justification."""
        matrix = UNSWAdapter.get_feature_matrix()
        proxies = [m for m in matrix if m.availability == FeatureAvailability.PROXY]
        for m in proxies:
            assert len(m.justification) > 5, (
                f"PROXY feature '{m.sentinel_name}' needs better justification"
            )


# ═══════════════════════════════════════════════════════════════════════
# UNSW-NB15 Transformation Tests (synthetic data)
# ═══════════════════════════════════════════════════════════════════════

class TestUNSWTransformations:
    """Tests for UNSW-NB15 adapter transformations."""

    @pytest.fixture
    def sample_df(self):
        return pd.DataFrame({
            "dur": [1.0, 2.0, 0.5],
            "spkts": [10, 20, 5],
            "dpkts": [8, 0, 3],
            "sbytes": [1000, 2000, 500],
            "dbytes": [800, 0, 300],
            "rate": [10000.0, 20000.0, 5000.0],
            "sinpkt": [0.05, 0.1, 0.025],
            "dinpkt": [0.07, 0.0, 0.035],
            "proto": ["tcp", "udp", "icmp"],
            "attack_cat": ["Normal", "DoS", "Fuzzers"],
            "label": [0, 1, 1],
        })

    def test_duration_is_direct(self, sample_df):
        matrix = UNSWAdapter.get_feature_matrix()
        dur = matrix[0]
        result = dur.transformation(sample_df)
        np.testing.assert_array_equal(result.values, [1.0, 2.0, 0.5])

    def test_total_packets_derived(self, sample_df):
        matrix = UNSWAdapter.get_feature_matrix()
        tp = matrix[1]
        result = tp.transformation(sample_df)
        np.testing.assert_array_equal(result.values, [18, 20, 8])

    def test_protocol_encoding(self, sample_df):
        matrix = UNSWAdapter.get_feature_matrix()
        proto = [m for m in matrix if m.sentinel_name == "protocol"][0]
        result = proto.transformation(sample_df)
        np.testing.assert_array_equal(result.values, [6.0, 17.0, 1.0])

    def test_is_tcp_derived(self, sample_df):
        matrix = UNSWAdapter.get_feature_matrix()
        is_tcp = [m for m in matrix if m.sentinel_name == "is_tcp"][0]
        result = is_tcp.transformation(sample_df)
        np.testing.assert_array_equal(result.values, [1.0, 0.0, 0.0])

    def test_missing_features_are_nan(self, sample_df):
        matrix = UNSWAdapter.get_feature_matrix()
        missing = [m for m in matrix if m.availability == FeatureAvailability.MISSING]
        for m in missing:
            result = m.transformation(sample_df)
            assert result.isna().all(), f"'{m.sentinel_name}' should be NaN"


# ═══════════════════════════════════════════════════════════════════════
# UNSW-NB15 Label Mapping Tests
# ═══════════════════════════════════════════════════════════════════════

class TestUNSWLabelMapping:
    """Tests for UNSW-NB15 label mapping."""

    def test_all_raw_categories_mapped(self):
        raw_cats = [
            "Normal", "Analysis", "Backdoor", "DoS", "Exploits",
            "Fuzzers", "Generic", "Reconnaissance", "Shellcode", "Worms",
        ]
        mapper = LabelMapper.for_unsw_nb15()
        for cat in raw_cats:
            mapped = mapper.map(cat)
            assert mapped != "unknown", f"Category '{cat}' mapped to 'unknown'"

    def test_label_mapping_dict(self):
        mapping = UNSWAdapter.get_label_mapping()
        assert isinstance(mapping, dict)
        assert len(mapping) >= 10


# ═══════════════════════════════════════════════════════════════════════
# Preprocessing Compatibility Tests
# ═══════════════════════════════════════════════════════════════════════

class TestPreprocessingCompatibility:
    """Tests for preprocessing pipeline compatibility with adapter output."""

    def test_preprocessor_handles_nan_features(self):
        """Preprocessor must handle NaN columns from missing features."""
        from sentinel_net.detection.preprocessing import FeaturePreprocessor
        
        # Create data with NaN columns (like CICIDS missing features)
        X = np.random.randn(100, 52)
        # Set columns 15,16,17,18,23 to NaN (pkt_size_median, p25, p75, p90, iat_median)
        nan_cols = [15, 16, 17, 18, 23, 33, 44, 48, 49, 50, 51]
        X[:, nan_cols] = np.nan
        
        pp = FeaturePreprocessor()
        X_transformed = pp.fit_transform(X)
        
        # Should not contain NaN after imputation
        assert not np.isnan(X_transformed).any(), "Preprocessor should impute NaN values"
        assert not np.isinf(X_transformed).any(), "Preprocessor should handle inf"

    def test_preprocessor_feature_count_matches(self):
        from sentinel_net.detection.preprocessing import FeaturePreprocessor
        pp = FeaturePreprocessor()
        assert pp.n_features_in == FEATURE_COUNT or pp.n_features_in == len(pp._feature_subset)


# ═══════════════════════════════════════════════════════════════════════
# Model Compatibility Tests
# ═══════════════════════════════════════════════════════════════════════

class TestModelCompatibility:
    """Tests verifying model input compatibility."""

    def test_adapter_output_shape_matches_model_input(self):
        """Adapter output must have exactly 52 features."""
        # Use synthetic small parquet data would be ideal, but we test the matrix
        matrix = CICIDSAdapter.get_feature_matrix()
        assert len(matrix) == 52
        
        unsw_matrix = UNSWAdapter.get_feature_matrix()
        assert len(unsw_matrix) == 52

    def test_feature_schema_version_consistent(self):
        from sentinel_net.features.schema import FEATURE_SCHEMA_VERSION
        assert FEATURE_SCHEMA_VERSION == "2.0.0"

    def test_unsw_high_missing_rate_documented(self):
        """UNSW-NB15 has >50% missing features — this must be visible."""
        summary = get_unsw_availability_summary()
        missing = summary.get("MISSING", 0)
        assert missing > 26, (
            f"UNSW-NB15 has {missing} MISSING features — expected >26 (>50%)"
        )


# ═══════════════════════════════════════════════════════════════════════
# Determinism Tests
# ═══════════════════════════════════════════════════════════════════════

class TestDeterminism:
    """Tests ensuring transformation determinism."""

    def test_cicids_matrix_deterministic(self):
        m1 = CICIDSAdapter.get_feature_matrix()
        m2 = CICIDSAdapter.get_feature_matrix()
        for a, b in zip(m1, m2):
            assert a.sentinel_name == b.sentinel_name
            assert a.availability == b.availability

    def test_unsw_matrix_deterministic(self):
        m1 = UNSWAdapter.get_feature_matrix()
        m2 = UNSWAdapter.get_feature_matrix()
        for a, b in zip(m1, m2):
            assert a.sentinel_name == b.sentinel_name
            assert a.availability == b.availability

    def test_cicids_transform_deterministic(self):
        """Same input must produce same output."""
        df = pd.DataFrame({
            "Protocol": [6], "Flow Duration": [1_000_000],
            "Total Fwd Packets": [10], "Total Backward Packets": [5],
            "Fwd Packets Length Total": [1000], "Bwd Packets Length Total": [500],
            "Flow Packets/s": [100.0], "Flow Bytes/s": [10000.0],
            "Packet Length Mean": [100.0], "Packet Length Std": [10.0],
            "Packet Length Min": [50], "Packet Length Max": [200],
            "Flow IAT Mean": [50000.0], "Flow IAT Std": [5000.0],
            "Flow IAT Min": [1000], "Flow IAT Max": [100000],
            "Fwd IAT Mean": [60000.0], "Fwd IAT Std": [6000.0],
            "Fwd IAT Min": [1200], "Fwd IAT Max": [120000],
            "Bwd IAT Mean": [70000.0], "Bwd IAT Std": [7000.0],
            "Bwd IAT Min": [1400], "Bwd IAT Max": [140000],
            "SYN Flag Count": [1], "ACK Flag Count": [5],
            "FIN Flag Count": [1], "RST Flag Count": [0],
            "PSH Flag Count": [3],
        })
        matrix = CICIDSAdapter.get_feature_matrix()
        r1 = [m.transformation(df).iloc[0] for m in matrix]
        r2 = [m.transformation(df).iloc[0] for m in matrix]
        for i, (a, b) in enumerate(zip(r1, r2)):
            if np.isnan(a) and np.isnan(b):
                continue
            assert a == b, f"Feature {FEATURE_SCHEMA[i]} not deterministic"
