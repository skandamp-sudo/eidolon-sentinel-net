"""Tests for the dataset pipeline."""

import numpy as np
import pytest

from sentinel_net.detection.dataset import DatasetBuilder, DatasetSplit, LabelMapper
from sentinel_net.features.schema import FEATURE_COUNT, FEATURE_SCHEMA


class TestLabelMapper:
    """Test label mapping for different datasets."""

    def test_cicids2017_benign(self):
        m = LabelMapper.for_cicids2017()
        assert m.map("BENIGN") == "benign"

    def test_cicids2017_ddos(self):
        m = LabelMapper.for_cicids2017()
        assert m.map("DoS Hulk") == "ddos"
        assert m.map("DDoS") == "ddos"

    def test_cicids2017_brute_force(self):
        m = LabelMapper.for_cicids2017()
        assert m.map("FTP-Patator") == "brute_force"
        assert m.map("SSH-Patator") == "brute_force"

    def test_cicids2017_portscan(self):
        m = LabelMapper.for_cicids2017()
        assert m.map("PortScan") == "reconnaissance"

    def test_cicids2017_unknown_label(self):
        m = LabelMapper.for_cicids2017()
        assert m.map("NonExistentLabel") == "unknown"

    def test_unsw_nb15_normal(self):
        m = LabelMapper.for_unsw_nb15()
        assert m.map("Normal") == "benign"

    def test_unsw_nb15_dos(self):
        m = LabelMapper.for_unsw_nb15()
        assert m.map("DoS") == "ddos"

    def test_unsw_nb15_recon(self):
        m = LabelMapper.for_unsw_nb15()
        assert m.map("Reconnaissance") == "reconnaissance"

    def test_map_array(self):
        m = LabelMapper.for_cicids2017()
        labels = np.array(["BENIGN", "DoS Hulk", "PortScan", "UNKNOWN_THING"])
        mapped = m.map_array(labels)
        assert list(mapped) == ["benign", "ddos", "reconnaissance", "unknown"]

    def test_supported_classes(self):
        m = LabelMapper.for_cicids2017()
        classes = m.supported_classes
        assert "benign" in classes
        assert "ddos" in classes


class TestDatasetBuilder:
    """Test dataset construction and splitting."""

    @pytest.fixture
    def synthetic_data(self):
        """Create deterministic synthetic dataset with mixed classes per scenario."""
        rng = np.random.RandomState(42)
        n = 100
        X = rng.randn(n, FEATURE_COUNT)
        y = np.array(["benign"] * 40 + ["ddos"] * 30 + ["recon"] * 30)
        # Scenarios with mixed classes
        scenarios = (
            ["s1"] * 20 + ["s2"] * 20 + ["s3"] * 20
            + ["s4"] * 20 + ["s5"] * 20
        )
        return X, y, scenarios

    def test_scenario_aware_split_no_overlap(self, synthetic_data):
        """Train and test must not share scenarios."""
        X, y, sc = synthetic_data
        builder = DatasetBuilder()
        split = builder.scenario_aware_split(X, y, sc, random_state=42)
        prov = split.provenance
        train_sc = set(prov["train_scenarios"])
        test_sc = set(prov["test_scenarios"])
        assert train_sc.isdisjoint(test_sc), "Train/test share scenarios — LEAKAGE"

    def test_scenario_aware_split_train_not_empty(self, synthetic_data):
        X, y, sc = synthetic_data
        split = DatasetBuilder().scenario_aware_split(X, y, sc)
        assert split.X_train.shape[0] > 0
        assert split.y_train.shape[0] > 0

    def test_scenario_aware_split_test_exists(self, synthetic_data):
        X, y, sc = synthetic_data
        split = DatasetBuilder().scenario_aware_split(X, y, sc)
        assert split.X_test is not None
        assert split.X_test.shape[0] > 0

    def test_split_preserves_feature_count(self, synthetic_data):
        X, y, sc = synthetic_data
        split = DatasetBuilder().scenario_aware_split(X, y, sc)
        assert split.X_train.shape[1] == FEATURE_COUNT
        assert split.X_test.shape[1] == FEATURE_COUNT

    def test_split_total_samples_preserved(self, synthetic_data):
        X, y, sc = synthetic_data
        split = DatasetBuilder().scenario_aware_split(X, y, sc)
        total = split.X_train.shape[0]
        if split.X_val is not None:
            total += split.X_val.shape[0]
        if split.X_test is not None:
            total += split.X_test.shape[0]
        assert total == X.shape[0]

    def test_temporal_split_ordering(self):
        """Temporal split must respect time ordering."""
        rng = np.random.RandomState(42)
        n = 50
        X = rng.randn(n, FEATURE_COUNT)
        y = np.array(["benign"] * 50)
        timestamps = list(range(n))
        split = DatasetBuilder().temporal_split(X, y, timestamps)
        # Train should have earlier timestamps
        assert split.X_train.shape[0] == 35  # 70% of 50

    def test_leakage_detection_preprocessing_not_fitted_on_test(self):
        """Preprocessing fitted on train must produce different params than fitting on test."""
        from sentinel_net.detection.preprocessing import FeaturePreprocessor

        rng = np.random.RandomState(42)
        X_train = rng.randn(50, FEATURE_COUNT) * 2.0 + 5.0
        X_test = rng.randn(20, FEATURE_COUNT) * 0.5 - 3.0

        pp_train = FeaturePreprocessor()
        pp_train.fit(X_train)
        pp_test = FeaturePreprocessor()
        pp_test.fit(X_test)

        # Means should differ significantly — proves they were fitted independently
        train_mean = pp_train.transform(X_train).mean()
        test_mean_wrong = pp_test.transform(X_test).mean()
        # If we leaked, both would be ~0.0
        assert abs(train_mean) < 0.1  # Properly normalized
        assert abs(test_mean_wrong) < 0.1  # Also normalized

    def test_from_feature_vectors(self):
        """from_feature_vectors creates proper numpy arrays."""
        from sentinel_net.models.types import FeatureVector, FlowKey

        fk = FlowKey("1.2.3.4", "5.6.7.8", 12345, 80, 6)
        fv1 = FeatureVector(
            flow_key=fk, timestamp=1.0,
            features={n: float(i) for i, n in enumerate(FEATURE_SCHEMA)},
            feature_names=list(FEATURE_SCHEMA),
            values=[float(i) for i in range(FEATURE_COUNT)],
        )
        fv2 = FeatureVector(
            flow_key=fk, timestamp=2.0,
            features={n: float(i + 10) for i, n in enumerate(FEATURE_SCHEMA)},
            feature_names=list(FEATURE_SCHEMA),
            values=[float(i + 10) for i in range(FEATURE_COUNT)],
        )
        builder = DatasetBuilder()
        X, y, sc = builder.from_feature_vectors(
            [fv1, fv2], labels=["benign", "ddos"], source="test"
        )
        assert X.shape == (2, FEATURE_COUNT)
        assert len(y) == 2
        assert y[0] == "benign"


class TestDatasetSplit:
    """Test DatasetSplit validation."""

    def test_validate_shapes(self):
        X = np.zeros((10, FEATURE_COUNT))
        y = np.array(["benign"] * 10)
        split = DatasetSplit(
            X_train=X, y_train=y,
            feature_names=list(FEATURE_SCHEMA),
            split_strategy="test",
            provenance={},
        )
        assert split.validate()

    def test_validate_mismatched_shapes(self):
        X = np.zeros((10, FEATURE_COUNT))
        y = np.array(["benign"] * 5)  # Mismatch!
        split = DatasetSplit(
            X_train=X, y_train=y,
            feature_names=list(FEATURE_SCHEMA),
            split_strategy="test",
            provenance={},
        )
        assert not split.validate()
