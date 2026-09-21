"""Tests for anomaly detection."""

import numpy as np
import pytest
import tempfile
from pathlib import Path

from sentinel_net.detection.anomaly import AnomalyDetector
from sentinel_net.features.schema import FEATURE_COUNT


class TestAnomalyDetector:
    """Test Isolation Forest anomaly detector."""

    @pytest.fixture
    def rng(self):
        return np.random.RandomState(42)

    @pytest.fixture
    def benign_data(self, rng):
        """Normal traffic: tight cluster."""
        return rng.randn(100, FEATURE_COUNT) * 0.5

    @pytest.fixture
    def anomaly_data(self, rng):
        """Anomalous traffic: shifted distribution."""
        return rng.randn(10, FEATURE_COUNT) * 2.0 + 5.0

    def test_train(self, benign_data):
        ad = AnomalyDetector(random_state=42)
        ad.train(benign_data)
        assert ad.is_trained

    def test_not_trained_raises(self, benign_data):
        ad = AnomalyDetector()
        with pytest.raises((ValueError, RuntimeError)):
            ad.score(benign_data)

    def test_score_range(self, benign_data, anomaly_data):
        """Anomaly scores must be in [0, 1]."""
        ad = AnomalyDetector(random_state=42)
        ad.train(benign_data)
        scores = ad.score(np.vstack([benign_data, anomaly_data]))
        assert scores.min() >= 0.0
        assert scores.max() <= 1.0

    def test_anomalies_score_higher(self, benign_data, anomaly_data):
        """Anomalous data should score higher than benign on average."""
        ad = AnomalyDetector(random_state=42)
        ad.train(benign_data)
        benign_scores = ad.score(benign_data)
        anomaly_scores = ad.score(anomaly_data)
        assert anomaly_scores.mean() > benign_scores.mean()

    def test_predict_boolean(self, benign_data):
        ad = AnomalyDetector(random_state=42)
        ad.train(benign_data)
        preds = ad.predict(benign_data, threshold=0.5)
        assert preds.dtype == bool

    def test_deterministic(self, benign_data):
        """Same seed must produce identical results."""
        ad1 = AnomalyDetector(random_state=42)
        ad1.train(benign_data)
        scores1 = ad1.score(benign_data)

        ad2 = AnomalyDetector(random_state=42)
        ad2.train(benign_data)
        scores2 = ad2.score(benign_data)

        np.testing.assert_array_equal(scores1, scores2)

    def test_save_load(self, benign_data):
        ad = AnomalyDetector(random_state=42)
        ad.train(benign_data)
        original = ad.score(benign_data[:5])

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "anomaly.joblib"
            ad.save(path)
            loaded = AnomalyDetector.load(path)

        result = loaded.score(benign_data[:5])
        np.testing.assert_array_almost_equal(original, result)

    def test_model_metadata(self):
        ad = AnomalyDetector(model_name="test_if", model_version="0.1.0")
        assert ad.model_name == "test_if"
        assert ad.model_version == "0.1.0"

    def test_to_anomaly_results(self, benign_data):
        """to_anomaly_results must return AnomalyResult objects."""
        from sentinel_net.models.types import AnomalyResult, FlowKey

        ad = AnomalyDetector(random_state=42)
        ad.train(benign_data)
        fks = [FlowKey("1.2.3.4", "5.6.7.8", i, 80, 6) for i in range(5)]
        ts = [float(i) for i in range(5)]
        results = ad.to_anomaly_results(benign_data[:5], fks, ts)
        assert len(results) == 5
        assert isinstance(results[0], AnomalyResult)
        assert 0.0 <= results[0].anomaly_score <= 1.0
