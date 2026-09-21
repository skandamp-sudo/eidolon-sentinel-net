"""Tests for the detection inference pipeline."""

import numpy as np
import pytest

from sentinel_net.detection.anomaly import AnomalyDetector
from sentinel_net.detection.classifier import RandomForestBaseline
from sentinel_net.detection.inference import DetectionPipeline
from sentinel_net.detection.preprocessing import FeaturePreprocessor
from sentinel_net.detection.thresholds import ThresholdConfig
from sentinel_net.features.schema import FEATURE_COUNT, FEATURE_SCHEMA
from sentinel_net.models.types import DetectionEvent, FeatureVector, FlowKey


@pytest.fixture
def trained_pipeline():
    """Build a complete trained detection pipeline from synthetic data."""
    rng = np.random.RandomState(42)
    X_train = np.vstack([
        rng.randn(60, FEATURE_COUNT) * 0.5,       # benign
        rng.randn(30, FEATURE_COUNT) * 0.5 + 3.0,  # ddos
    ])
    y_train = np.array(["benign"] * 60 + ["ddos"] * 30)

    pp = FeaturePreprocessor()
    pp.fit(X_train)
    X_pp = pp.transform(X_train)

    ad = AnomalyDetector(random_state=42)
    ad.train(X_pp[y_train == "benign"])

    clf = RandomForestBaseline(random_state=42)
    clf.train(X_pp, y_train)

    thresholds = ThresholdConfig(anomaly_threshold=0.5, min_confidence=0.3)
    return DetectionPipeline(pp, ad, clf, thresholds)


@pytest.fixture
def sample_fv():
    """Create a single FeatureVector for testing."""
    fk = FlowKey("10.0.0.1", "10.0.0.2", 12345, 80, 6)
    values = [float(i) for i in range(FEATURE_COUNT)]
    return FeatureVector(
        flow_key=fk,
        timestamp=1000.0,
        features={n: float(i) for i, n in enumerate(FEATURE_SCHEMA)},
        feature_names=list(FEATURE_SCHEMA),
        values=values,
    )


class TestDetectionPipeline:
    def test_detect_single_returns_event(self, trained_pipeline, sample_fv):
        event = trained_pipeline.detect_single(sample_fv)
        assert isinstance(event, DetectionEvent)

    def test_event_has_anomaly_result(self, trained_pipeline, sample_fv):
        event = trained_pipeline.detect_single(sample_fv)
        assert event.anomaly_result is not None
        assert 0.0 <= event.anomaly_result.anomaly_score <= 1.0

    def test_event_has_threat_classification(self, trained_pipeline, sample_fv):
        event = trained_pipeline.detect_single(sample_fv)
        assert event.threat_classification is not None
        assert event.threat_classification.threat_type in ("benign", "ddos")

    def test_event_has_metadata(self, trained_pipeline, sample_fv):
        event = trained_pipeline.detect_single(sample_fv)
        assert "feature_schema_version" in event.metadata
        assert event.id  # UUID should be non-empty

    def test_event_has_rationale(self, trained_pipeline, sample_fv):
        event = trained_pipeline.detect_single(sample_fv)
        assert len(event.rationale) > 0
        assert "anomaly" in event.rationale.lower() or "score" in event.rationale.lower()

    def test_detect_batch(self, trained_pipeline, sample_fv):
        """Batch detection must process multiple feature vectors."""
        fvs = [sample_fv, sample_fv, sample_fv]
        events = trained_pipeline.detect_batch(fvs)
        assert len(events) == 3
        for e in events:
            assert isinstance(e, DetectionEvent)

    def test_severity_assigned(self, trained_pipeline, sample_fv):
        event = trained_pipeline.detect_single(sample_fv)
        assert event.severity in ("info", "low", "medium", "high", "critical")


class TestThresholdConfig:
    def test_default_values(self):
        tc = ThresholdConfig()
        assert tc.anomaly_threshold == 0.5
        assert tc.min_confidence == 0.3

    def test_is_anomalous(self):
        tc = ThresholdConfig(anomaly_threshold=0.5)
        assert tc.is_anomalous(0.6)
        assert not tc.is_anomalous(0.4)
        assert tc.is_anomalous(0.5)  # >= threshold

    def test_get_severity(self):
        tc = ThresholdConfig()
        assert tc.get_severity(0.1) == "info"      # below 0.3
        assert tc.get_severity(0.3) == "low"        # >= 0.3
        assert tc.get_severity(0.5) == "medium"     # >= 0.5
        assert tc.get_severity(0.7) == "high"       # >= 0.7
        assert tc.get_severity(0.95) == "critical"  # >= 0.9

    def test_serialization(self):
        tc = ThresholdConfig(anomaly_threshold=0.7)
        d = tc.to_dict()
        loaded = ThresholdConfig.from_dict(d)
        assert loaded.anomaly_threshold == 0.7
