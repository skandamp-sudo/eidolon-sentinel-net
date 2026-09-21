"""Tests for ExplainableDetection composite type."""

import time
import pytest
import numpy as np

from sentinel_net.explainability.evidence import Evidence, EvidenceCollection
from sentinel_net.explainability.explainable_detection import ExplainableDetection, EXPLANATION_VERSION
from sentinel_net.explainability.attack_mapping import ATTACKMapping
from sentinel_net.explainability.anomaly_explainer import AnomalyExplainer
from sentinel_net.explainability.rationale import RationaleGenerator
from sentinel_net.models.types import (
    DetectionEvent, AnomalyResult, ThreatClassification, FlowKey, FeatureVector,
)
from sentinel_net.features.schema import FEATURE_SCHEMA, FEATURE_COUNT


def _make_detection_event() -> DetectionEvent:
    fk = FlowKey("10.0.0.1", "10.0.0.2", 12345, 80, 6)
    return DetectionEvent(
        id="evt-001",
        timestamp=time.time(),
        flow_key=fk,
        observed_flow=None,
        anomaly_result=AnomalyResult(
            flow_key=fk, timestamp=time.time(), anomaly_score=0.85,
            is_anomalous=True, model_name="isolation_forest", model_version="1.0.0",
        ),
        threat_classification=ThreatClassification(
            flow_key=fk, timestamp=time.time(), threat_type="ddos",
            confidence=0.92, model_name="xgboost", model_version="1.0.0",
        ),
        severity="high",
        rationale="Original rationale",
        metadata={"feature_schema_version": "2.0.0"},
    )


def _make_evidence():
    return EvidenceCollection(items=[
        Evidence(
            feature_name="pkt_size_mean", observed_value=1500.0,
            reference_value=400.0, contribution=0.45, direction="increase",
            evidence_type="model", source="shap",
            model_name="xgboost", model_version="1.0.0",
            feature_schema_version="2.0.0",
        ),
    ])


class TestExplainableDetection:
    def test_create(self):
        event = _make_detection_event()
        ed = ExplainableDetection(
            detection_event=event,
            classifier_evidence=_make_evidence(),
            rationale="Test rationale",
        )
        assert ed.detection_event_id == "evt-001"
        assert ed.threat_type == "ddos"
        assert ed.anomaly_score == 0.85
        assert ed.confidence == 0.92

    def test_does_not_mutate_event(self):
        event = _make_detection_event()
        original_id = event.id
        original_rationale = event.rationale
        ed = ExplainableDetection(
            detection_event=event,
            rationale="New rationale",
        )
        assert event.id == original_id
        assert event.rationale == original_rationale

    def test_explanation_version(self):
        ed = ExplainableDetection(detection_event=_make_detection_event())
        assert ed.explanation_version == EXPLANATION_VERSION

    def test_unique_explanation_id(self):
        e1 = ExplainableDetection(detection_event=_make_detection_event())
        e2 = ExplainableDetection(detection_event=_make_detection_event())
        assert e1.explanation_id != e2.explanation_id

    def test_generation_timestamp(self):
        before = time.time()
        ed = ExplainableDetection(detection_event=_make_detection_event())
        after = time.time()
        assert before <= ed.generation_timestamp <= after

    def test_all_evidence_merges(self):
        model_ev = _make_evidence()
        stat_ev = EvidenceCollection(items=[
            Evidence(
                feature_name="iat_mean", observed_value=0.001,
                reference_value=0.5, contribution=3.2, direction="decrease",
                evidence_type="statistical", source="train_dist",
                model_name="if", model_version="1.0.0",
                feature_schema_version="2.0.0",
            ),
        ])
        ed = ExplainableDetection(
            detection_event=_make_detection_event(),
            classifier_evidence=model_ev,
            anomaly_evidence=stat_ev,
        )
        merged = ed.all_evidence
        assert len(merged.items) == 2
        assert merged.explanation_available

    def test_to_dict(self):
        ed = ExplainableDetection(
            detection_event=_make_detection_event(),
            classifier_evidence=_make_evidence(),
            rationale="Test",
            attack_mappings=[ATTACKMapping(
                technique_id="T1498", technique_name="Network DoS",
                tactic="Impact", rationale="Volume",
                applicability="high", qualification="possible",
            )],
        )
        d = ed.to_dict()
        assert d["detection_event_id"] == "evt-001"
        assert d["threat_type"] == "ddos"
        assert d["explanation_version"] == EXPLANATION_VERSION
        assert len(d["attack_mappings"]) == 1
        assert len(d["classifier_evidence"]["items"]) == 1

    def test_severity(self):
        ed = ExplainableDetection(detection_event=_make_detection_event())
        assert ed.severity == "high"


class TestAnomalyExplainer:
    @pytest.fixture
    def rng(self):
        return np.random.RandomState(42)

    @pytest.fixture
    def explainer(self, rng):
        X_train = rng.randn(100, FEATURE_COUNT)
        ae = AnomalyExplainer()
        ae.fit(X_train)
        return ae

    def test_fit(self, explainer):
        assert explainer.is_fitted

    def test_not_fitted_returns_unavailable(self):
        ae = AnomalyExplainer()
        X = np.zeros((1, FEATURE_COUNT))
        result = ae.explain(X, anomaly_score=0.5)
        assert not result.explanation_available
        assert "fitted" in result.unavailable_reason.lower()

    def test_normal_sample_few_evidence(self, explainer, rng):
        X = rng.randn(1, FEATURE_COUNT) * 0.5  # Normal range
        result = explainer.explain(X, anomaly_score=0.3)
        assert result.explanation_available
        # Most features should be within z_threshold
        assert len(result.items) < FEATURE_COUNT

    def test_extreme_sample_many_evidence(self, explainer):
        X = np.full((1, FEATURE_COUNT), 10.0)  # Far from training distribution
        result = explainer.explain(X, anomaly_score=0.95)
        assert result.explanation_available
        assert len(result.items) > 0

    def test_evidence_type_is_statistical(self, explainer):
        X = np.full((1, FEATURE_COUNT), 10.0)
        result = explainer.explain(X, anomaly_score=0.95)
        for item in result.items:
            assert item.evidence_type == "statistical"

    def test_evidence_source_is_training_distribution(self, explainer):
        X = np.full((1, FEATURE_COUNT), 10.0)
        result = explainer.explain(X, anomaly_score=0.95)
        for item in result.items:
            assert item.source == "training_distribution"

    def test_z_threshold_configurable(self, rng):
        X_train = rng.randn(100, FEATURE_COUNT)
        ae = AnomalyExplainer()
        ae.fit(X_train)
        ae.z_threshold = 1.0  # More sensitive
        X = rng.randn(1, FEATURE_COUNT) * 1.5
        result_sensitive = ae.explain(X, anomaly_score=0.5)

        ae.z_threshold = 5.0  # Less sensitive
        result_strict = ae.explain(X, anomaly_score=0.5)
        assert len(result_sensitive.items) >= len(result_strict.items)

    def test_z_threshold_must_be_positive(self):
        ae = AnomalyExplainer()
        with pytest.raises(ValueError, match="positive"):
            ae.z_threshold = -1.0

    def test_reference_values_populated(self, explainer):
        X = np.full((1, FEATURE_COUNT), 10.0)
        result = explainer.explain(X, anomaly_score=0.95)
        for item in result.items:
            assert item.reference_value is not None

    def test_direction_correctness(self, explainer):
        """Features above mean should have direction='increase'."""
        X = np.full((1, FEATURE_COUNT), 100.0)  # Way above mean
        result = explainer.explain(X, anomaly_score=0.95)
        for item in result.items:
            assert item.direction == "increase"


class TestFullExplainableWorkflow:
    """Integration test: Evidence → Rationale → ExplainableDetection."""

    def test_end_to_end(self):
        # 1. Build detection event
        event = _make_detection_event()

        # 2. Generate anomaly evidence
        rng = np.random.RandomState(42)
        X_train = rng.randn(100, FEATURE_COUNT)
        ae = AnomalyExplainer()
        ae.fit(X_train)
        X_sample = np.full((1, FEATURE_COUNT), 5.0)
        anomaly_ev = ae.explain(X_sample, anomaly_score=0.85)

        # 3. Generate rationale
        from sentinel_net.explainability.attack_mapping import ATTACKMapper
        attack_mapper = ATTACKMapper()
        attack_mappings = attack_mapper.map("ddos", confidence=0.92)

        rg = RationaleGenerator()
        rationale = rg.generate(
            threat_label="ddos", anomaly_score=0.85,
            model_name="xgboost", evidence=anomaly_ev,
            attack_mappings=attack_mappings, confidence=0.92,
        )

        # 4. Compose ExplainableDetection
        ed = ExplainableDetection(
            detection_event=event,
            anomaly_evidence=anomaly_ev,
            rationale=rationale,
            attack_mappings=attack_mappings,
        )

        # Verify
        assert ed.detection_event_id == "evt-001"
        assert ed.threat_type == "ddos"
        assert "THREAT:" in ed.rationale
        assert "LIMITATION:" in ed.rationale
        assert len(ed.attack_mappings) > 0
        assert ed.all_evidence.explanation_available
        d = ed.to_dict()
        assert isinstance(d, dict)
        assert "explanation_id" in d
