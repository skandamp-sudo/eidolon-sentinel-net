"""Tests for rationale generation."""

import pytest
from sentinel_net.explainability.evidence import Evidence, EvidenceCollection
from sentinel_net.explainability.attack_mapping import ATTACKMapping
from sentinel_net.explainability.rationale import RationaleGenerator


@pytest.fixture
def generator():
    return RationaleGenerator()


@pytest.fixture
def sample_evidence():
    return EvidenceCollection(items=[
        Evidence(
            feature_name="pkt_size_mean", observed_value=1500.0,
            reference_value=400.0, contribution=0.45, direction="increase",
            evidence_type="model", source="shap_tree_explainer",
            model_name="xgboost", model_version="1.0.0",
            feature_schema_version="2.0.0",
        ),
        Evidence(
            feature_name="iat_mean", observed_value=0.001,
            reference_value=0.5, contribution=3.5, direction="decrease",
            evidence_type="statistical", source="training_distribution",
            model_name="isolation_forest", model_version="1.0.0",
            feature_schema_version="2.0.0",
        ),
    ])


class TestRationaleGenerator:
    def test_basic_rationale(self, generator, sample_evidence):
        result = generator.generate(
            threat_label="ddos", anomaly_score=0.93,
            model_name="xgboost", evidence=sample_evidence,
        )
        assert "THREAT:" in result
        assert "ANOMALY SCORE:" in result
        assert "MODEL:" in result
        assert "EVIDENCE:" in result
        assert "LIMITATION:" in result

    def test_ddos_threat_label(self, generator, sample_evidence):
        result = generator.generate(
            threat_label="ddos", anomaly_score=0.8,
            model_name="xgb", evidence=sample_evidence,
        )
        assert "Possible DDoS Attack" in result

    def test_c2_threat_label(self, generator, sample_evidence):
        result = generator.generate(
            threat_label="c2", anomaly_score=0.7,
            model_name="xgb", evidence=sample_evidence,
        )
        assert "Possible C2 Beaconing" in result

    def test_benign_label(self, generator, sample_evidence):
        result = generator.generate(
            threat_label="benign", anomaly_score=0.1,
            model_name="xgb", evidence=sample_evidence,
        )
        assert "Benign Traffic" in result

    def test_unknown_label(self, generator, sample_evidence):
        result = generator.generate(
            threat_label="unknown_custom", anomaly_score=0.5,
            model_name="xgb", evidence=sample_evidence,
        )
        assert "Model classified: unknown_custom" in result

    def test_never_says_confirmed_attack(self, generator, sample_evidence):
        result = generator.generate(
            threat_label="ddos", anomaly_score=0.99,
            model_name="xgb", evidence=sample_evidence, confidence=0.99,
        )
        assert "confirmed attack" not in result.lower() or "not a confirmed attack" in result.lower()

    def test_limitation_always_present(self, generator, sample_evidence):
        result = generator.generate(
            threat_label="benign", anomaly_score=0.05,
            model_name="xgb", evidence=sample_evidence,
        )
        assert "Encrypted payload" in result or "encrypted" in result.lower()
        assert "not inspected" in result.lower() or "not inspect" in result.lower()

    def test_empty_evidence(self, generator):
        empty = EvidenceCollection(items=[])
        result = generator.generate(
            threat_label="ddos", anomaly_score=0.5,
            model_name="xgb", evidence=empty,
        )
        assert "No significant evidence" in result

    def test_unavailable_evidence(self, generator):
        unavail = EvidenceCollection.unavailable("SHAP not installed")
        result = generator.generate(
            threat_label="ddos", anomaly_score=0.5,
            model_name="xgb", evidence=unavail,
        )
        assert "SHAP not installed" in result

    def test_with_attack_mappings(self, generator, sample_evidence):
        mappings = [
            ATTACKMapping(
                technique_id="T1498", technique_name="Network Denial of Service",
                tactic="Impact", rationale="High volume",
                applicability="high", qualification="possible",
            )
        ]
        result = generator.generate(
            threat_label="ddos", anomaly_score=0.9,
            model_name="xgb", evidence=sample_evidence,
            attack_mappings=mappings,
        )
        assert "T1498" in result
        assert "ATT&CK" in result

    def test_with_confidence(self, generator, sample_evidence):
        result = generator.generate(
            threat_label="ddos", anomaly_score=0.9,
            model_name="xgb", evidence=sample_evidence, confidence=0.87,
        )
        assert "confidence: 0.87" in result

    def test_statistical_evidence_formatting(self, generator):
        ev = EvidenceCollection(items=[
            Evidence(
                feature_name="iat_mean", observed_value=0.001,
                reference_value=0.5, contribution=3.5, direction="decrease",
                evidence_type="statistical", source="training_distribution",
                model_name="if", model_version="1.0.0",
                feature_schema_version="2.0.0",
            )
        ])
        result = generator.generate(
            threat_label="ddos", anomaly_score=0.8,
            model_name="if", evidence=ev,
        )
        assert "below baseline" in result
        assert "z-score" in result

    def test_model_evidence_formatting(self, generator):
        ev = EvidenceCollection(items=[
            Evidence(
                feature_name="pkt_size_mean", observed_value=1500.0,
                reference_value=400.0, contribution=0.45, direction="increase",
                evidence_type="model", source="shap",
                model_name="xgb", model_version="1.0.0",
                feature_schema_version="2.0.0",
            )
        ])
        result = generator.generate(
            threat_label="ddos", anomaly_score=0.8,
            model_name="xgb", evidence=ev,
        )
        assert "elevated" in result
        assert "contribution" in result
