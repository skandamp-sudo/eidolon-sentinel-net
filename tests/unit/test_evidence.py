"""Tests for Evidence model and EvidenceCollection."""

import pytest
from sentinel_net.explainability.evidence import Evidence, EvidenceCollection


class TestEvidence:
    def test_create_model_evidence(self):
        e = Evidence(
            feature_name="pkt_size_mean",
            observed_value=1200.5,
            reference_value=450.2,
            contribution=0.35,
            direction="increase",
            evidence_type="model",
            source="shap_tree_explainer",
            model_name="xgboost",
            model_version="1.0.0",
            feature_schema_version="2.0.0",
        )
        assert e.feature_name == "pkt_size_mean"
        assert e.evidence_type == "model"
        assert e.direction == "increase"

    def test_create_statistical_evidence(self):
        e = Evidence(
            feature_name="iat_mean",
            observed_value=0.001,
            reference_value=0.5,
            contribution=3.2,
            direction="decrease",
            evidence_type="statistical",
            source="training_distribution",
            model_name="isolation_forest",
            model_version="1.0.0",
            feature_schema_version="2.0.0",
        )
        assert e.evidence_type == "statistical"
        assert e.contribution == 3.2

    def test_invalid_evidence_type_raises(self):
        with pytest.raises(ValueError, match="evidence_type"):
            Evidence(
                feature_name="x", observed_value=1.0, reference_value=0.0,
                contribution=0.5, direction="increase", evidence_type="causal",
                source="test", model_name="test", model_version="1",
                feature_schema_version="2.0.0",
            )

    def test_invalid_direction_raises(self):
        with pytest.raises(ValueError, match="direction"):
            Evidence(
                feature_name="x", observed_value=1.0, reference_value=0.0,
                contribution=0.5, direction="up", evidence_type="model",
                source="test", model_name="test", model_version="1",
                feature_schema_version="2.0.0",
            )

    def test_frozen(self):
        e = Evidence(
            feature_name="x", observed_value=1.0, reference_value=0.0,
            contribution=0.5, direction="increase", evidence_type="model",
            source="test", model_name="test", model_version="1",
            feature_schema_version="2.0.0",
        )
        with pytest.raises(AttributeError):
            e.feature_name = "y"

    def test_to_dict_roundtrip(self):
        e = Evidence(
            feature_name="syn_count", observed_value=100.0, reference_value=5.0,
            contribution=2.5, direction="increase", evidence_type="statistical",
            source="training_distribution", model_name="if", model_version="1.0.0",
            feature_schema_version="2.0.0",
        )
        d = e.to_dict()
        assert d["feature_name"] == "syn_count"
        e2 = Evidence.from_dict(d)
        assert e2 == e

    def test_reference_value_none(self):
        e = Evidence(
            feature_name="x", observed_value=1.0, reference_value=None,
            contribution=0.1, direction="increase", evidence_type="heuristic",
            source="rule", model_name="test", model_version="1",
            feature_schema_version="2.0.0",
        )
        assert e.reference_value is None


class TestEvidenceCollection:
    @pytest.fixture
    def sample_evidence(self):
        items = []
        for i, name in enumerate(["feat_a", "feat_b", "feat_c"]):
            items.append(Evidence(
                feature_name=name, observed_value=float(i),
                reference_value=0.0, contribution=float(3 - i),
                direction="increase", evidence_type="model",
                source="test", model_name="test", model_version="1",
                feature_schema_version="2.0.0",
            ))
        return items

    def test_top_k(self, sample_evidence):
        ec = EvidenceCollection(items=sample_evidence)
        top = ec.top_k
        assert top[0].feature_name == "feat_a"  # highest |contribution|
        assert len(top) == 3

    def test_model_vs_statistical(self):
        model_ev = Evidence(
            feature_name="a", observed_value=1.0, reference_value=0.0,
            contribution=0.5, direction="increase", evidence_type="model",
            source="shap", model_name="xgb", model_version="1",
            feature_schema_version="2.0.0",
        )
        stat_ev = Evidence(
            feature_name="b", observed_value=2.0, reference_value=0.0,
            contribution=3.0, direction="decrease", evidence_type="statistical",
            source="train_dist", model_name="if", model_version="1",
            feature_schema_version="2.0.0",
        )
        ec = EvidenceCollection(items=[model_ev, stat_ev])
        assert len(ec.model_evidence) == 1
        assert len(ec.statistical_evidence) == 1

    def test_unavailable(self):
        ec = EvidenceCollection.unavailable("SHAP not installed")
        assert not ec.explanation_available
        assert ec.unavailable_reason == "SHAP not installed"
        assert len(ec.items) == 0

    def test_to_dict_roundtrip(self, sample_evidence):
        ec = EvidenceCollection(items=sample_evidence)
        d = ec.to_dict()
        ec2 = EvidenceCollection.from_dict(d)
        assert len(ec2.items) == 3
        assert ec2.items[0].feature_name == "feat_a"
