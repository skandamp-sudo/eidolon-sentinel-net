"""
Tests for the Phase 7 evaluation framework.

These are SOFTWARE TESTS validating implementation correctness.
They are NOT scientific experiments.
"""

import numpy as np
import pytest
from pathlib import Path

from sentinel_net.features.schema import FEATURE_SCHEMA, FEATURE_COUNT, FEATURE_SCHEMA_VERSION
from sentinel_net.detection.dataset import DatasetSplit


# ─── Protocol Tests ────────────────────────────────────────────────────

class TestEvaluationProtocol:
    """Tests for evaluation protocol state machine."""

    def test_initial_state_is_open(self):
        from sentinel_net.evaluation.protocol import EvaluationProtocol
        proto = EvaluationProtocol("test-001")
        assert proto.state == EvaluationProtocol.OPEN

    def test_lock_threshold_transitions_state(self):
        from sentinel_net.evaluation.protocol import EvaluationProtocol
        proto = EvaluationProtocol("test-002")
        proto.lock_threshold(0.5, source="default")
        assert proto.state == EvaluationProtocol.THRESHOLD_LOCKED
        assert proto.threshold == 0.5
        assert proto.threshold_source == "default"

    def test_lock_threshold_validation_optimized(self):
        from sentinel_net.evaluation.protocol import EvaluationProtocol
        proto = EvaluationProtocol("test-003")
        proto.lock_threshold(0.35, source="validation_optimized")
        assert proto.state == EvaluationProtocol.THRESHOLD_LOCKED
        assert proto.threshold_source == "validation_optimized"

    def test_cannot_lock_threshold_twice(self):
        from sentinel_net.evaluation.protocol import EvaluationProtocol
        proto = EvaluationProtocol("test-004")
        proto.lock_threshold(0.5, source="default")
        with pytest.raises(RuntimeError):
            proto.lock_threshold(0.6, source="default")

    def test_cannot_register_split_after_lock(self):
        from sentinel_net.evaluation.protocol import EvaluationProtocol
        proto = EvaluationProtocol("test-005")
        proto.lock_threshold(0.5, source="default")
        X = np.random.randn(10, FEATURE_COUNT)
        y = np.array(["benign"] * 10)
        split = DatasetSplit(X_train=X, y_train=y)
        with pytest.raises(RuntimeError):
            proto.register_split(split)

    def test_final_evaluation_transitions_state(self):
        from sentinel_net.evaluation.protocol import EvaluationProtocol
        proto = EvaluationProtocol("test-006")
        proto.lock_threshold(0.5, source="default")
        proto.record_final_evaluation({"f1": 0.8})
        assert proto.state == EvaluationProtocol.FINAL_EVALUATED

    def test_cannot_evaluate_without_locked_threshold(self):
        from sentinel_net.evaluation.protocol import EvaluationProtocol
        proto = EvaluationProtocol("test-007")
        with pytest.raises(RuntimeError):
            proto.record_final_evaluation({"f1": 0.8})

    def test_cannot_modify_after_final_evaluation(self):
        from sentinel_net.evaluation.protocol import EvaluationProtocol
        proto = EvaluationProtocol("test-008")
        proto.lock_threshold(0.5, source="default")
        proto.record_final_evaluation({"f1": 0.8})
        # State is FINAL_EVALUATED — no more changes
        with pytest.raises(RuntimeError):
            proto.lock_threshold(0.6, source="default")

    def test_invalid_threshold_source_rejected(self):
        from sentinel_net.evaluation.protocol import EvaluationProtocol
        proto = EvaluationProtocol("test-009")
        with pytest.raises(ValueError):
            proto.lock_threshold(0.5, source="test_optimized")

    def test_split_integrity_disjoint_samples(self):
        from sentinel_net.evaluation.protocol import EvaluationProtocol
        rng = np.random.RandomState(42)
        X = rng.randn(30, FEATURE_COUNT)
        y = np.array(["benign"] * 10 + ["ddos"] * 10 + ["scan"] * 10)
        split = DatasetSplit(
            X_train=X[:10], y_train=y[:10],
            X_val=X[10:20], y_val=y[10:20],
            X_test=X[20:], y_test=y[20:],
        )
        proto = EvaluationProtocol("test-010")
        proto.register_split(split)
        assert proto.verify_split_integrity() is True

    def test_split_integrity_fails_on_overlap(self):
        from sentinel_net.evaluation.protocol import EvaluationProtocol
        rng = np.random.RandomState(42)
        X = rng.randn(20, FEATURE_COUNT)
        y = np.array(["benign"] * 10 + ["ddos"] * 10)
        # Overlap: test = train
        split = DatasetSplit(
            X_train=X[:10], y_train=y[:10],
            X_test=X[:10], y_test=y[:10],
        )
        proto = EvaluationProtocol("test-011")
        proto.register_split(split)
        assert proto.verify_split_integrity() is False

    def test_scenario_disjointness_checked(self):
        from sentinel_net.evaluation.protocol import EvaluationProtocol
        rng = np.random.RandomState(42)
        X = rng.randn(30, FEATURE_COUNT)
        y = np.array(["benign"] * 30)
        split = DatasetSplit(
            X_train=X[:10], y_train=y[:10],
            X_val=X[10:20], y_val=y[10:20],
            X_test=X[20:], y_test=y[20:],
            train_scenario_ids=["A", "B"],
            val_scenario_ids=["C"],
            test_scenario_ids=["D"],
        )
        proto = EvaluationProtocol("test-012")
        proto.register_split(split)
        assert proto.verify_split_integrity() is True

    def test_scenario_overlap_detected(self):
        from sentinel_net.evaluation.protocol import EvaluationProtocol
        rng = np.random.RandomState(42)
        X = rng.randn(30, FEATURE_COUNT)
        y = np.array(["benign"] * 30)
        split = DatasetSplit(
            X_train=X[:10], y_train=y[:10],
            X_val=X[10:20], y_val=y[10:20],
            X_test=X[20:], y_test=y[20:],
            train_scenario_ids=["A", "B"],
            val_scenario_ids=["B", "C"],  # B overlaps!
            test_scenario_ids=["D"],
        )
        proto = EvaluationProtocol("test-013")
        proto.register_split(split)
        assert proto.verify_split_integrity() is False


# ─── Threshold Optimizer Tests ────────────────────────────────────────

class TestThresholdOptimizer:
    """Tests for validation-based threshold optimization."""

    def test_search_returns_result(self):
        from sentinel_net.detection.threshold_optimizer import ThresholdOptimizer
        rng = np.random.RandomState(42)
        y = np.array([0] * 80 + [1] * 20)
        scores = rng.rand(100)
        scores[80:] += 0.3
        opt = ThresholdOptimizer(objective="f1")
        result = opt.search(y, scores)
        assert result.data_partition == "validation"
        assert 0.0 < result.optimal_threshold < 1.0
        assert result.objective == "f1"
        assert len(result.candidates) > 0

    def test_partition_label_is_validation(self):
        from sentinel_net.detection.threshold_optimizer import ThresholdOptimizer
        y = np.array([0, 1, 0, 1])
        scores = np.array([0.2, 0.8, 0.3, 0.7])
        result = ThresholdOptimizer().search(y, scores)
        assert result.data_partition == "validation"

    def test_candidates_contain_metrics(self):
        from sentinel_net.detection.threshold_optimizer import ThresholdOptimizer
        y = np.array([0] * 50 + [1] * 50)
        scores = np.linspace(0, 1, 100)
        result = ThresholdOptimizer().search(y, scores)
        for c in result.candidates:
            assert "threshold" in c
            assert "precision" in c
            assert "recall" in c
            assert "f1" in c
            assert "fpr" in c
            assert "fnr" in c


# ─── Calibration Tests ────────────────────────────────────────────────

class TestCalibration:
    """Tests for calibration analysis with score-type discipline."""

    def test_isolation_forest_not_applicable(self):
        from sentinel_net.evaluation.calibration import calibration_analysis
        result = calibration_analysis("isolation_forest", np.array([0, 1]), np.array([0.3, 0.7]))
        assert result.calibration_applicable is False
        assert "anomaly_score" in result.score_type.lower() or "anomaly" in result.inapplicable_reason.lower()

    def test_xgboost_calibration_applicable(self):
        from sentinel_net.evaluation.calibration import calibration_analysis
        y = np.array([0] * 50 + [1] * 50)
        scores = np.random.rand(100)
        result = calibration_analysis("xgboost", y, scores)
        assert result.calibration_applicable is True
        assert result.brier_score is not None
        assert result.expected_calibration_error is not None
        assert len(result.reliability_diagram) == result.n_bins

    def test_brier_score_perfect(self):
        from sentinel_net.evaluation.calibration import compute_brier_score
        y = np.array([0, 0, 1, 1])
        scores = np.array([0.0, 0.0, 1.0, 1.0])
        assert compute_brier_score(y, scores) == 0.0

    def test_brier_score_worst(self):
        from sentinel_net.evaluation.calibration import compute_brier_score
        y = np.array([0, 0, 1, 1])
        scores = np.array([1.0, 1.0, 0.0, 0.0])
        assert compute_brier_score(y, scores) == 1.0

    def test_ece_perfect_calibration(self):
        from sentinel_net.evaluation.calibration import compute_ece
        y = np.array([0] * 50 + [1] * 50)
        # Perfect calibration: P(y=1) matches actual proportion
        scores = np.array([0.0] * 50 + [1.0] * 50)
        ece, diagram = compute_ece(y, scores, n_bins=10)
        assert ece < 0.01  # Should be very close to 0


# ─── Unidirectional Tests ─────────────────────────────────────────────

class TestUnidirectional:
    """Tests for simulated unidirectional feature ablation."""

    def test_reverse_features_identified(self):
        from sentinel_net.evaluation.unidirectional import ALL_AFFECTED_FEATURES, REVERSE_DIRECTION_FEATURES
        # All reverse features must be in FEATURE_SCHEMA
        for feat in REVERSE_DIRECTION_FEATURES:
            assert feat in FEATURE_SCHEMA, f"{feat} not in FEATURE_SCHEMA"
        assert len(ALL_AFFECTED_FEATURES) == 10  # 7 reverse + 3 ratio

    def test_simulate_zeros_reverse_features(self):
        from sentinel_net.evaluation.unidirectional import SimulatedUnidirectionalAblation
        rng = np.random.RandomState(42)
        X = rng.randn(5, FEATURE_COUNT)
        ablation = SimulatedUnidirectionalAblation()
        X_uni = ablation.simulate_unidirectional(X)
        # Reverse indices should be zero
        for idx in ablation.reverse_indices:
            assert np.allclose(X_uni[:, idx], 0.0)
        # Other features unchanged
        non_reverse = [i for i in range(FEATURE_COUNT) if i not in ablation.reverse_indices]
        for idx in non_reverse:
            assert np.allclose(X_uni[:, idx], X[:, idx])

    def test_original_unchanged(self):
        from sentinel_net.evaluation.unidirectional import SimulatedUnidirectionalAblation
        rng = np.random.RandomState(42)
        X = rng.randn(5, FEATURE_COUNT)
        X_orig = X.copy()
        ablation = SimulatedUnidirectionalAblation()
        ablation.simulate_unidirectional(X)
        np.testing.assert_array_equal(X, X_orig)


# ─── Experiments Tests ─────────────────────────────────────────────────

class TestExperiments:
    """Tests for core experiment implementations."""

    def test_experiment_result_serialization(self):
        from sentinel_net.evaluation.experiments import ExperimentResult
        r = ExperimentResult(
            experiment_type="test",
            result_category="software_test",
            model_name="test_model",
            dataset_id="synthetic",
            metrics={"f1": 0.5},
            metadata={"n": 100},
            timestamp="2024-01-01T00:00:00Z",
            notes="Test",
        )
        d = r.to_dict()
        assert d["result_category"] == "software_test"
        assert d["metrics"]["f1"] == 0.5

    def test_class_imbalance_analysis(self):
        from sentinel_net.evaluation.experiments import ClassImbalanceAnalysis
        y_true = np.array(["benign"] * 90 + ["ddos"] * 10)
        y_pred = np.array(["benign"] * 95 + ["ddos"] * 5)
        analysis = ClassImbalanceAnalysis()
        result = analysis.run(y_true, y_pred, y_train=y_true)
        assert result["imbalance_ratio"] == 9.0
        assert "benign" in result["per_class_metrics"]
        assert "ddos" in result["per_class_metrics"]
        assert result["train_distribution"]["benign"]["proportion"] == 0.9

    def test_false_positive_collector(self):
        from sentinel_net.evaluation.experiments import FalsePositiveCollector
        X = np.random.randn(10, FEATURE_COUNT)
        y_true = np.array(["benign"] * 5 + ["ddos"] * 5)
        y_pred = np.array(["ddos"] + ["benign"] * 4 + ["ddos"] * 5)  # 1 FP
        train_mean = np.mean(X, axis=0)
        train_std = np.std(X, axis=0)
        collector = FalsePositiveCollector()
        fps = collector.collect(X, y_true, y_pred, None, list(FEATURE_SCHEMA), train_mean, train_std)
        assert len(fps) == 1
        assert fps[0]["predicted_class"] == "ddos"

    def test_false_negative_collector(self):
        from sentinel_net.evaluation.experiments import FalseNegativeCollector
        X = np.random.randn(10, FEATURE_COUNT)
        y_true = np.array(["benign"] * 5 + ["ddos"] * 5)
        y_pred = np.array(["benign"] * 5 + ["benign"] * 3 + ["ddos"] * 2)  # 3 FN
        collector = FalseNegativeCollector()
        result = collector.collect(X, y_true, y_pred, None, None, 0.5)
        assert result["total_false_negatives"] == 3
        assert result["class_summary"]["ddos"]["miss_rate"] == 0.6


# ─── Feature Ablation Tests ──────────────────────────────────────────

class TestFeatureAblation:
    """Tests for feature ablation framework."""

    def test_feature_groups_cover_all_features(self):
        from sentinel_net.evaluation.ablation import FEATURE_GROUPS
        all_features = set()
        for features in FEATURE_GROUPS.values():
            all_features.update(features)
        schema_set = set(FEATURE_SCHEMA)
        assert all_features == schema_set, f"Missing: {schema_set - all_features}"

    def test_ablation_result_structure(self):
        from sentinel_net.evaluation.ablation import AblationResult
        r = AblationResult(
            group_name="test", features_removed=["a", "b"],
            n_features_remaining=50, full_f1=0.9, ablated_f1=0.7,
            delta_f1=-0.2, full_precision=0.9, ablated_precision=0.7,
            full_recall=0.9, ablated_recall=0.7,
        )
        d = r.to_dict()
        assert d["delta_f1"] == -0.2


# ─── Robustness Tests ────────────────────────────────────────────────

class TestRobustness:
    """Tests for controlled robustness experiments."""

    def test_timing_jitter_changes_iat(self):
        from sentinel_net.evaluation.robustness import timing_jitter
        X = np.ones((5, FEATURE_COUNT))
        X_pert = timing_jitter(X, noise_std=1.0, seed=42)
        iat_indices = [i for i, n in enumerate(FEATURE_SCHEMA) if "iat_" in n]
        assert not np.allclose(X[:, iat_indices], X_pert[:, iat_indices])

    def test_timing_jitter_preserves_other_features(self):
        from sentinel_net.evaluation.robustness import timing_jitter
        X = np.ones((5, FEATURE_COUNT))
        X_pert = timing_jitter(X, noise_std=1.0, seed=42)
        non_iat = [i for i, n in enumerate(FEATURE_SCHEMA) if "iat_" not in n]
        np.testing.assert_array_equal(X[:, non_iat], X_pert[:, non_iat])

    def test_directional_imbalance_zeros_reverse(self):
        from sentinel_net.evaluation.robustness import directional_imbalance
        X = np.ones((5, FEATURE_COUNT))
        X_pert = directional_imbalance(X)
        reverse_indices = [i for i, n in enumerate(FEATURE_SCHEMA)
                          if n.startswith("reverse_") or n.startswith("rev_iat_")]
        assert np.allclose(X_pert[:, reverse_indices], 0.0)

    def test_missing_metadata_fraction(self):
        from sentinel_net.evaluation.robustness import missing_metadata
        X = np.ones((100, FEATURE_COUNT))
        X_pert = missing_metadata(X, drop_fraction=0.5, seed=42)
        zero_fraction = (X_pert == 0.0).mean()
        assert 0.3 < zero_fraction < 0.7  # Should be approximately 0.5


# ─── Failure Taxonomy Tests ──────────────────────────────────────────

class TestFailureTaxonomy:
    """Tests for failure classification."""

    def test_all_failure_codes_defined(self):
        from sentinel_net.evaluation.failure_taxonomy import FAILURE_CODES
        assert len(FAILURE_CODES) == 10
        for code in [f"F{i}" for i in range(1, 11)]:
            assert code in FAILURE_CODES

    def test_threshold_proximity_assigns_f3(self):
        from sentinel_net.evaluation.failure_taxonomy import FailureTaxonomist
        train_mean = np.zeros(FEATURE_COUNT)
        train_std = np.ones(FEATURE_COUNT)
        taxonomist = FailureTaxonomist(train_mean, train_std, {"benign": 100, "ddos": 100}, threshold=0.5)
        x = np.zeros(FEATURE_COUNT)
        failure = taxonomist.classify_failure(0, x, "ddos", "benign", anomaly_score=0.45)
        assert "F3" in failure.failure_codes

    def test_minority_class_assigns_f6(self):
        from sentinel_net.evaluation.failure_taxonomy import FailureTaxonomist
        train_mean = np.zeros(FEATURE_COUNT)
        train_std = np.ones(FEATURE_COUNT)
        # c2 has only 2 samples out of 100
        taxonomist = FailureTaxonomist(train_mean, train_std, {"benign": 90, "ddos": 8, "c2": 2}, threshold=0.5)
        x = np.zeros(FEATURE_COUNT)
        failure = taxonomist.classify_failure(0, x, "c2", "benign", anomaly_score=0.2)
        assert "F6" in failure.failure_codes


# ─── Manifest Tests ──────────────────────────────────────────────────

class TestExperimentManifest:
    """Tests for experiment reproducibility manifests."""

    def test_manifest_records_schema_version(self):
        from sentinel_net.evaluation.protocol import ExperimentManifest
        m = ExperimentManifest(
            experiment_id="test-001", experiment_type="model_comparison",
            dataset_id="synthetic", dataset_hash=None,
            split_strategy="scenario_aware",
            train_scenarios=["A"], val_scenarios=["B"], test_scenarios=["C"],
            random_seed=42, model_name="xgboost", model_version="1.0.0",
            hyperparameters={}, feature_schema_version=FEATURE_SCHEMA_VERSION,
            feature_count=FEATURE_COUNT, preprocessing_config={},
            threshold_config={"anomaly_threshold": 0.5},
            threshold_source="default", timestamp="2024-01-01T00:00:00Z",
            code_version="0.7.0", notes="Test",
        )
        d = m.to_dict()
        assert d["feature_schema_version"] == "2.0.0"
        assert d["feature_count"] == 52
        assert d["threshold_source"] == "default"

    def test_manifest_save_load(self, tmp_path):
        from sentinel_net.evaluation.protocol import ExperimentManifest
        import json
        m = ExperimentManifest(
            experiment_id="test-002", experiment_type="ablation",
            dataset_id="synthetic", dataset_hash=None,
            split_strategy="scenario_aware",
            train_scenarios=[], val_scenarios=[], test_scenarios=[],
            random_seed=42, model_name="rf", model_version="1.0.0",
            hyperparameters={"n_estimators": 100},
            feature_schema_version=FEATURE_SCHEMA_VERSION,
            feature_count=FEATURE_COUNT, preprocessing_config={},
            threshold_config={}, threshold_source="validation_optimized",
            timestamp="2024-01-01", code_version="0.7.0", notes="",
        )
        p = tmp_path / "manifest.json"
        m.save(p)
        with open(p) as f:
            loaded = json.load(f)
        assert loaded["experiment_id"] == "test-002"
        assert loaded["random_seed"] == 42
