"""
Experiment runner and report generator for EIDOLON // SENTINEL-NET Phase 7.

Orchestrates all evaluation experiments and produces structured artifacts.
Enforces the locked evaluation protocol.

CLASSIFICATION OF OUTPUTS:
    - SOFTWARE TEST: validates implementation correctness (unit tests, fixtures)
    - SYNTHETIC ROBUSTNESS TEST: controlled perturbations on synthetic data
    - SCIENTIFIC EXPERIMENT: evaluation on real datasets with locked protocol
    - REAL-DATA EVALUATION: results from CICIDS2017/UNSW-NB15 (if available)

This module never fabricates real-data metrics from synthetic fixtures.
"""

import json
import logging
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np

from sentinel_net.detection.anomaly import AnomalyDetector
from sentinel_net.detection.classifier import (
    XGBoostClassifier,
    RandomForestBaseline,
    LogisticRegressionBaseline,
)
from sentinel_net.detection.dataset import DatasetBuilder, DatasetSplit
from sentinel_net.detection.evaluation import ClassificationReport, AnomalyReport
from sentinel_net.detection.preprocessing import FeaturePreprocessor
from sentinel_net.detection.thresholds import ThresholdConfig
from sentinel_net.detection.audit import TREE_MODEL_FEATURES, LINEAR_MODEL_FEATURES
from sentinel_net.features.schema import (
    FEATURE_SCHEMA,
    FEATURE_COUNT,
    FEATURE_SCHEMA_VERSION,
)

logger = logging.getLogger(__name__)


@dataclass
class RunnerConfig:
    """Configuration for the experiment runner."""

    output_dir: Path = field(default_factory=lambda: Path("experiments"))
    random_seed: int = 42
    n_stability_seeds: int = 5
    anomaly_threshold_default: float = 0.5
    run_ablation: bool = True
    run_robustness: bool = True
    run_calibration: bool = True
    run_unidirectional: bool = True
    run_ood: bool = True
    run_stability: bool = True
    run_cross_scenario: bool = True


@dataclass
class ExperimentSuite:
    """Collection of all experiment results.

    Explicitly tracks which results come from real data vs synthetic fixtures.
    """

    data_source: str  # 'real_dataset' | 'synthetic_fixture'
    dataset_id: str
    model_comparison: dict[str, Any] = field(default_factory=dict)
    class_imbalance: dict[str, Any] = field(default_factory=dict)
    false_positives: dict[str, Any] = field(default_factory=dict)
    false_negatives: dict[str, Any] = field(default_factory=dict)
    threshold_sensitivity: dict[str, Any] = field(default_factory=dict)
    feature_ablation: dict[str, Any] = field(default_factory=dict)
    robustness: dict[str, Any] = field(default_factory=dict)
    calibration: dict[str, Any] = field(default_factory=dict)
    unidirectional: dict[str, Any] = field(default_factory=dict)
    ood: dict[str, Any] = field(default_factory=dict)
    cross_scenario: dict[str, Any] = field(default_factory=dict)
    model_stability: dict[str, Any] = field(default_factory=dict)
    failure_taxonomy: dict[str, Any] = field(default_factory=dict)
    explainability_validation: dict[str, Any] = field(default_factory=dict)
    attack_mapping_validation: dict[str, Any] = field(default_factory=dict)
    timestamp: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        # Remove numpy arrays that aren't JSON serializable
        return json.loads(json.dumps(d, default=str))


def create_experiment_directories(base_dir: Path) -> dict[str, Path]:
    """Create structured experiment output directory tree."""
    subdirs = {
        "reports": base_dir / "reports",
        "metrics": base_dir / "metrics",
        "confusion_matrices": base_dir / "confusion_matrices",
        "feature_ablation": base_dir / "feature_ablation",
        "robustness": base_dir / "robustness",
        "calibration": base_dir / "calibration",
        "scenario_holdout": base_dir / "scenario_holdout",
        "manifests": base_dir / "manifests",
    }
    for subdir in subdirs.values():
        subdir.mkdir(parents=True, exist_ok=True)
    return subdirs


def run_synthetic_validation(
    config: RunnerConfig,
    n_samples: int = 200,
    n_classes: int = 4,
) -> ExperimentSuite:
    """Run evaluation framework validation using synthetic fixtures.

    This is a SOFTWARE TEST, not a scientific experiment.
    Results validate implementation correctness, NOT real-world performance.

    Args:
        config: Runner configuration.
        n_samples: Number of synthetic samples.
        n_classes: Number of synthetic classes.

    Returns:
        ExperimentSuite labeled as 'synthetic_fixture'.
    """
    from sentinel_net.evaluation.calibration import calibration_analysis
    from sentinel_net.evaluation.ood import generate_ood_samples, OODAnalyzer
    from sentinel_net.evaluation.failure_taxonomy import FailureTaxonomist

    rng = np.random.RandomState(config.random_seed)
    dirs = create_experiment_directories(config.output_dir)

    suite = ExperimentSuite(
        data_source="synthetic_fixture",
        dataset_id="synthetic_validation",
        timestamp=datetime.now(timezone.utc).isoformat(),
    )

    # Generate synthetic data
    class_names = ["benign", "ddos", "reconnaissance", "c2"][:n_classes]
    X = rng.randn(n_samples, FEATURE_COUNT).astype(np.float64)
    # Make classes slightly separable
    for i, cls in enumerate(class_names):
        mask = np.arange(n_samples) % n_classes == i
        X[mask, i * 3:(i + 1) * 3] += 2.0
    y = np.array([class_names[i % n_classes] for i in range(n_samples)])
    scenarios = np.array([f"scenario_{i % 10}" for i in range(n_samples)])

    # Split
    builder = DatasetBuilder()
    split = builder.scenario_aware_split(X, y, list(scenarios), random_state=config.random_seed)

    if split.X_val is None or split.X_test is None:
        suite.model_comparison = {
            "status": "insufficient_data",
            "notes": "Synthetic fixture too small for 3-way split.",
        }
        return suite

    # Preprocess
    preprocessor = FeaturePreprocessor(random_state=config.random_seed)
    X_train_pp = preprocessor.fit_transform(split.X_train)
    X_val_pp = preprocessor.transform(split.X_val)
    X_test_pp = preprocessor.transform(split.X_test)

    # Train models
    models = {}

    # Anomaly detector (train on benign only)
    benign_mask = split.y_train == "benign"
    if benign_mask.any():
        anomaly = AnomalyDetector(random_state=config.random_seed)
        anomaly.train(X_train_pp[benign_mask])
        models["isolation_forest"] = anomaly

    # XGBoost
    try:
        xgb = XGBoostClassifier(random_state=config.random_seed)
        xgb.train(X_train_pp, split.y_train)
        models["xgboost"] = xgb
    except Exception as e:
        logger.warning(f"XGBoost training failed: {e}")

    # Random Forest
    try:
        rf = RandomForestBaseline(random_state=config.random_seed)
        rf.train(X_train_pp, split.y_train)
        models["random_forest"] = rf
    except Exception as e:
        logger.warning(f"RF training failed: {e}")

    # Logistic Regression (uses LINEAR_MODEL_FEATURES subset)
    try:
        lr_preprocessor = FeaturePreprocessor(
            feature_subset=LINEAR_MODEL_FEATURES,
            random_state=config.random_seed,
        )
        X_train_lr = lr_preprocessor.fit_transform(split.X_train)
        X_val_lr = lr_preprocessor.transform(split.X_val)
        X_test_lr = lr_preprocessor.transform(split.X_test)
        lr = LogisticRegressionBaseline(random_state=config.random_seed)
        lr.train(X_train_lr, split.y_train)
        models["logistic_regression"] = lr
    except Exception as e:
        logger.warning(f"LogReg training failed: {e}")

    # Model comparison
    comparison: dict[str, Any] = {"result_category": "software_test"}
    for name, model in models.items():
        if name == "isolation_forest":
            continue  # Anomaly detector evaluated separately
        if name == "logistic_regression":
            X_eval = X_test_lr
        else:
            X_eval = X_test_pp
        try:
            y_pred = model.predict(X_eval)
            report = ClassificationReport.from_predictions(split.y_test, y_pred)
            comparison[name] = {
                "f1_macro": report.f1_macro,
                "f1_weighted": report.f1_weighted,
                "precision_macro": report.precision_macro,
                "recall_macro": report.recall_macro,
                "accuracy": report.accuracy,
                "per_class": report.per_class,
            }
        except Exception as e:
            comparison[name] = {"error": str(e)}

    suite.model_comparison = comparison

    # Anomaly evaluation
    if "isolation_forest" in models:
        anomaly_model = models["isolation_forest"]
        a_scores = anomaly_model.score(X_test_pp)
        y_binary = (split.y_test != "benign").astype(int)
        a_report = AnomalyReport.from_scores(y_binary, a_scores, config.anomaly_threshold_default)
        suite.threshold_sensitivity = {
            "result_category": "software_test",
            "default_threshold": {
                "threshold": config.anomaly_threshold_default,
                "precision": a_report.precision_at_threshold,
                "recall": a_report.recall_at_threshold,
                "f1": a_report.f1_at_threshold,
                "roc_auc": a_report.roc_auc,
            },
        }

    # Calibration
    if config.run_calibration:
        cal_results: dict[str, Any] = {"result_category": "software_test"}
        for name, model in models.items():
            if name == "isolation_forest":
                # Anomaly scores — calibration NOT APPLICABLE
                cal = calibration_analysis(name, np.array([]), np.array([]))
                cal_results[name] = cal.to_dict()
                continue
            if name == "logistic_regression":
                X_eval = X_test_lr
            else:
                X_eval = X_test_pp
            try:
                scores_dict = model.predict_scores(X_eval)
                # Binary: P(not benign)
                benign_scores = scores_dict.get("benign", np.ones(len(X_eval)))
                threat_scores = 1.0 - benign_scores
                y_binary = (split.y_test != "benign").astype(int)
                cal = calibration_analysis(name, y_binary, threat_scores)
                cal_results[name] = cal.to_dict()
            except Exception as e:
                cal_results[name] = {"error": str(e)}
        suite.calibration = cal_results

    # OOD
    if config.run_ood and "isolation_forest" in models:
        ood_samples = generate_ood_samples(X_train_pp, n_samples_per_type=5, random_seed=config.random_seed)
        analyzer = OODAnalyzer()
        primary_classifier = models.get("xgboost") or models.get("random_forest")
        if primary_classifier:
            ood_result = analyzer.analyze(
                ood_samples, models["isolation_forest"], primary_classifier,
                preprocessor, config.anomaly_threshold_default,
            )
            suite.ood = ood_result.to_dict()

    # Failure taxonomy
    if "xgboost" in models:
        xgb_model = models["xgboost"]
        y_pred = xgb_model.predict(X_test_pp)
        train_mean = np.mean(X_train_pp, axis=0)
        train_std = np.std(X_train_pp, axis=0)
        unique, counts = np.unique(split.y_train, return_counts=True)
        class_counts = dict(zip(unique.tolist(), counts.tolist()))

        taxonomist = FailureTaxonomist(train_mean, train_std, class_counts, config.anomaly_threshold_default)
        failures = []
        for i in range(len(split.y_test)):
            if y_pred[i] != split.y_test[i]:
                a_score = None
                if "isolation_forest" in models:
                    a_score = float(models["isolation_forest"].score(X_test_pp[i:i+1])[0])
                scores = xgb_model.predict_scores(X_test_pp[i:i+1])
                conf = float(scores.get(str(y_pred[i]), np.zeros(1))[0])
                f = taxonomist.classify_failure(
                    i, split.X_test[i], str(split.y_test[i]), str(y_pred[i]),
                    anomaly_score=a_score, confidence_score=conf,
                )
                failures.append(f)
        report = taxonomist.build_report(failures)
        suite.failure_taxonomy = report.to_dict()
        suite.failure_taxonomy["result_category"] = "software_test"

    # Save
    suite_path = dirs["reports"] / "synthetic_validation.json"
    with open(suite_path, "w") as f:
        json.dump(suite.to_dict(), f, indent=2, default=str)

    return suite


def generate_research_report(
    suite: ExperimentSuite,
    output_path: Path,
) -> None:
    """Generate a research-style markdown evaluation report.

    Report structure follows the user's specification.
    Every section clearly states whether results are from real data or
    synthetic fixtures.

    Args:
        suite: Complete experiment results.
        output_path: Path for the markdown report.
    """
    data_label = (
        "REAL-DATA EVALUATION" if suite.data_source == "real_dataset"
        else "SYNTHETIC VALIDATION (software test — not scientific evidence)"
    )

    lines: list[str] = []

    def section(title: str) -> None:
        lines.append(f"\n## {title}\n")

    lines.append("# EIDOLON // SENTINEL-NET — Evaluation Report\n")
    lines.append(f"**Data source**: {data_label}\n")
    lines.append(f"**Dataset**: {suite.dataset_id}\n")
    lines.append(f"**Timestamp**: {suite.timestamp}\n")
    lines.append(f"**Feature schema**: v{FEATURE_SCHEMA_VERSION} ({FEATURE_COUNT} features)\n")

    # Abstract
    section("Abstract")
    if suite.data_source == "synthetic_fixture":
        lines.append(
            "This report documents evaluation framework validation using "
            "synthetic fixtures. Results demonstrate implementation correctness "
            "and do NOT constitute scientific evidence of real-world detection "
            "performance. Real-data evaluation requires CICIDS2017 or UNSW-NB15 "
            "datasets.\n"
        )
    else:
        lines.append(
            "This report documents scientific evaluation of Sentinel-NET's "
            "detection capabilities using real network traffic datasets.\n"
        )

    # Model Comparison
    section("Model Comparison")
    mc = suite.model_comparison
    if mc:
        cat = mc.get("result_category", "unknown")
        lines.append(f"**Result category**: {cat}\n")
        for model_name in ["xgboost", "random_forest", "logistic_regression"]:
            if model_name in mc:
                m = mc[model_name]
                if "error" in m:
                    lines.append(f"### {model_name}\n\nError: {m['error']}\n")
                else:
                    lines.append(f"### {model_name}\n")
                    lines.append(f"- F1 Macro: {m.get('f1_macro', 'N/A'):.4f}\n")
                    lines.append(f"- F1 Weighted: {m.get('f1_weighted', 'N/A'):.4f}\n")
                    lines.append(f"- Precision Macro: {m.get('precision_macro', 'N/A'):.4f}\n")
                    lines.append(f"- Recall Macro: {m.get('recall_macro', 'N/A'):.4f}\n")
    else:
        lines.append("No model comparison data available.\n")

    # Threshold Sensitivity
    section("Threshold Sensitivity")
    ts = suite.threshold_sensitivity
    if ts:
        cat = ts.get("result_category", "unknown")
        lines.append(f"**Result category**: {cat}\n")
        if "default_threshold" in ts:
            dt = ts["default_threshold"]
            lines.append("### Default Threshold\n")
            lines.append(f"- Threshold: {dt.get('threshold', 'N/A')}\n")
            lines.append(f"- Precision: {dt.get('precision', 'N/A')}\n")
            lines.append(f"- Recall: {dt.get('recall', 'N/A')}\n")
            lines.append(f"- F1: {dt.get('f1', 'N/A')}\n")
            roc = dt.get('roc_auc')
            lines.append(f"- ROC-AUC: {roc if roc is not None else 'undefined'}\n")
    else:
        lines.append("No threshold sensitivity data available.\n")

    # Calibration
    section("Calibration")
    cal = suite.calibration
    if cal:
        cat = cal.get("result_category", "unknown")
        lines.append(f"**Result category**: {cat}\n")
        for model_name in ["isolation_forest", "xgboost", "random_forest", "logistic_regression"]:
            if model_name in cal:
                c = cal[model_name]
                lines.append(f"### {model_name}\n")
                if not c.get("calibration_applicable", True):
                    lines.append(f"**NOT APPLICABLE**: {c.get('inapplicable_reason', '')}\n")
                elif "error" in c:
                    lines.append(f"Error: {c['error']}\n")
                else:
                    lines.append(f"- Brier Score: {c.get('brier_score', 'N/A')}\n")
                    lines.append(f"- ECE: {c.get('expected_calibration_error', 'N/A')}\n")

    # Failure Taxonomy
    section("Failure Taxonomy")
    ft = suite.failure_taxonomy
    if ft:
        cat = ft.get("result_category", "unknown")
        lines.append(f"**Result category**: {cat}\n")
        lines.append(f"- Total failures: {ft.get('total_failures', 0)}\n")
        lines.append(f"- False positives: {ft.get('false_positives', 0)}\n")
        lines.append(f"- False negatives: {ft.get('false_negatives', 0)}\n")
        codes = ft.get("failures_by_code", {})
        if codes:
            lines.append("\n| Code | Description | Count |\n")
            lines.append("|------|-------------|-------|\n")
            defs = ft.get("code_definitions", {})
            for code in sorted(codes.keys()):
                desc = defs.get(code, "")
                lines.append(f"| {code} | {desc} | {codes[code]} |\n")

    # OOD
    section("Out-of-Distribution Analysis")
    ood = suite.ood
    if ood:
        lines.append(f"**Result category**: {ood.get('result_category', 'unknown')}\n")
        lines.append(f"- Total OOD samples: {ood.get('n_total', 0)}\n")
        lines.append(f"- Flagged anomalous: {ood.get('n_flagged_anomalous', 0)}\n")
        lines.append(f"- Mean anomaly score: {ood.get('mean_anomaly_score', 'N/A')}\n")
        lines.append(f"\n> {ood.get('notes', '')}\n")

    # Limitations
    section("Limitations")
    lines.append("### Known Limitations\n")
    lines.append("1. **Unidirectional observation**: Sentinel-NET observes passive, ")
    lines.append("potentially unidirectional traffic. Reverse-direction information ")
    lines.append("may be absent, degrading detection of bidirectional attack patterns.\n")
    lines.append("2. **No payload inspection**: All 52 features are metadata-only. ")
    lines.append("Encrypted payload contents are never inspected.\n")
    lines.append("3. **Default thresholds**: The anomaly threshold (0.5) is a design ")
    lines.append("default, not validation-optimized. This is a design/evaluation ")
    lines.append("limitation, not a software defect.\n")
    lines.append("4. **Class imbalance**: Baseline models do not use class weighting. ")
    lines.append("On imbalanced datasets, models may be biased toward the majority class.\n")
    lines.append("5. **Score interpretation**: XGBoost/RF classification scores are ")
    lines.append("NOT calibrated probabilities. Isolation Forest produces anomaly scores, ")
    lines.append("not probabilities.\n")

    if suite.data_source == "synthetic_fixture":
        lines.append("\n### Data Limitation\n")
        lines.append("All results in this report are from synthetic fixtures. ")
        lines.append("They validate implementation correctness but do NOT constitute ")
        lines.append("scientific evidence of real-world detection performance. ")
        lines.append("Real-data evaluation requires CICIDS2017 or UNSW-NB15 datasets.\n")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        f.writelines(lines)
