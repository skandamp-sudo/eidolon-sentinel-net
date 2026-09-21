#!/usr/bin/env python3
"""
EIDOLON // SENTINEL-NET — Phase 7 Real-Data Scientific Evaluation
=================================================================

CICIDS2017 primary evaluation with locked experimental protocol.

Result categories:
  SMOKE_TEST    — pre-flight validation on small sample
  REAL_DATA     — full CICIDS2017 evaluation
  ABLATION      — controlled feature removal experiments
  ROBUSTNESS    — controlled perturbation experiments

This script DOES NOT modify original datasets.
This script DOES NOT commit artifacts to Git.
"""
import json
import time
import hashlib
import logging
import sys
from pathlib import Path
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict

import numpy as np

# ── Sentinel-NET imports ──
from sentinel_net.features.schema import FEATURE_SCHEMA, FEATURE_COUNT, FEATURE_SCHEMA_VERSION
from sentinel_net.evaluation.adapters import (
    CICIDSAdapter, UNSWAdapter,
    get_cicids_availability_summary, get_unsw_availability_summary,
)
from sentinel_net.detection.dataset import DatasetBuilder, DatasetSplit, LabelMapper
from sentinel_net.detection.preprocessing import FeaturePreprocessor
from sentinel_net.detection.classifier import (
    XGBoostClassifier, RandomForestBaseline, LogisticRegressionBaseline,
)
from sentinel_net.detection.anomaly import AnomalyDetector
from sentinel_net.detection.evaluation import ClassificationReport, AnomalyReport
from sentinel_net.detection.threshold_optimizer import ThresholdOptimizer
from sentinel_net.detection.audit import TREE_MODEL_FEATURES, LINEAR_MODEL_FEATURES
from sentinel_net.evaluation.protocol import EvaluationProtocol, ExperimentManifest
from sentinel_net.evaluation.experiments import (
    ModelComparison, ClassImbalanceAnalysis,
    FalsePositiveCollector, FalseNegativeCollector,
    CrossScenarioHoldout, ModelStability, ExperimentResult,
)
from sentinel_net.evaluation.ablation import FeatureAblation, FEATURE_GROUPS
from sentinel_net.evaluation.robustness import (
    RobustnessEvaluator, timing_jitter, packet_size_noise,
    flow_duration_perturbation, directional_imbalance, missing_metadata,
)
from sentinel_net.evaluation.calibration import calibration_analysis, is_calibration_applicable
from sentinel_net.evaluation.unidirectional import SimulatedUnidirectionalAblation

# ── Configuration ──
EXPERIMENTS_DIR = Path(__file__).parent
CICIDS_DIR = Path.home() / "Datasets" / "CICIDS2017"
UNSW_DIR = Path.home() / "Datasets" / "UNSW-NB15"
RANDOM_SEED = 42
TIMESTAMP = datetime.now(timezone.utc).isoformat()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(EXPERIMENTS_DIR / "evaluation.log"),
    ],
)
log = logging.getLogger("phase7")


def save_json(data, path):
    """Save dict/list to JSON, handling numpy types."""
    def convert(obj):
        if isinstance(obj, np.integer):
            return int(obj)
        if isinstance(obj, np.floating):
            return float(obj)
        if isinstance(obj, np.ndarray):
            return obj.tolist()
        if isinstance(obj, np.bool_):
            return bool(obj)
        if isinstance(obj, (np.str_, bytes)):
            return str(obj)
        if hasattr(obj, 'to_dict'):
            return obj.to_dict()
        if hasattr(obj, '__dict__'):
            return obj.__dict__
        return str(obj)
    
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=convert)
    log.info(f"  Saved: {path} ({path.stat().st_size:,} bytes)")


# ═══════════════════════════════════════════════════════════════════════
# PHASE 1: SMOKE TEST
# ═══════════════════════════════════════════════════════════════════════

def run_smoke_test():
    """Pre-flight smoke test on deterministic small sample."""
    log.info("=" * 70)
    log.info("PHASE 1: PRE-FLIGHT SMOKE TEST")
    log.info("=" * 70)
    
    # Load a small deterministic sample
    log.info("Loading CICIDS2017 adapter...")
    X_full, labels_full, scenarios_full = CICIDSAdapter.load_all(CICIDS_DIR)
    log.info(f"  Full dataset: {X_full.shape[0]:,} rows, {X_full.shape[1]} features")
    
    # Take deterministic stratified sample (first N are all benign Monday)
    N_SMOKE = 2000
    rng = np.random.RandomState(RANDOM_SEED)
    unique_labels = np.unique(labels_full)
    smoke_indices = []
    per_class = max(N_SMOKE // len(unique_labels), 10)
    for lbl in unique_labels:
        lbl_idx = np.where(labels_full == lbl)[0]
        n_take = min(per_class, len(lbl_idx))
        smoke_indices.extend(rng.choice(lbl_idx, size=n_take, replace=False).tolist())
    smoke_indices = np.array(sorted(smoke_indices[:N_SMOKE]))
    
    X_smoke = X_full[smoke_indices]
    labels_smoke = labels_full[smoke_indices]
    scenarios_smoke = scenarios_full[smoke_indices]
    N_SMOKE = len(smoke_indices)
    
    # Verify adapter output
    assert X_smoke.shape == (N_SMOKE, 52), f"Shape mismatch: {X_smoke.shape}"
    assert X_smoke.dtype == np.float64
    assert len(labels_smoke) == N_SMOKE
    assert (labels_smoke != "unknown").all(), "Found unmapped labels"
    log.info(f"  ✓ Adapter: {N_SMOKE} rows, 52 features, dtype=float64")
    
    # Verify NaN columns match expected missing features
    nan_mask = np.isnan(X_smoke).all(axis=0)
    nan_features = [FEATURE_SCHEMA[i] for i in range(52) if nan_mask[i]]
    expected_missing = [
        "pkt_size_median", "pkt_size_p25", "pkt_size_p75", "pkt_size_p90",
        "iat_median", "syn_ack_count", "ip_version",
        "payload_bytes_total", "forward_payload_bytes",
        "reverse_payload_bytes", "payload_ratio",
    ]
    assert set(nan_features) == set(expected_missing), f"Unexpected NaN: {nan_features}"
    log.info(f"  ✓ Missing features ({len(nan_features)}): correct")
    
    # Preprocessing
    pp = FeaturePreprocessor(feature_subset=TREE_MODEL_FEATURES, random_state=RANDOM_SEED)
    X_pp = pp.fit_transform(X_smoke)
    assert not np.isnan(X_pp).any(), "NaN after preprocessing"
    assert not np.isinf(X_pp).any(), "Inf after preprocessing"
    log.info(f"  ✓ Preprocessing: {X_pp.shape}, no NaN/Inf")
    log.info(f"    Constant features: {pp.constant_features}")
    
    # Model training (small sample, just verifying pipeline)
    xgb = XGBoostClassifier(n_estimators=10, max_depth=3, random_state=RANDOM_SEED)
    xgb.train(X_pp, labels_smoke)
    y_pred = xgb.predict(X_pp)
    scores = xgb.predict_scores(X_pp)
    assert len(y_pred) == N_SMOKE
    log.info(f"  ✓ XGBoost: trained, predicted {len(set(y_pred))} classes")
    
    # Metrics
    report = ClassificationReport.from_predictions(
        labels_smoke, y_pred,
    )
    log.info(f"  ✓ Metrics: F1_macro={report.f1_macro:.4f}")
    
    # Result serialization
    smoke_result = {
        "result_category": "SMOKE_TEST",
        "timestamp": TIMESTAMP,
        "n_samples": N_SMOKE,
        "n_features": 52,
        "n_missing_features": len(nan_features),
        "missing_features": nan_features,
        "labels": sorted(set(labels_smoke.tolist())),
        "scenarios": sorted(set(scenarios_smoke.tolist())),
        "preprocessing": {
            "imputer": "median",
            "scaler": "standard",
            "constant_features": pp.constant_features,
        },
        "model": "xgboost_smoke",
        "f1_macro": float(report.f1_macro),
        "status": "PASS",
        "notes": "Smoke test only — NOT for model selection or threshold tuning.",
    }
    save_json(smoke_result, EXPERIMENTS_DIR / "metrics" / "smoke_test.json")
    log.info("  ✓ Smoke test PASSED")
    
    return X_full, labels_full, scenarios_full


# ═══════════════════════════════════════════════════════════════════════
# PHASE 2: FULL CICIDS2017 EVALUATION
# ═══════════════════════════════════════════════════════════════════════

def run_cicids_evaluation(X, labels, scenarios):
    """Full CICIDS2017 evaluation with locked protocol."""
    log.info("")
    log.info("=" * 70)
    log.info("PHASE 2: CICIDS2017 PRIMARY EVALUATION")
    log.info("=" * 70)
    
    # ── Step 1: Scenario-aware split ──
    log.info("Step 1: Scenario-aware splitting...")
    builder = DatasetBuilder()
    split = builder.scenario_aware_split(
        X, labels, scenarios.tolist(),
        train_ratio=0.7, val_ratio=0.15, test_ratio=0.15,
        random_state=RANDOM_SEED,
    )
    
    train_scens = set(split.provenance.get("train_scenarios", []))
    val_scens = set(split.provenance.get("val_scenarios", []))
    test_scens = set(split.provenance.get("test_scenarios", []))
    
    assert train_scens.isdisjoint(val_scens), "LEAK: train ∩ val"
    assert train_scens.isdisjoint(test_scens), "LEAK: train ∩ test"
    assert val_scens.isdisjoint(test_scens), "LEAK: val ∩ test"
    
    log.info(f"  Train scenarios ({len(train_scens)}): {sorted(train_scens)}")
    log.info(f"  Val scenarios   ({len(val_scens)}):   {sorted(val_scens)}")
    log.info(f"  Test scenarios  ({len(test_scens)}):  {sorted(test_scens)}")
    log.info(f"  Train: {split.X_train.shape[0]:,} | Val: {split.X_val.shape[0] if split.X_val is not None else 0:,} | Test: {split.X_test.shape[0] if split.X_test is not None else 0:,}")
    
    # Class distributions
    train_classes = dict(zip(*np.unique(split.y_train, return_counts=True)))
    log.info(f"  Train class distribution: {train_classes}")
    if split.y_val is not None:
        val_classes = dict(zip(*np.unique(split.y_val, return_counts=True)))
        log.info(f"  Val class distribution:   {val_classes}")
    if split.y_test is not None:
        test_classes = dict(zip(*np.unique(split.y_test, return_counts=True)))
        log.info(f"  Test class distribution:  {test_classes}")
    
    split_info = {
        "train_scenarios": sorted(train_scens),
        "val_scenarios": sorted(val_scens),
        "test_scenarios": sorted(test_scens),
        "train_rows": int(split.X_train.shape[0]),
        "val_rows": int(split.X_val.shape[0]) if split.X_val is not None else 0,
        "test_rows": int(split.X_test.shape[0]) if split.X_test is not None else 0,
        "train_classes": {str(k): int(v) for k, v in train_classes.items()},
        "val_classes": {str(k): int(v) for k, v in val_classes.items()} if split.y_val is not None else {},
        "test_classes": {str(k): int(v) for k, v in test_classes.items()} if split.y_test is not None else {},
        "random_seed": RANDOM_SEED,
        "feature_availability": get_cicids_availability_summary(),
        "missing_features": [FEATURE_SCHEMA[i] for i in range(52) if np.isnan(X[:, i]).all()],
    }
    save_json(split_info, EXPERIMENTS_DIR / "metrics" / "dataset_split.json")
    
    # ── Step 2: Preprocessing ──
    log.info("Step 2: Preprocessing...")
    pp_tree = FeaturePreprocessor(feature_subset=TREE_MODEL_FEATURES, random_state=RANDOM_SEED)
    X_train_tree = pp_tree.fit_transform(split.X_train)
    X_val_tree = pp_tree.transform(split.X_val) if split.X_val is not None else None
    X_test_tree = pp_tree.transform(split.X_test) if split.X_test is not None else None
    
    pp_linear = FeaturePreprocessor(feature_subset=LINEAR_MODEL_FEATURES, random_state=RANDOM_SEED)
    X_train_linear = pp_linear.fit_transform(split.X_train)
    X_val_linear = pp_linear.transform(split.X_val) if split.X_val is not None else None
    X_test_linear = pp_linear.transform(split.X_test) if split.X_test is not None else None
    
    log.info(f"  Tree features: {X_train_tree.shape[1]}, constant: {pp_tree.constant_features}")
    log.info(f"  Linear features: {X_train_linear.shape[1]}, constant: {pp_linear.constant_features}")
    
    # Compute post-preprocessing feature names (imputer strips all-NaN cols)
    def get_surviving_features(pp, feature_subset):
        """Get feature names that survived preprocessing (non-NaN columns)."""
        imp = pp._pipeline.named_steps.get('imputer', None)
        if imp is not None and hasattr(imp, 'statistics_'):
            kept_mask = ~np.isnan(imp.statistics_)
            kept_indices = np.where(kept_mask)[0].tolist()
            return [feature_subset[i] for i in kept_indices]
        return list(feature_subset)
    
    tree_feature_names = get_surviving_features(pp_tree, TREE_MODEL_FEATURES)
    linear_feature_names = get_surviving_features(pp_linear, LINEAR_MODEL_FEATURES)
    
    results = {
        "dataset": "CICIDS2017",
        "result_category": "REAL_DATA",
        "timestamp": TIMESTAMP,
        "split": split_info,
    }
    
    # ── EXPERIMENT A: Baseline Model Evaluation ──
    log.info("")
    log.info("─── EXPERIMENT A: BASELINE MODEL EVALUATION ───")
    
    # Train classifiers on CICIDS2017 train split
    log.info("Training XGBoost...")
    t0 = time.time()
    xgb = XGBoostClassifier(n_estimators=100, max_depth=6, random_state=RANDOM_SEED)
    xgb.train(X_train_tree, split.y_train)
    log.info(f"  XGBoost trained in {time.time()-t0:.1f}s")
    
    log.info("Training Random Forest...")
    t0 = time.time()
    rf = RandomForestBaseline(n_estimators=100, random_state=RANDOM_SEED)
    rf.train(X_train_tree, split.y_train)
    log.info(f"  RF trained in {time.time()-t0:.1f}s")
    
    log.info("Training Logistic Regression...")
    t0 = time.time()
    lr = LogisticRegressionBaseline(max_iter=1000, random_state=RANDOM_SEED)
    lr.train(X_train_linear, split.y_train)
    log.info(f"  LR trained in {time.time()-t0:.1f}s")
    
    log.info("Training Isolation Forest (benign only)...")
    t0 = time.time()
    benign_mask = split.y_train == "benign"
    iforest = AnomalyDetector(n_estimators=100, random_state=RANDOM_SEED)
    iforest.train(X_train_tree[benign_mask])
    log.info(f"  IForest trained in {time.time()-t0:.1f}s on {benign_mask.sum():,} benign samples")
    
    # Evaluate on FINAL TEST
    model_results = {}
    
    for name, model, X_test_pp, X_val_pp in [
        ("XGBoost", xgb, X_test_tree, X_val_tree),
        ("RandomForest", rf, X_test_tree, X_val_tree),
        ("LogisticRegression", lr, X_test_linear, X_val_linear),
    ]:
        log.info(f"  Evaluating {name} on test...")
        y_pred = model.predict(X_test_pp)
        y_scores = model.predict_scores(X_test_pp)
        report = ClassificationReport.from_predictions(
            split.y_test, y_pred,
        )
        model_results[name] = {
            "precision_macro": float(report.precision_macro),
            "recall_macro": float(report.recall_macro),
            "f1_macro": float(report.f1_macro),
            "f1_weighted": float(report.f1_weighted),
            "precision_weighted": float(report.precision_weighted),
            "recall_weighted": float(report.recall_weighted),
            "accuracy": float(report.accuracy),
            "roc_auc_ovr": float(report.roc_auc_ovr) if report.roc_auc_ovr is not None else None,
            "pr_auc_macro": float(report.pr_auc_macro) if report.pr_auc_macro is not None else None,
            "per_class": report.per_class,
            "confusion_matrix": report.confusion_matrix.tolist(),
            "class_names": report.class_names,
            "n_test_samples": int(X_test_pp.shape[0]),
        }
        log.info(f"    {name}: F1_macro={report.f1_macro:.4f}, F1_weighted={report.f1_weighted:.4f}, Prec={report.precision_macro:.4f}, Rec={report.recall_macro:.4f}")
        
        # Save confusion matrix
        save_json(
            {"model": name, "matrix": report.confusion_matrix.tolist(), "classes": report.class_names},
            EXPERIMENTS_DIR / "confusion_matrices" / f"{name.lower()}_confusion.json",
        )
    
    # Isolation Forest — threshold on validation
    log.info("  Evaluating Isolation Forest...")
    
    # ── EXPERIMENT B: THRESHOLD SENSITIVITY ──
    log.info("")
    log.info("─── EXPERIMENT B: THRESHOLD SENSITIVITY ───")
    
    if X_val_tree is not None and split.y_val is not None:
        val_scores_if = iforest.score(X_val_tree)
        y_val_binary = (split.y_val != "benign").astype(int)
        
        optimizer = ThresholdOptimizer(objective="f1")
        threshold_result = optimizer.search(y_val_binary, val_scores_if)
        
        log.info(f"  Threshold search on VALIDATION ({len(y_val_binary):,} samples)")
        log.info(f"  Default threshold: 0.5")
        log.info(f"  Optimal threshold: {threshold_result.optimal_threshold:.4f} (F1={threshold_result.optimal_score:.4f})")
        
        # Lock threshold
        protocol = EvaluationProtocol("cicids2017-iforest", random_seed=RANDOM_SEED)
        protocol.register_split(split)
        protocol.lock_threshold(threshold_result.optimal_threshold, source="validation_optimized")
        
        # Evaluate on FINAL TEST with both thresholds
        test_scores_if = iforest.score(X_test_tree)
        y_test_binary = (split.y_test != "benign").astype(int)
        
        default_report = AnomalyReport.from_scores(y_test_binary, test_scores_if, threshold=0.5)
        optimal_report = AnomalyReport.from_scores(y_test_binary, test_scores_if, threshold=threshold_result.optimal_threshold)
        
        iforest_results = {
            "default_threshold": {
                "threshold": 0.5,
                "precision": float(default_report.precision_at_threshold),
                "recall": float(default_report.recall_at_threshold),
                "f1": float(default_report.f1_at_threshold),
                "fpr": float(default_report.fpr_at_threshold),
                "roc_auc": float(default_report.roc_auc) if default_report.roc_auc is not None else None,
                "pr_auc": float(default_report.pr_auc) if default_report.pr_auc is not None else None,
            },
            "validation_optimized_threshold": {
                "threshold": float(threshold_result.optimal_threshold),
                "precision": float(optimal_report.precision_at_threshold),
                "recall": float(optimal_report.recall_at_threshold),
                "f1": float(optimal_report.f1_at_threshold),
                "fpr": float(optimal_report.fpr_at_threshold),
            },
            "threshold_candidates": threshold_result.candidates,
            "n_val_samples": int(len(y_val_binary)),
            "n_test_samples": int(len(y_test_binary)),
            "calibration": "NOT_APPLICABLE (anomaly scores are not probabilities)",
        }
        model_results["IsolationForest"] = iforest_results
        
        log.info(f"    IForest default (0.5):    F1={default_report.f1_at_threshold:.4f}, Prec={default_report.precision_at_threshold:.4f}, Rec={default_report.recall_at_threshold:.4f}")
        log.info(f"    IForest optimized ({threshold_result.optimal_threshold:.3f}): F1={optimal_report.f1_at_threshold:.4f}, Prec={optimal_report.precision_at_threshold:.4f}, Rec={optimal_report.recall_at_threshold:.4f}")
        
        save_json(iforest_results, EXPERIMENTS_DIR / "metrics" / "threshold_sensitivity.json")
        
        protocol.record_final_evaluation({
            "f1": float(optimal_report.f1_at_threshold),
            "threshold": float(threshold_result.optimal_threshold),
        })
    
    results["experiment_A_model_performance"] = model_results
    save_json(model_results, EXPERIMENTS_DIR / "metrics" / "model_performance.json")
    
    # ── EXPERIMENT C: Feature Ablation (missing features) ──
    log.info("")
    log.info("─── EXPERIMENT C: MISSING FEATURE IMPACT ABLATION ───")
    
    missing_indices = [i for i in range(52) if np.isnan(X[:, i]).all()]
    missing_names = [FEATURE_SCHEMA[i] for i in missing_indices]
    
    # Train with all 52 features (11 are NaN→imputed)
    full_pred = xgb.predict(X_test_tree)
    full_report = ClassificationReport.from_predictions(split.y_test, full_pred)
    
    # For comparison: zero out the 11 missing features explicitly
    # (they're already imputed to median, so this measures if imputed values help)
    X_train_ablated = split.X_train.copy()
    X_test_ablated = split.X_test.copy()
    X_train_ablated[:, missing_indices] = 0.0
    X_test_ablated[:, missing_indices] = 0.0
    
    pp_ablated = FeaturePreprocessor(feature_subset=TREE_MODEL_FEATURES, random_state=RANDOM_SEED)
    X_train_abl_pp = pp_ablated.fit_transform(X_train_ablated)
    X_test_abl_pp = pp_ablated.transform(X_test_ablated)
    
    xgb_abl = XGBoostClassifier(n_estimators=100, max_depth=6, random_state=RANDOM_SEED)
    xgb_abl.train(X_train_abl_pp, split.y_train)
    y_pred_abl = xgb_abl.predict(X_test_abl_pp)
    abl_report = ClassificationReport.from_predictions(split.y_test, y_pred_abl)
    
    missing_ablation = {
        "result_category": "ABLATION",
        "experiment": "missing_feature_impact",
        "description": "Impact of 11 CICIDS2017-unavailable features being NaN vs explicitly zeroed",
        "missing_features": missing_names,
        "full_model_f1_macro": float(full_report.f1_macro),
        "ablated_model_f1_macro": float(abl_report.f1_macro),
        "delta_f1": float(abl_report.f1_macro - full_report.f1_macro),
        "notes": "Both models receive imputed values; ablated model has zeros instead of NaN for missing features.",
    }
    results["experiment_C_missing_ablation"] = missing_ablation
    save_json(missing_ablation, EXPERIMENTS_DIR / "ablation" / "missing_feature_impact.json")
    log.info(f"  Full (NaN→imputed) F1: {full_report.f1_macro:.4f}")
    log.info(f"  Ablated (zeros) F1:    {abl_report.f1_macro:.4f}")
    log.info(f"  Delta: {abl_report.f1_macro - full_report.f1_macro:+.4f}")
    
    # ── EXPERIMENT D: Feature Group Ablation ──
    log.info("")
    log.info("─── EXPERIMENT D: FEATURE GROUP ABLATION ───")
    
    ablation = FeatureAblation(feature_names=tree_feature_names)
    abl_results = ablation.run(
        X_train_tree, split.y_train,
        X_test_tree, split.y_test,
        model_class=XGBoostClassifier,
        random_seed=RANDOM_SEED,
        n_estimators=100, max_depth=6,
    )
    
    group_ablation = []
    for ar in abl_results:
        d = ar.to_dict()
        group_ablation.append(d)
        log.info(f"  {ar.group_name}: full={ar.full_f1:.4f}, ablated={ar.ablated_f1:.4f}, delta={ar.delta_f1:+.4f}")
    
    results["experiment_D_feature_group_ablation"] = group_ablation
    save_json(group_ablation, EXPERIMENTS_DIR / "ablation" / "feature_group_ablation.json")
    
    # ── EXPERIMENT E: False Positive Analysis ──
    log.info("")
    log.info("─── EXPERIMENT E: FALSE POSITIVE ANALYSIS ───")
    
    train_mean = np.nanmean(X_train_tree, axis=0)
    train_std = np.nanstd(X_train_tree, axis=0)
    train_std[train_std == 0] = 1.0  # Avoid div-by-zero
    
    fp_collector = FalsePositiveCollector()
    y_pred_xgb = xgb.predict(X_test_tree)
    xgb_scores = xgb.predict_scores(X_test_tree)
    # Get max confidence
    max_conf = np.zeros(len(y_pred_xgb))
    for cls_name, cls_scores in xgb_scores.items():
        max_conf = np.maximum(max_conf, cls_scores)
    
    fp_results = fp_collector.collect(
        X_test_tree, split.y_test, y_pred_xgb,
        confidence_scores=max_conf,
        feature_names=list(TREE_MODEL_FEATURES),
        train_mean=train_mean,
        train_std=train_std,
        max_samples=100,
    )
    
    actual_fp_count = int(((split.y_test == "benign") & (y_pred_xgb != "benign")).sum())
    total_benign = int((split.y_test == "benign").sum())
    
    fp_summary = {
        "result_category": "REAL_DATA",
        "total_false_positives": actual_fp_count,
        "total_benign_samples": total_benign,
        "fpr": actual_fp_count / max(total_benign, 1),
        "examples": fp_results[:20],
    }
    results["experiment_E_false_positives"] = fp_summary
    save_json(fp_summary, EXPERIMENTS_DIR / "metrics" / "false_positives.json")
    log.info(f"  Total FPs: {actual_fp_count} / {total_benign} benign")
    
    # ── EXPERIMENT F: False Negative Analysis ──
    log.info("")
    log.info("─── EXPERIMENT F: FALSE NEGATIVE ANALYSIS ───")
    
    fn_collector = FalseNegativeCollector()
    fn_results = fn_collector.collect(
        X_test_tree, split.y_test, y_pred_xgb,
        anomaly_scores=None,
        confidence_scores=max_conf,
        threshold=0.5,
        max_samples=100,
    )
    
    results["experiment_F_false_negatives"] = fn_results
    save_json(fn_results, EXPERIMENTS_DIR / "metrics" / "false_negatives.json")
    log.info(f"  Total FNs: {fn_results.get('total_false_negatives', 0)}")
    if 'class_summary' in fn_results:
        for cls, info in fn_results['class_summary'].items():
            log.info(f"    {cls}: {info.get('false_negatives', 0)}/{info.get('total_samples', 0)} missed (rate={info.get('miss_rate', 0):.4f})")
    
    # ── EXPERIMENT G: Simulated Unidirectional ──
    log.info("")
    log.info("─── EXPERIMENT G: SIMULATED UNIDIRECTIONAL ABLATION ───")
    
    uni_ablation = SimulatedUnidirectionalAblation()
    uni_result = uni_ablation.evaluate(
        split.X_test, split.y_test,
        model=xgb, preprocessor=pp_tree,
    )
    
    uni_dict = uni_result.to_dict()
    uni_dict["result_category"] = "ROBUSTNESS"
    uni_dict["label"] = "SIMULATED_UNIDIRECTIONAL_FEATURE_ABLATION"
    results["experiment_G_unidirectional"] = uni_dict
    save_json(uni_dict, EXPERIMENTS_DIR / "robustness" / "simulated_unidirectional.json")
    log.info(f"  Full F1:      {uni_result.full_macro_f1:.4f}")
    log.info(f"  Uni-dir F1:   {uni_result.unidirectional_macro_f1:.4f}")
    log.info(f"  Degradation:  {uni_result.f1_degradation:+.4f}")
    
    # ── EXPERIMENT H: Robustness ──
    log.info("")
    log.info("─── EXPERIMENT H: CONTROLLED ROBUSTNESS ───")
    
    robustness_eval = RobustnessEvaluator()
    X_test_raw = split.X_test.copy()
    robustness_results = {}
    
    perturbations = [
        ("timing_jitter", timing_jitter(X_test_raw, noise_std=0.1, seed=RANDOM_SEED)),
        ("packet_size_noise", packet_size_noise(X_test_raw, noise_std=0.1, seed=RANDOM_SEED)),
        ("flow_duration_perturbation", flow_duration_perturbation(X_test_raw, scale=0.2, seed=RANDOM_SEED)),
        ("directional_imbalance", directional_imbalance(X_test_raw)),
        ("missing_metadata_20pct", missing_metadata(X_test_raw, drop_fraction=0.2, seed=RANDOM_SEED)),
    ]
    
    for ptype, X_perturbed in perturbations:
        pr = robustness_eval.evaluate_perturbation(
            X_test_raw, X_perturbed, xgb, pp_tree, perturbation_type=ptype,
        )
        robustness_results[ptype] = pr.to_dict()
        log.info(f"  {ptype}: {pr.classification_changed_pct:.1f}% changed, mean_score_change={pr.mean_score_change:.4f}")
    
    results["experiment_H_robustness"] = robustness_results
    save_json(robustness_results, EXPERIMENTS_DIR / "robustness" / "perturbation_results.json")
    
    # ── EXPERIMENT I: Cross-Scenario Generalization ──
    log.info("")
    log.info("─── EXPERIMENT I: CROSS-SCENARIO GENERALIZATION ───")
    
    # Use a subsample for speed if dataset is huge
    n_cross = min(len(X), 500_000)
    rng = np.random.RandomState(RANDOM_SEED)
    cross_idx = rng.choice(len(X), size=n_cross, replace=False)
    X_cross = X[cross_idx]
    y_cross = labels[cross_idx]
    s_cross = scenarios[cross_idx]
    
    cross_holdout = CrossScenarioHoldout()
    cross_results = cross_holdout.run(
        X_cross, y_cross, s_cross,
        model_class=XGBoostClassifier,
        preprocessor_class=FeaturePreprocessor,
        random_seed=RANDOM_SEED,
        n_estimators=50, max_depth=6,
    )
    
    results["experiment_I_cross_scenario"] = cross_results
    save_json(cross_results, EXPERIMENTS_DIR / "scenario_holdout" / "cross_scenario.json")
    log.info(f"  F1 mean: {cross_results.get('f1_mean', 0):.4f} ± {cross_results.get('f1_std', 0):.4f}")
    if 'per_scenario' in cross_results:
        for scen, metrics in cross_results['per_scenario'].items():
            log.info(f"    Holdout {scen}: F1={metrics.get('macro_f1', 0):.4f} (n_test={metrics.get('n_test', 0):,})")
    
    # ── EXPERIMENT J: Model Stability ──
    log.info("")
    log.info("─── EXPERIMENT J: MODEL STABILITY ───")
    
    stability = ModelStability()
    stability_result = stability.run(
        X_train_tree, split.y_train,
        X_test_tree, split.y_test,
        model_class=XGBoostClassifier,
        k_seeds=5,
        n_estimators=100, max_depth=6,
    )
    
    results["experiment_J_stability"] = stability_result
    save_json(stability_result, EXPERIMENTS_DIR / "metrics" / "model_stability.json")
    log.info(f"  F1 macro: {stability_result.get('f1_macro', {}).get('mean', 0):.4f} ± {stability_result.get('f1_macro', {}).get('std', 0):.4f}")
    
    # ── Calibration ──
    log.info("")
    log.info("─── CALIBRATION ANALYSIS ───")
    
    calibration_results = {}
    for name, model, X_pp in [
        ("XGBoost", xgb, X_test_tree),
        ("RandomForest", rf, X_test_tree),
        ("LogisticRegression", lr, X_test_linear),
    ]:
        applicable, reason = is_calibration_applicable(name.lower())
        if applicable:
            # Binary calibration: benign vs not-benign
            y_binary = (split.y_test != "benign").astype(int)
            scores = model.predict_scores(X_pp)
            # Get the max non-benign score
            non_benign_scores = np.zeros(len(y_binary))
            for cls_name, cls_scores in scores.items():
                if cls_name != "benign":
                    non_benign_scores = np.maximum(non_benign_scores, cls_scores)
            
            cal = calibration_analysis(name.lower(), y_binary, non_benign_scores)
            calibration_results[name] = cal.to_dict()
            log.info(f"  {name}: Brier={cal.brier_score:.4f}, ECE={cal.expected_calibration_error:.4f}")
        else:
            calibration_results[name] = {"applicable": False, "reason": reason}
            log.info(f"  {name}: {reason}")
    
    # IForest
    applicable, reason = is_calibration_applicable("isolation_forest")
    calibration_results["IsolationForest"] = {"applicable": False, "reason": reason}
    log.info(f"  IsolationForest: NOT APPLICABLE ({reason})")
    
    results["calibration"] = calibration_results
    save_json(calibration_results, EXPERIMENTS_DIR / "calibration" / "calibration_analysis.json")
    
    # ── Class Imbalance Analysis ──
    log.info("")
    log.info("─── CLASS IMBALANCE ANALYSIS ───")
    
    imbalance = ClassImbalanceAnalysis()
    imb_result = imbalance.run(split.y_test, y_pred_xgb, y_train=split.y_train)
    results["class_imbalance"] = imb_result
    save_json(imb_result, EXPERIMENTS_DIR / "metrics" / "class_imbalance.json")
    log.info(f"  Imbalance ratio: {imb_result.get('imbalance_ratio', 0):.1f}")
    
    return results


# ═══════════════════════════════════════════════════════════════════════
# PHASE 3: UNSW-NB15 ANALYSIS
# ═══════════════════════════════════════════════════════════════════════

def run_unsw_analysis():
    """UNSW-NB15 compatibility analysis — NOT direct model evaluation."""
    log.info("")
    log.info("=" * 70)
    log.info("PHASE 3: UNSW-NB15 ANALYSIS")
    log.info("=" * 70)
    
    summary = get_unsw_availability_summary()
    total_available = summary.get("DIRECT", 0) + summary.get("DERIVED", 0) + summary.get("PROXY", 0)
    total_missing = summary.get("MISSING", 0)
    
    log.info(f"  Feature availability: {total_available}/52 available, {total_missing}/52 missing")
    
    # Load and inspect
    X, labels, scenarios = UNSWAdapter.load_all(UNSW_DIR)
    nan_cols = np.isnan(X).all(axis=0)
    nan_count = nan_cols.sum()
    
    log.info(f"  Loaded: {X.shape[0]:,} rows, {X.shape[1]} features")
    log.info(f"  All-NaN columns: {nan_count}")
    log.info(f"  Labels: {sorted(set(labels.tolist()))}")
    log.info(f"  Scenarios: {sorted(set(scenarios.tolist()))}")
    
    # Scientific decision: UNSW-NB15 has 35/52 missing features (67%)
    # Direct evaluation with CICIDS-trained models is NOT scientifically valid
    decision = {
        "result_category": "REAL_DATA",
        "dataset": "UNSW-NB15",
        "total_rows": int(X.shape[0]),
        "features_available": int(total_available),
        "features_missing": int(total_missing),
        "missing_percentage": float(total_missing / 52 * 100),
        "availability_summary": summary,
        "class_distribution": dict(zip(*np.unique(labels, return_counts=True))),
        "scientific_decision": "C",
        "decision_rationale": (
            "UNSW-NB15 has only 17/52 features (33%) mappable to the Sentinel-NET schema. "
            "35 features (67%) are missing due to fundamentally different feature extraction tools "
            "(Argus/Bro vs CICFlowMeter). After imputation, 35 features become constant values, "
            "providing zero discriminative signal. Direct evaluation with CICIDS-trained models "
            "would produce misleading metrics. This is classified as a DOCUMENTATION-ONLY LIMITATION. "
            "Future work: train UNSW-specific model on the 17-feature subset or identify a "
            "scientifically defensible common feature set."
        ),
        "cross_dataset_valid": False,
        "notes": (
            "Decision based on methodological validity, NOT performance optimization. "
            "A model evaluated on 67% constant features cannot produce meaningful metrics."
        ),
    }
    
    save_json(decision, EXPERIMENTS_DIR / "metrics" / "unsw_nb15_analysis.json")
    log.info(f"  Decision: {decision['scientific_decision']} — Documentation-only limitation")
    
    return decision


# ═══════════════════════════════════════════════════════════════════════
# PHASE 4: MANIFESTS & REPORT
# ═══════════════════════════════════════════════════════════════════════

def generate_manifests(results):
    """Generate reproducibility manifests for all experiments."""
    log.info("")
    log.info("─── GENERATING MANIFESTS ───")
    
    manifest = {
        "experiment_id": "phase7-cicids2017-evaluation",
        "experiment_type": "real_data_evaluation",
        "dataset_id": "CICIDS2017",
        "dataset_source": "Kaggle dhoogla/cicids2017 (UNB CIC origin)",
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "feature_count": FEATURE_COUNT,
        "features_available": 41,
        "features_missing": 11,
        "random_seed": RANDOM_SEED,
        "timestamp": TIMESTAMP,
        "code_version": "phase7-evaluation",
        "models": ["XGBoost", "RandomForest", "LogisticRegression", "IsolationForest"],
        "preprocessing": {
            "tree_imputer": "SimpleImputer(median)",
            "tree_scaler": "StandardScaler",
            "tree_schema_features": len(TREE_MODEL_FEATURES),
            "linear_schema_features": len(LINEAR_MODEL_FEATURES),
            "tree_post_preprocessing_features": 41,
            "linear_post_preprocessing_features": 40,
            "note": "Schema features are pre-preprocessing counts. Post-preprocessing counts reflect all-NaN column removal by SimpleImputer.",
        },
        "experiments_run": [
            "A_baseline", "B_threshold", "C_missing_ablation",
            "D_feature_group_ablation", "E_false_positives", "F_false_negatives",
            "G_unidirectional", "H_robustness", "I_cross_scenario",
            "J_stability", "calibration", "class_imbalance",
        ],
    }
    save_json(manifest, EXPERIMENTS_DIR / "manifests" / "evaluation_manifest.json")


# ═══════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════

def main():
    log.info("EIDOLON // SENTINEL-NET — Phase 7 Real-Data Scientific Evaluation")
    log.info(f"Timestamp: {TIMESTAMP}")
    log.info(f"Random seed: {RANDOM_SEED}")
    log.info("")
    
    # Phase 1: Smoke test (also loads full data)
    X_full, labels_full, scenarios_full = run_smoke_test()
    
    # Phase 2: Full CICIDS2017 evaluation
    results = run_cicids_evaluation(X_full, labels_full, scenarios_full)
    
    # Phase 3: UNSW-NB15 analysis
    unsw_results = run_unsw_analysis()
    results["unsw_nb15"] = unsw_results
    
    # Phase 4: Manifests
    generate_manifests(results)
    
    # Save complete results
    save_json(results, EXPERIMENTS_DIR / "reports" / "complete_evaluation.json")
    
    log.info("")
    log.info("=" * 70)
    log.info("EVALUATION COMPLETE")
    log.info("=" * 70)
    log.info(f"Results: {EXPERIMENTS_DIR / 'reports' / 'complete_evaluation.json'}")


if __name__ == "__main__":
    main()
