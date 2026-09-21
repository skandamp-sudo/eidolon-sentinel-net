#!/usr/bin/env python3
"""
EIDOLON // SENTINEL-NET — Phase 8 Novel Threat & Generalization Hardening
=========================================================================

Evaluates Sentinel-NET's anomaly detector against unseen attack families
using LOAO (Leave-One-Attack-Out) and cascaded fusion.
"""
import json
import time
import logging
import sys
from pathlib import Path
from datetime import datetime, timezone
import numpy as np
from sklearn.metrics import f1_score

# ── Sentinel-NET imports ──
from sentinel_net.features.schema import FEATURE_SCHEMA, FEATURE_COUNT, FEATURE_SCHEMA_VERSION
from sentinel_net.evaluation.adapters import CICIDSAdapter
from sentinel_net.detection.preprocessing import FeaturePreprocessor
from sentinel_net.detection.classifier import XGBoostClassifier
from sentinel_net.detection.anomaly import AnomalyDetector
from sentinel_net.detection.evaluation import ClassificationReport, AnomalyReport
from sentinel_net.detection.threshold_optimizer import ThresholdOptimizer
from sentinel_net.detection.audit import TREE_MODEL_FEATURES
from sentinel_net.evaluation.robustness import (
    RobustnessEvaluator, timing_jitter, packet_size_noise,
    flow_duration_perturbation, directional_imbalance, missing_metadata,
)
from sentinel_net.evaluation.novelty import (
    Phase8Protocol, LeaveOneAttackOut, AttackFamilyFold,
    NoveltyRanking, SupervisedAnomalyFusion, MultiOperatingPointAnalysis,
    CategorizedFPAnalysis
)

# ── Configuration ──
EXPERIMENTS_DIR = Path(__file__).parent / "phase8"
CICIDS_DIR = Path.home() / "Datasets" / "CICIDS2017"
RANDOM_SEED = 42
TIMESTAMP = datetime.now(timezone.utc).isoformat()

EXPERIMENTS_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(EXPERIMENTS_DIR / "phase8.log"),
    ],
)
log = logging.getLogger("phase8")

def save_json(data, path):
    """Save dict/list to JSON, handling numpy types."""
    def convert(obj):
        if isinstance(obj, np.integer): return int(obj)
        if isinstance(obj, np.floating): return float(obj)
        if isinstance(obj, np.ndarray): return obj.tolist()
        if isinstance(obj, np.bool_): return bool(obj)
        if hasattr(obj, 'to_dict'): return obj.to_dict()
        if hasattr(obj, '__dict__'): return obj.__dict__
        return str(obj)
    
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=convert)
    log.info(f"  Saved: {path} ({path.stat().st_size:,} bytes)")


# ═══════════════════════════════════════════════════════════════════════
# EXPERIMENTS
# ═══════════════════════════════════════════════════════════════════════

def run_smoke_test():
    log.info("=" * 70)
    log.info("PHASE 1: PRE-FLIGHT SMOKE TEST")
    log.info("=" * 70)
    
    X_full, labels_full, scenarios_full = CICIDSAdapter.load_all(CICIDS_DIR)
    
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
    
    X_sm = X_full[smoke_indices]
    y_sm = labels_full[smoke_indices]
    s_sm = scenarios_full[smoke_indices]
    
    pp = FeaturePreprocessor(feature_subset=TREE_MODEL_FEATURES, random_state=RANDOM_SEED)
    X_pp = pp.fit_transform(X_sm)
    
    xgb = XGBoostClassifier(n_estimators=10, max_depth=3, random_state=RANDOM_SEED)
    xgb.train(X_pp, y_sm)
    y_pred = xgb.predict(X_pp)
    
    iforest = AnomalyDetector(n_estimators=10, random_state=RANDOM_SEED)
    iforest.train(X_pp[y_sm == "benign"])
    
    loao = LeaveOneAttackOut(random_seed=RANDOM_SEED)
    folds = loao.build_folds(y_sm, s_sm, val_ratio=0.15)
    
    smoke_result = {
        "result_category": "SMOKE_TEST",
        "n_samples": len(X_sm),
        "n_folds": len(folds),
        "status": "PASS",
        "f1_macro": float(f1_score(y_sm, y_pred, average="macro", zero_division=0)),
    }
    save_json(smoke_result, EXPERIMENTS_DIR / "metrics" / "smoke_test.json")
    return X_full, labels_full, scenarios_full


def run_experiment_a(X, labels, scenarios):
    log.info("─── EXPERIMENT A: KNOWN VS UNSEEN (C2 HELD OUT) ───")
    test_scens = ["Botnet-Friday"]
    remaining = sorted(list(set(scenarios) - set(test_scens)))
    rng = np.random.RandomState(RANDOM_SEED)
    rng.shuffle(remaining)
    val_scens = remaining[:1]
    train_scens = remaining[1:]
    
    train_mask = np.isin(scenarios, train_scens)
    val_mask = np.isin(scenarios, val_scens)
    test_mask = np.isin(scenarios, test_scens)
    
    X_tr, y_tr = X[train_mask], labels[train_mask]
    X_v, y_v = X[val_mask], labels[val_mask]
    X_te, y_te = X[test_mask], labels[test_mask]
    
    protocol = Phase8Protocol("exp_a", RANDOM_SEED)
    protocol.register_split(train_scens, val_scens, test_scens, len(y_tr), len(y_v), len(y_te))
    
    pp = FeaturePreprocessor(feature_subset=TREE_MODEL_FEATURES, random_state=RANDOM_SEED)
    X_tr_pp = pp.fit_transform(X_tr)
    X_v_pp = pp.transform(X_v)
    X_te_pp = pp.transform(X_te)
    
    protocol.lock_training(dict(zip(*np.unique(y_tr, return_counts=True))))
    xgb = XGBoostClassifier(n_estimators=100, max_depth=6, random_state=RANDOM_SEED)
    xgb.train(X_tr_pp, y_tr)
    
    iforest = AnomalyDetector(n_estimators=100, random_state=RANDOM_SEED)
    iforest.train(X_tr_pp[y_tr == "benign"])
    
    protocol.lock_validation(dict(zip(*np.unique(y_v, return_counts=True))))
    y_v_bin = (y_v != "benign").astype(int)
    opt_res = ThresholdOptimizer(objective="f1").search(y_v_bin, iforest.score(X_v_pp))
    protocol.lock_threshold(opt_res.optimal_threshold, "validation_optimized")
    
    protocol.lock_test(dict(zip(*np.unique(y_te, return_counts=True))))
    
    y_pred_xgb = xgb.predict(X_te_pp)
    rep_xgb = ClassificationReport.from_predictions(y_te, y_pred_xgb)
    
    test_scores = iforest.score(X_te_pp)
    y_te_bin = (y_te != "benign").astype(int)
    rep_if = AnomalyReport.from_scores(y_te_bin, test_scores, opt_res.optimal_threshold)
    
    metrics = {
        "result_category": "REAL_DATA",
        "attack_prevalence": float(y_te_bin.mean()),
        "supervised_f1_macro": float(rep_xgb.f1_macro),
        "anomaly_f1": float(rep_if.f1_at_threshold),
        "anomaly_precision": float(rep_if.precision_at_threshold),
        "anomaly_recall": float(rep_if.recall_at_threshold),
    }
    protocol.record_evaluation(metrics)
    
    save_json(metrics, EXPERIMENTS_DIR / "metrics" / "known_vs_unseen.json")
    protocol.write_artifact(str(EXPERIMENTS_DIR / "metrics" / "known_vs_unseen.json"))


def run_experiment_b(X, labels, scenarios):
    log.info("─── EXPERIMENT B: LOAO ───")
    loao = LeaveOneAttackOut(random_seed=RANDOM_SEED)
    folds = loao.build_folds(labels, scenarios)
    
    results = {}
    for fold in folds:
        if not fold.feasible:
            results[fold.held_out_family] = fold.to_dict()
            continue
            
        protocol = Phase8Protocol(f"loao_{fold.held_out_family}", RANDOM_SEED)
        protocol.register_split(fold.train_scenarios, fold.val_scenarios, fold.test_scenarios, fold.n_train, fold.n_val, fold.n_test)
        
        X_tr, y_tr, X_v, y_v, X_te, y_te = loao.get_fold_data(X, labels, scenarios, fold)
        assert loao.verify_no_leakage(fold, y_tr)
        
        pp = FeaturePreprocessor(feature_subset=TREE_MODEL_FEATURES, random_state=RANDOM_SEED)
        X_tr_pp = pp.fit_transform(X_tr)
        X_v_pp = pp.transform(X_v)
        X_te_pp = pp.transform(X_te)
        
        protocol.lock_training(fold.train_classes)
        xgb = XGBoostClassifier(n_estimators=100, max_depth=6, random_state=RANDOM_SEED)
        xgb.train(X_tr_pp, y_tr)
        
        iforest = AnomalyDetector(n_estimators=100, random_state=RANDOM_SEED)
        iforest.train(X_tr_pp[y_tr == "benign"])
        
        protocol.lock_validation(fold.val_classes)
        y_v_bin = (y_v != "benign").astype(int)
        opt_res = ThresholdOptimizer(objective="f1").search(y_v_bin, iforest.score(X_v_pp))
        protocol.lock_threshold(opt_res.optimal_threshold, "validation_optimized")
        
        protocol.lock_test(fold.test_classes)
        
        y_pred_xgb = xgb.predict(X_te_pp)
        rep_xgb = ClassificationReport.from_predictions(y_te, y_pred_xgb)
        
        test_scores = iforest.score(X_te_pp)
        y_te_bin = (y_te != "benign").astype(int)
        rep_if = AnomalyReport.from_scores(y_te_bin, test_scores, opt_res.optimal_threshold)
        
        nr = NoveltyRanking().analyze(
            test_scores[y_te == "benign"],
            test_scores[y_te != "benign"]
        )
        
        fold_res = fold.to_dict()
        fold_res.update({
            "threshold": opt_res.optimal_threshold,
            "supervised_f1_macro": float(rep_xgb.f1_macro),
            "supervised_recall_macro": float(rep_xgb.recall_macro),
            "supervised_precision_macro": float(rep_xgb.precision_macro),
            "anomaly_f1": float(rep_if.f1_at_threshold),
            "anomaly_recall": float(rep_if.recall_at_threshold),
            "anomaly_precision": float(rep_if.precision_at_threshold),
            "anomaly_roc_auc": float(rep_if.roc_auc),
            "anomaly_pr_auc": float(rep_if.pr_auc),
            "anomaly_fpr": float(rep_if.fpr_at_threshold),
            "novelty_ranking": nr.to_dict(),
        })
        protocol.record_evaluation(fold_res)
        results[fold.held_out_family] = fold_res
        log.info(f"  {fold.held_out_family}: sup_F1={rep_xgb.f1_macro:.4f} anomaly_F1={rep_if.f1_at_threshold:.4f} ROC-AUC={rep_if.roc_auc:.4f}")
        
    save_json(results, EXPERIMENTS_DIR / "metrics" / "loao_results.json")
    return results


def run_experiment_c(X, labels, scenarios):
    log.info("─── EXPERIMENT C: LOSO ───")
    results = {}
    for sc in np.unique(scenarios):
        test_scens = [sc]
        train_scens = [s for s in np.unique(scenarios) if s != sc]
        
        train_mask = np.isin(scenarios, train_scens)
        test_mask = np.isin(scenarios, test_scens)
        
        X_tr, y_tr = X[train_mask], labels[train_mask]
        X_te, y_te = X[test_mask], labels[test_mask]
        
        pp = FeaturePreprocessor(feature_subset=TREE_MODEL_FEATURES, random_state=RANDOM_SEED)
        X_tr_pp = pp.fit_transform(X_tr)
        X_te_pp = pp.transform(X_te)
        
        xgb = XGBoostClassifier(n_estimators=100, max_depth=6, random_state=RANDOM_SEED)
        xgb.train(X_tr_pp, y_tr)
        
        iforest = AnomalyDetector(n_estimators=100, random_state=RANDOM_SEED)
        iforest.train(X_tr_pp[y_tr == "benign"])
        
        xgb_pred = xgb.predict(X_te_pp)
        rep_xgb = ClassificationReport.from_predictions(y_te, xgb_pred)
        
        if_scores = iforest.score(X_te_pp)
        y_te_bin = (y_te != "benign").astype(int)
        rep_if = AnomalyReport.from_scores(y_te_bin, if_scores, 0.5)
        
        results[sc] = {
            "result_category": "REAL_DATA",
            "attack_prevalence": float(y_te_bin.mean()),
            "xgb_f1_macro": float(rep_xgb.f1_macro),
            "iforest_f1": float(rep_if.f1_at_threshold),
        }
    save_json(results, EXPERIMENTS_DIR / "scenario_holdout" / "loso_results.json")


def run_experiment_d(X, labels, scenarios, loao_results):
    log.info("─── EXPERIMENT D: SUPERVISED VS ANOMALY ───")
    comparison = {"result_category": "REAL_DATA", "families": {}}
    for fam, data in loao_results.items():
        if not isinstance(data, dict) or not data.get("feasible"):
            continue
        comparison["families"][fam] = {
            "attack_prevalence": data.get("attack_prevalence"),
            "supervised": {
                "f1_macro": data.get("supervised_f1_macro"),
                "recall_macro": data.get("supervised_recall_macro"),
                "precision_macro": data.get("supervised_precision_macro"),
            },
            "anomaly": {
                "f1": data.get("anomaly_f1"),
                "recall": data.get("anomaly_recall"),
                "precision": data.get("anomaly_precision"),
                "roc_auc": data.get("anomaly_roc_auc"),
                "pr_auc": data.get("anomaly_pr_auc"),
                "fpr": data.get("anomaly_fpr"),
            },
            "threshold": data.get("threshold"),
        }
    save_json(comparison, EXPERIMENTS_DIR / "metrics" / "supervised_vs_anomaly.json")


def run_experiment_e(X, labels, scenarios, loao_results):
    log.info("─── EXPERIMENT E: THRESHOLD ANALYSIS ───")
    c2_data = loao_results.get("c2")
    if not c2_data or not c2_data.get("feasible"):
        log.info("  Skipped: c2 not feasible in LOAO")
        return
        
    loao = LeaveOneAttackOut(random_seed=RANDOM_SEED)
    folds = loao.build_folds(labels, scenarios)
    c2_fold = next((f for f in folds if f.held_out_family == "c2"), None)
    if c2_fold:
        X_tr, y_tr, X_v, y_v, X_te, y_te = loao.get_fold_data(X, labels, scenarios, c2_fold)
        pp = FeaturePreprocessor(feature_subset=TREE_MODEL_FEATURES, random_state=RANDOM_SEED)
        X_tr_pp = pp.fit_transform(X_tr)
        X_te_pp = pp.transform(X_te)
        
        iforest = AnomalyDetector(n_estimators=100, random_state=RANDOM_SEED)
        iforest.train(X_tr_pp[y_tr == "benign"])
        scores = iforest.score(X_te_pp)
        y_te_bin = (y_te != "benign").astype(int)
        
        mop = MultiOperatingPointAnalysis.analyze(y_te_bin, scores, c2_data.get("threshold", 0.5))
        mop["result_category"] = "REAL_DATA"
        mop["attack_prevalence"] = float(y_te_bin.mean())
        save_json(mop, EXPERIMENTS_DIR / "metrics" / "threshold_analysis.json")


def run_experiment_f(X, labels, scenarios, loao_results):
    log.info("─── EXPERIMENT F: NOVELTY RANKING ───")
    res = {"result_category": "REAL_DATA"}
    for fam, data in loao_results.items():
        if data.get("feasible"):
            nr = data.get("novelty_ranking", {})
            nr["attack_prevalence"] = data.get("attack_prevalence")
            res[fam] = nr
    save_json(res, EXPERIMENTS_DIR / "metrics" / "novelty_ranking.json")


def run_experiment_g(X, labels, scenarios):
    log.info("─── EXPERIMENT G: FUSION ───")
    loao = LeaveOneAttackOut(random_seed=RANDOM_SEED)
    folds = loao.build_folds(labels, scenarios)
    c2_fold = next((f for f in folds if f.held_out_family == "c2"), None)
    if not c2_fold or not c2_fold.feasible:
        log.info("  Skipped: c2 not feasible in LOAO")
        return
        
    X_tr, y_tr, X_v, y_v, X_te, y_te = loao.get_fold_data(X, labels, scenarios, c2_fold)
    pp = FeaturePreprocessor(feature_subset=TREE_MODEL_FEATURES, random_state=RANDOM_SEED)
    X_tr_pp = pp.fit_transform(X_tr)
    X_v_pp = pp.transform(X_v)
    X_te_pp = pp.transform(X_te)
    
    xgb = XGBoostClassifier(n_estimators=100, max_depth=6, random_state=RANDOM_SEED)
    xgb.train(X_tr_pp, y_tr)
    
    iforest = AnomalyDetector(n_estimators=100, random_state=RANDOM_SEED)
    iforest.train(X_tr_pp[y_tr == "benign"])
    
    xgb_pred_v = xgb.predict(X_v_pp)
    xgb_scores_v = xgb.predict_scores(X_v_pp)
    xgb_conf_v = np.max(np.array(list(xgb_scores_v.values())), axis=0)
    
    if_scores_v = iforest.score(X_v_pp)
    
    fusion = SupervisedAnomalyFusion()
    fusion.fit_thresholds(y_v, xgb_pred_v, xgb_conf_v, if_scores_v)
    
    xgb_pred_te = xgb.predict(X_te_pp)
    xgb_scores_te = xgb.predict_scores(X_te_pp)
    xgb_conf_te = np.max(np.array(list(xgb_scores_te.values())), axis=0)
    
    if_scores_te = iforest.score(X_te_pp)
    
    fusion_preds = fusion.predict(xgb_pred_te, xgb_conf_te, if_scores_te)
    eval_res = fusion.evaluate(y_te, fusion_preds, set(np.unique(y_tr)))
    eval_res["result_category"] = "REAL_DATA"
    eval_res["attack_prevalence"] = float((y_te != "benign").mean())
    
    save_json(eval_res, EXPERIMENTS_DIR / "fusion" / "fusion_results.json")


def run_experiment_h(X, labels, scenarios, loao_results):
    log.info("─── EXPERIMENT H: FP ANALYSIS ───")
    c2_data = loao_results.get("c2")
    if not c2_data or not c2_data.get("feasible"):
        log.info("  Skipped: c2 not feasible in LOAO")
        return
        
    loao = LeaveOneAttackOut(random_seed=RANDOM_SEED)
    folds = loao.build_folds(labels, scenarios)
    c2_fold = next(f for f in folds if f.held_out_family == "c2")
    
    X_tr, y_tr, X_v, y_v, X_te, y_te = loao.get_fold_data(X, labels, scenarios, c2_fold)
    pp = FeaturePreprocessor(feature_subset=TREE_MODEL_FEATURES, random_state=RANDOM_SEED)
    X_tr_pp = pp.fit_transform(X_tr)
    X_te_pp = pp.transform(X_te)
    
    iforest = AnomalyDetector(n_estimators=100, random_state=RANDOM_SEED)
    iforest.train(X_tr_pp[y_tr == "benign"])
    
    scores = iforest.score(X_te_pp)
    y_te_bin = (y_te != "benign").astype(int)
    threshold = c2_data["threshold"]
    preds = (scores >= threshold).astype(int)
    
    test_mask = np.isin(scenarios, c2_fold.test_scenarios)
    test_scenarios_aligned = scenarios[test_mask]
    
    fp_res = CategorizedFPAnalysis.analyze(scores, y_te, preds, test_scenarios_aligned, threshold)
    fp_res["result_category"] = "REAL_DATA"
    fp_res["attack_prevalence"] = float(y_te_bin.mean())
    save_json(fp_res, EXPERIMENTS_DIR / "metrics" / "fp_analysis.json")


def run_experiment_i(X, labels, scenarios):
    log.info("─── EXPERIMENT I: ROBUSTNESS ───")
    loao = LeaveOneAttackOut(random_seed=RANDOM_SEED)
    folds = loao.build_folds(labels, scenarios)
    c2_fold = next((f for f in folds if f.held_out_family == "c2"), None)
    if not c2_fold or not c2_fold.feasible:
        log.info("  Skipped: c2 not feasible in LOAO")
        return
        
    X_tr, y_tr, X_v, y_v, X_te, y_te = loao.get_fold_data(X, labels, scenarios, c2_fold)
    pp = FeaturePreprocessor(feature_subset=TREE_MODEL_FEATURES, random_state=RANDOM_SEED)
    X_tr_pp = pp.fit_transform(X_tr)
    
    xgb = XGBoostClassifier(n_estimators=100, max_depth=6, random_state=RANDOM_SEED)
    xgb.train(X_tr_pp, y_tr)
    
    robustness_eval = RobustnessEvaluator()
    X_test_raw = X_te.copy()
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
            X_test_raw, X_perturbed, xgb, pp, perturbation_type=ptype,
        )
        pr_dict = pr.to_dict()
        pr_dict["result_category"] = "ROBUSTNESS"
        pr_dict["attack_prevalence"] = float((y_te != "benign").mean())
        robustness_results[ptype] = pr_dict
    
    save_json(robustness_results, EXPERIMENTS_DIR / "robustness" / "perturbation_results.json")


def run_experiment_j(results):
    log.info("─── EXPERIMENT J: REPRODUCIBILITY MANIFESTS ───")
    import platform
    manifest = {
        "experiment_id": "phase8_complete",
        "result_category": "DOCUMENTATION_ONLY",
        "timestamp": TIMESTAMP,
        "random_seed": RANDOM_SEED,
        "dataset_id": "CICIDS2017",
        "schema_version": FEATURE_SCHEMA_VERSION,
        "feature_count": FEATURE_COUNT,
        "post_preprocessing_features": 41,
        "experiments_completed": sorted(results.keys()),
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "machine": platform.machine(),
        },
        "model_configs": {
            "xgboost": {"n_estimators": 100, "max_depth": 6},
            "isolation_forest": {"n_estimators": 100, "contamination": "auto"},
        },
        "threshold_protocol": "validation_optimized",
        "notes": "Phase 8 - Novel Threat & Generalization Hardening",
    }
    save_json(manifest, EXPERIMENTS_DIR / "manifests" / "phase8_manifest.json")


def main():
    t0 = time.time()
    log.info("=" * 70)
    log.info("EIDOLON // SENTINEL-NET — Phase 8 Execution")
    log.info(f"Timestamp: {TIMESTAMP}")
    log.info(f"Seed: {RANDOM_SEED}")
    log.info("=" * 70)
    
    X, labels, scenarios = run_smoke_test()
    
    run_experiment_a(X, labels, scenarios)
    loao_results = run_experiment_b(X, labels, scenarios)
    run_experiment_c(X, labels, scenarios)
    
    run_experiment_d(X, labels, scenarios, loao_results)
    run_experiment_e(X, labels, scenarios, loao_results)
    run_experiment_f(X, labels, scenarios, loao_results)
    
    run_experiment_g(X, labels, scenarios)
    run_experiment_h(X, labels, scenarios, loao_results)
    run_experiment_i(X, labels, scenarios)
    
    elapsed = time.time() - t0
    run_experiment_j({
        "smoke_test": True,
        "experiment_a": True,
        "experiment_b": True,
        "experiment_c": True,
        "experiment_d": True,
        "experiment_e": True,
        "experiment_f": True,
        "experiment_g": True,
        "experiment_h": True,
        "experiment_i": True,
        "runtime_seconds": round(elapsed, 2),
    })
    
    log.info(f"Phase 8 complete in {elapsed:.1f}s")

if __name__ == "__main__":
    main()
