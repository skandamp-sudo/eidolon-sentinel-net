"""
Core experiment implementations for EIDOLON // SENTINEL-NET Phase 7.

CLASSIFICATION OF RESULTS:
    - SOFTWARE TEST: validates implementation correctness using fixtures
    - SYNTHETIC ROBUSTNESS TEST: controlled perturbations on synthetic data
    - SCIENTIFIC EXPERIMENT: evaluation on real datasets with locked protocol
    - REAL-DATA EVALUATION: results from CICIDS2017/UNSW-NB15

Synthetic fixtures can validate implementation correctness.
They must NOT be presented as evidence of real-world detection performance.
"""

import json
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
from sklearn.metrics import f1_score, precision_score, recall_score

from sentinel_net.detection.evaluation import ClassificationReport


@dataclass
class ExperimentResult:
    """Structured result from a scientific experiment or synthetic test.

    WARNING: Synthetic fixtures validate implementation correctness. They are NOT
    evidence of real-world detection performance.
    """

    experiment_type: str
    result_category: str  # 'real_data_evaluation' | 'synthetic_robustness_test' | 'software_test'
    model_name: str
    dataset_id: str
    metrics: dict[str, Any]
    metadata: dict[str, Any]
    timestamp: str
    notes: str

    def to_dict(self) -> dict:
        return asdict(self)

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2, default=str)


class ModelComparison:
    """Trains and evaluates models on identical partitions.

    Uses TREE_MODEL_FEATURES for tree models, LINEAR_MODEL_FEATURES for LogReg.
    Reports ClassificationReport per model.
    Records which partition is used for each metric.
    """

    def run(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_test: np.ndarray,
        y_test: np.ndarray,
        models: dict,
        dataset_id: str = "unknown",
        result_category: str = "software_test",
    ) -> list[ExperimentResult]:
        """Execute the comparison across provided trained models.

        Args:
            X_train: Training features (for reference statistics).
            y_train: Training labels.
            X_test: Test features (preprocessed).
            y_test: Test labels.
            models: Dict of {model_name: trained_model}.
            dataset_id: Dataset identifier.
            result_category: Category label for results.

        Returns:
            List of ExperimentResult, one per model.
        """
        results = []
        now = datetime.now(timezone.utc).isoformat()

        for name, model in models.items():
            try:
                y_pred = model.predict(X_test)
                scores = model.predict_scores(X_test)
                report = ClassificationReport.from_predictions(
                    y_test, y_pred, y_score=scores,
                )
                metrics = {
                    "f1_macro": report.f1_macro,
                    "f1_weighted": report.f1_weighted,
                    "precision_macro": report.precision_macro,
                    "recall_macro": report.recall_macro,
                    "accuracy": report.accuracy,
                    "roc_auc_ovr": report.roc_auc_ovr,
                    "pr_auc_macro": report.pr_auc_macro,
                    "per_class": report.per_class,
                    "confusion_matrix": report.confusion_matrix.tolist(),
                }
            except Exception as e:
                metrics = {"error": str(e)}

            results.append(ExperimentResult(
                experiment_type="model_comparison",
                result_category=result_category,
                model_name=name,
                dataset_id=dataset_id,
                metrics=metrics,
                metadata={"partition": "test", "n_train": len(y_train), "n_test": len(y_test)},
                timestamp=now,
                notes=f"Model comparison for {name} on partition 'test'.",
            ))

        return results


class ClassImbalanceAnalysis:
    """Analyzes impact of class imbalance on detection metrics.

    Records per-class counts, proportions, precision, recall, F1.
    Reports macro and weighted F1 and the imbalance ratio.
    """

    def run(
        self,
        y_true: np.ndarray,
        y_pred: np.ndarray,
        y_train: np.ndarray | None = None,
    ) -> dict[str, Any]:
        """Calculate class imbalance metrics.

        Args:
            y_true: True labels (test set).
            y_pred: Predicted labels.
            y_train: Training labels for distribution analysis.

        Returns:
            Dict with class distribution and per-class metrics.
        """
        classes = np.unique(np.concatenate([y_true, y_pred]))

        # Training distribution
        train_dist = {}
        if y_train is not None:
            unique, counts = np.unique(y_train, return_counts=True)
            total = len(y_train)
            for cls, cnt in zip(unique, counts):
                train_dist[str(cls)] = {"count": int(cnt), "proportion": float(cnt) / total}
            max_c, min_c = int(counts.max()), int(counts.min())
            imbalance_ratio = max_c / min_c if min_c > 0 else float("inf")
        else:
            imbalance_ratio = 0.0

        # Test distribution
        test_unique, test_counts = np.unique(y_true, return_counts=True)
        test_dist = {}
        for cls, cnt in zip(test_unique, test_counts):
            test_dist[str(cls)] = {"count": int(cnt), "proportion": float(cnt) / len(y_true)}

        # Per-class metrics
        per_class = {}
        for cls in classes:
            cls_mask = y_true == cls
            cls_count = int(cls_mask.sum())
            if cls_count == 0:
                per_class[str(cls)] = {"support": 0, "precision": 0.0, "recall": 0.0, "f1": 0.0}
                continue
            cls_pred_mask = y_pred == cls
            tp = int((cls_mask & cls_pred_mask).sum())
            fp = int((~cls_mask & cls_pred_mask).sum())
            fn = int((cls_mask & ~cls_pred_mask).sum())
            prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
            per_class[str(cls)] = {
                "support": cls_count,
                "precision": prec,
                "recall": rec,
                "f1": f1,
            }

        return {
            "train_distribution": train_dist,
            "test_distribution": test_dist,
            "imbalance_ratio": imbalance_ratio,
            "per_class_metrics": per_class,
            "macro_f1": float(f1_score(y_true, y_pred, average="macro", zero_division=0)),
            "weighted_f1": float(f1_score(y_true, y_pred, average="weighted", zero_division=0)),
            "notes": (
                "Class imbalance analysis. Accuracy alone is misleading on "
                "imbalanced datasets. Per-class recall identifies which threat "
                "classes are under-detected."
            ),
        }


class FalsePositiveCollector:
    """Collects False Positives (benign classified as threat).

    Returns structured list. Does NOT provide causal explanations —
    that would require claims this analysis cannot support.
    Categorizes by most-deviated features (which features are furthest
    from training mean).
    """

    def collect(
        self,
        X: np.ndarray,
        y_true: np.ndarray,
        y_pred: np.ndarray,
        confidence_scores: np.ndarray | None,
        feature_names: list[str],
        train_mean: np.ndarray,
        train_std: np.ndarray,
        max_samples: int = 100,
    ) -> list[dict[str, Any]]:
        """Collect and categorize false positives.

        Args:
            X: Feature matrix (raw, before preprocessing).
            y_true: True labels.
            y_pred: Predicted labels.
            confidence_scores: Confidence per prediction (optional).
            feature_names: Feature names for reporting.
            train_mean: Training set mean per feature.
            train_std: Training set std per feature (0 replaced with 1).
            max_samples: Maximum FPs to record in detail.

        Returns:
            List of FP records with feature deviations.
        """
        std_safe = train_std.copy()
        std_safe[std_safe == 0] = 1.0

        fp_indices = np.where((y_true == "benign") & (y_pred != "benign"))[0]
        records = []

        for idx in fp_indices[:max_samples]:
            z_scores = np.abs((X[idx] - train_mean) / std_safe)
            top_k = 5
            top_indices = np.argsort(z_scores)[-top_k:][::-1]
            top_features = [
                {"feature": feature_names[i], "z_score": float(z_scores[i]), "value": float(X[idx, i])}
                for i in top_indices
            ]

            record: dict[str, Any] = {
                "index": int(idx),
                "predicted_class": str(y_pred[idx]),
                "most_deviated_features": top_features,
            }
            if confidence_scores is not None:
                record["confidence_score"] = float(confidence_scores[idx])
            records.append(record)

        return records


class FalseNegativeCollector:
    """Collects False Negatives (threat classified as benign).

    Records true class, anomaly score, confidence, and reason category.
    Does NOT provide causal explanations.
    """

    def collect(
        self,
        X: np.ndarray,
        y_true: np.ndarray,
        y_pred: np.ndarray,
        anomaly_scores: np.ndarray | None,
        confidence_scores: np.ndarray | None,
        threshold: float,
        max_samples: int = 100,
    ) -> dict[str, Any]:
        """Collect false negatives grouped by true threat class.

        Returns:
            Dict with per-class FN counts and sample details.
        """
        fn_indices = np.where((y_true != "benign") & (y_pred == "benign"))[0]

        by_class: dict[str, list[dict]] = {}
        for idx in fn_indices[:max_samples]:
            true_cls = str(y_true[idx])
            if true_cls not in by_class:
                by_class[true_cls] = []

            record: dict[str, Any] = {"index": int(idx)}
            if anomaly_scores is not None:
                a_score = float(anomaly_scores[idx])
                record["anomaly_score"] = a_score
                record["below_threshold"] = a_score < threshold
            if confidence_scores is not None:
                record["confidence_score"] = float(confidence_scores[idx])
            by_class[true_cls].append(record)

        # Summary
        class_summary = {}
        unique_classes = np.unique(y_true[y_true != "benign"])
        for cls in unique_classes:
            cls_str = str(cls)
            total = int((y_true == cls).sum())
            missed = int(((y_true == cls) & (y_pred == "benign")).sum())
            class_summary[cls_str] = {
                "total_samples": total,
                "false_negatives": missed,
                "miss_rate": missed / total if total > 0 else 0.0,
            }

        return {
            "total_false_negatives": len(fn_indices),
            "by_class": {k: v[:10] for k, v in by_class.items()},  # Limit detail
            "class_summary": class_summary,
            "notes": (
                "False negatives are threat samples classified as benign. "
                "High miss rate for a class indicates the model struggles "
                "to detect that threat type."
            ),
        }


class CrossScenarioHoldout:
    """Evaluates generalization across network scenarios.

    For each unique scenario: train on all others, evaluate on held-out.
    Reports per-scenario metrics and variance.
    Verifies scenario-level disjointness.
    """

    def run(
        self,
        X: np.ndarray,
        y: np.ndarray,
        scenarios: np.ndarray,
        model_class: Any,
        preprocessor_class: Any,
        random_seed: int = 42,
        **model_kwargs: Any,
    ) -> dict[str, Any]:
        """Run leave-one-scenario-out evaluation.

        Args:
            X: Full feature matrix (raw).
            y: Full label array.
            scenarios: Scenario ID per sample.
            model_class: Uninstantiated model class.
            preprocessor_class: Uninstantiated preprocessor class.
            random_seed: For reproducibility.

        Returns:
            Dict with per-scenario metrics and variance.
        """
        unique_scenarios = np.unique(scenarios)
        if len(unique_scenarios) < 2:
            return {
                "status": "insufficient_scenarios",
                "notes": f"Only {len(unique_scenarios)} scenario(s). Need ≥2 for holdout.",
            }

        results_per_scenario: dict[str, dict] = {}
        f1_scores: list[float] = []

        for held_out in unique_scenarios:
            held_out_str = str(held_out)
            train_mask = scenarios != held_out
            test_mask = scenarios == held_out

            X_train, y_train = X[train_mask], y[train_mask]
            X_test, y_test = X[test_mask], y[test_mask]

            if len(np.unique(y_train)) < 2 or len(y_test) == 0:
                results_per_scenario[held_out_str] = {"status": "skipped", "reason": "insufficient classes or samples"}
                continue

            try:
                pp = preprocessor_class(random_state=random_seed)
                X_tr_pp = pp.fit_transform(X_train)
                X_te_pp = pp.transform(X_test)

                model = model_class(random_state=random_seed, **model_kwargs)
                model.train(X_tr_pp, y_train)
                y_pred = model.predict(X_te_pp)

                macro_f1 = float(f1_score(y_test, y_pred, average="macro", zero_division=0))
                weighted_f1 = float(f1_score(y_test, y_pred, average="weighted", zero_division=0))
                prec = float(precision_score(y_test, y_pred, average="macro", zero_division=0))
                rec = float(recall_score(y_test, y_pred, average="macro", zero_division=0))

                results_per_scenario[held_out_str] = {
                    "n_train": int(train_mask.sum()),
                    "n_test": int(test_mask.sum()),
                    "macro_f1": macro_f1,
                    "weighted_f1": weighted_f1,
                    "precision_macro": prec,
                    "recall_macro": rec,
                }
                f1_scores.append(macro_f1)
            except Exception as e:
                results_per_scenario[held_out_str] = {"status": "error", "message": str(e)}

        return {
            "per_scenario": results_per_scenario,
            "f1_mean": float(np.mean(f1_scores)) if f1_scores else None,
            "f1_std": float(np.std(f1_scores)) if f1_scores else None,
            "f1_min": float(np.min(f1_scores)) if f1_scores else None,
            "f1_max": float(np.max(f1_scores)) if f1_scores else None,
            "n_scenarios": len(unique_scenarios),
            "notes": (
                "Cross-scenario holdout: train on N-1 scenarios, test on held-out. "
                "High variance indicates scenario-dependent performance."
            ),
        }


class ModelStability:
    """Evaluates model stability across random initializations.

    Trains same model with K different random seeds.
    Reports metric variance and feature importance variance.
    If variance is high: documents as model limitation.
    """

    def run(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_test: np.ndarray,
        y_test: np.ndarray,
        model_class: Any,
        k_seeds: int = 5,
        **model_kwargs: Any,
    ) -> dict[str, Any]:
        """Run stability evaluation across random seeds.

        Args:
            X_train: Preprocessed training features.
            y_train: Training labels.
            X_test: Preprocessed test features.
            y_test: Test labels.
            model_class: Uninstantiated model class.
            k_seeds: Number of seeds to test.

        Returns:
            Dict with metric mean/std across seeds.
        """
        f1_scores = []
        precision_scores = []
        recall_scores = []
        seeds = list(range(42, 42 + k_seeds))

        for seed in seeds:
            try:
                model = model_class(random_state=seed, **model_kwargs)
                model.train(X_train, y_train)
                y_pred = model.predict(X_test)

                f1_scores.append(float(f1_score(y_test, y_pred, average="macro", zero_division=0)))
                precision_scores.append(float(precision_score(y_test, y_pred, average="macro", zero_division=0)))
                recall_scores.append(float(recall_score(y_test, y_pred, average="macro", zero_division=0)))
            except Exception as e:
                continue

        if not f1_scores:
            return {"status": "all_seeds_failed"}

        return {
            "n_seeds": len(f1_scores),
            "seeds": seeds[:len(f1_scores)],
            "f1_macro": {
                "mean": float(np.mean(f1_scores)),
                "std": float(np.std(f1_scores)),
                "min": float(np.min(f1_scores)),
                "max": float(np.max(f1_scores)),
                "values": f1_scores,
            },
            "precision_macro": {
                "mean": float(np.mean(precision_scores)),
                "std": float(np.std(precision_scores)),
            },
            "recall_macro": {
                "mean": float(np.mean(recall_scores)),
                "std": float(np.std(recall_scores)),
            },
            "notes": (
                "Model stability across random seeds. High std indicates "
                "model instability — predictions depend on initialization."
            ),
        }
