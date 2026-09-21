import time
import logging
from dataclasses import dataclass
import numpy as np
from sklearn.metrics import (
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
    roc_auc_score,
    precision_recall_curve,
    auc
)

logger = logging.getLogger(__name__)

@dataclass
class ClassificationReport:
    accuracy: float
    precision_macro: float
    recall_macro: float
    f1_macro: float
    precision_weighted: float
    recall_weighted: float
    f1_weighted: float
    confusion_matrix: np.ndarray
    per_class: dict[str, dict[str, float]]
    class_names: list[str]
    roc_auc_ovr: float | None = None
    pr_auc_macro: float | None = None

    @classmethod
    def from_predictions(cls, y_true: np.ndarray, y_pred: np.ndarray, class_names: list[str] | None = None, y_score: dict[str, np.ndarray] | None = None) -> "ClassificationReport":
        accuracy = float(np.mean(y_true == y_pred))
        precision_macro = float(precision_score(y_true, y_pred, average="macro", zero_division=0))
        recall_macro = float(recall_score(y_true, y_pred, average="macro", zero_division=0))
        f1_macro = float(f1_score(y_true, y_pred, average="macro", zero_division=0))
        precision_weighted = float(precision_score(y_true, y_pred, average="weighted", zero_division=0))
        recall_weighted = float(recall_score(y_true, y_pred, average="weighted", zero_division=0))
        f1_weighted = float(f1_score(y_true, y_pred, average="weighted", zero_division=0))
        
        cm = confusion_matrix(y_true, y_pred)
        
        # If class_names not provided, generate string representations of unique labels
        labels = np.unique(np.concatenate((y_true, y_pred)))
        if class_names is None:
            class_names = [str(lbl) for lbl in labels]
            
        report_dict = classification_report(y_true, y_pred, target_names=class_names, output_dict=True, zero_division=0)
        
        per_class = {}
        for i, label in enumerate(labels):
            label_str = class_names[i] if i < len(class_names) else str(label)
            if label_str in report_dict:
                class_metrics = report_dict[label_str].copy()
            else:
                class_metrics = {"precision": 0.0, "recall": 0.0, "f1-score": 0.0, "support": 0}
            
            # Calculate FPR and FNR
            if len(labels) == 2:
                # Binary classification
                tn, fp, fn, tp = cm.ravel()
                fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
                fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0
            else:
                # Multiclass (one-vs-rest calculation for this specific class)
                tp = cm[i, i]
                fp = cm[:, i].sum() - tp
                fn = cm[i, :].sum() - tp
                tn = cm.sum() - (tp + fp + fn)
                fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
                fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0
                
            class_metrics["fpr"] = fpr
            class_metrics["fnr"] = fnr
            per_class[label_str] = class_metrics

        roc_auc_ovr = None
        pr_auc_macro = None
        
        if y_score is not None and class_names is not None:
            try:
                y_score_matrix = np.column_stack([y_score.get(c, np.zeros(len(y_true))) for c in class_names])
                roc_auc_val = roc_auc_score(y_true, y_score_matrix, multi_class="ovr", labels=class_names)
                roc_auc_ovr = None if np.isnan(roc_auc_val) else float(roc_auc_val)
                
                from sklearn.preprocessing import label_binarize
                y_true_bin = label_binarize(y_true, classes=class_names)
                if len(class_names) == 2 and y_true_bin.shape[1] == 1:
                    y_true_bin = np.hstack((1 - y_true_bin, y_true_bin))
                
                pr_aucs = []
                for i in range(len(class_names)):
                    p, r, _ = precision_recall_curve(y_true_bin[:, i], y_score_matrix[:, i])
                    pr_aucs.append(auc(r, p))
                pr_auc_macro = float(np.mean(pr_aucs))
            except ValueError:
                pass

        return cls(
            accuracy=accuracy,
            precision_macro=precision_macro,
            recall_macro=recall_macro,
            f1_macro=f1_macro,
            precision_weighted=precision_weighted,
            recall_weighted=recall_weighted,
            f1_weighted=f1_weighted,
            confusion_matrix=cm,
            per_class=per_class,
            class_names=class_names,
            roc_auc_ovr=roc_auc_ovr,
            pr_auc_macro=pr_auc_macro
        )

    def summary(self) -> str:
        s = f"Accuracy: {self.accuracy:.4f}\n"
        s += f"Macro - Precision: {self.precision_macro:.4f}, Recall: {self.recall_macro:.4f}, F1: {self.f1_macro:.4f}\n"
        s += f"Weighted - Precision: {self.precision_weighted:.4f}, Recall: {self.recall_weighted:.4f}, F1: {self.f1_weighted:.4f}\n"
        return s

@dataclass
class AnomalyReport:
    precision_at_threshold: float
    recall_at_threshold: float
    f1_at_threshold: float
    fpr_at_threshold: float
    threshold: float
    roc_auc: float | None
    pr_auc: float | None

    @classmethod
    def from_scores(cls, y_true_binary: np.ndarray, scores: np.ndarray, threshold: float = 0.5) -> "AnomalyReport":
        y_pred = (scores >= threshold).astype(int)
        
        precision = float(precision_score(y_true_binary, y_pred, zero_division=0))
        recall = float(recall_score(y_true_binary, y_pred, zero_division=0))
        f1 = float(f1_score(y_true_binary, y_pred, zero_division=0))
        
        cm = confusion_matrix(y_true_binary, y_pred, labels=[0, 1])
        if cm.shape == (2, 2):
            tn, fp, fn, tp = cm.ravel()
            fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
        else:
            fpr = 0.0

        try:
            roc_auc_val = float(roc_auc_score(y_true_binary, scores))
            roc_auc = None if np.isnan(roc_auc_val) else roc_auc_val
        except ValueError:
            roc_auc = None

        try:
            p, r, _ = precision_recall_curve(y_true_binary, scores)
            pr_auc = float(auc(r, p))
        except ValueError:
            pr_auc = None

        return cls(
            precision_at_threshold=precision,
            recall_at_threshold=recall,
            f1_at_threshold=f1,
            fpr_at_threshold=fpr,
            threshold=threshold,
            roc_auc=roc_auc,
            pr_auc=pr_auc
        )

@dataclass
class PerformanceReport:
    model_load_time_ms: float
    preprocessing_latency_ms: float
    inference_latency_ms: float
    total_latency_ms: float
    n_samples: int
    latency_per_sample_ms: float

    @classmethod
    def measure(cls, preprocess_fn, predict_fn, X: np.ndarray, n_warmup: int = 3, n_runs: int = 10) -> "PerformanceReport":
        # Warmup
        for _ in range(n_warmup):
            _ = preprocess_fn(X)
            _ = predict_fn(X)

        total_prep = 0.0
        total_inf = 0.0
        
        for _ in range(n_runs):
            t0 = time.perf_counter()
            X_prep = preprocess_fn(X)
            t1 = time.perf_counter()
            _ = predict_fn(X_prep)
            t2 = time.perf_counter()
            
            total_prep += (t1 - t0)
            total_inf += (t2 - t1)

        prep_avg = (total_prep / n_runs) * 1000.0
        inf_avg = (total_inf / n_runs) * 1000.0
        total_avg = prep_avg + inf_avg
        n_samples = X.shape[0] if len(X.shape) > 0 else 1
        
        return cls(
            model_load_time_ms=0.0,
            preprocessing_latency_ms=prep_avg,
            inference_latency_ms=inf_avg,
            total_latency_ms=total_avg,
            n_samples=n_samples,
            latency_per_sample_ms=total_avg / n_samples
        )

def class_imbalance_report(y: np.ndarray) -> dict:
    """Analyze class distribution.
    Returns: {class_name: {count, proportion}} and imbalance_ratio."""
    unique, counts = np.unique(y, return_counts=True)
    total = len(y)
    dist = {}
    for cls_name, count in zip(unique, counts):
        dist[str(cls_name)] = {
            'count': int(count),
            'proportion': float(count) / total
        }
    imbalance_ratio = float(np.max(counts)) / float(np.min(counts)) if len(counts) > 0 and np.min(counts) > 0 else 0.0
    return {
        'distribution': dist,
        'imbalance_ratio': imbalance_ratio
    }
