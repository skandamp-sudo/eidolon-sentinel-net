"""
Threshold optimization using validation data.
"""

from dataclasses import dataclass
import numpy as np
from sklearn.metrics import precision_score, recall_score, f1_score

@dataclass
class ThresholdSearchResult:
    """Result of validation-based threshold search."""
    optimal_threshold: float
    objective: str  # 'f1', 'precision', 'recall'
    optimal_score: float
    candidates: list[dict]  # [{threshold, precision, recall, f1, fpr, fnr}]
    data_partition: str  # Must be 'validation'
    n_samples: int

class ThresholdOptimizer:
    """Searches for optimal anomaly threshold using VALIDATION data only.
    
    DESIGN NOTE: The existing ThresholdConfig default (anomaly_threshold=0.5)
    is a design/evaluation limitation, not a software defect. This optimizer
    provides an evaluation capability for comparison, not a production override.
    
    Both default and validation-optimized thresholds should be reported.
    """
    
    def __init__(self, candidates: list[float] | None = None, objective: str = 'f1'):
        if candidates is None:
            self.candidates = list(np.arange(0.1, 0.95, 0.05))
        else:
            self.candidates = candidates
        self.objective = objective
        if self.objective not in ('f1', 'precision', 'recall'):
            raise ValueError("objective must be 'f1', 'precision', or 'recall'")
    
    def search(self, y_true_binary: np.ndarray, anomaly_scores: np.ndarray) -> ThresholdSearchResult:
        """Search threshold candidates on validation data.
        
        Args:
            y_true_binary: Binary labels (0=benign, 1=anomalous) from VALIDATION set.
            anomaly_scores: Anomaly scores (NOT probabilities) from VALIDATION set.
        
        Returns:
            ThresholdSearchResult with optimal threshold and all candidate metrics.
        """
        results = []
        best_score = -1.0
        best_threshold = 0.5
        
        for thresh in self.candidates:
            y_pred = (anomaly_scores >= thresh).astype(int)
            
            precision = float(precision_score(y_true_binary, y_pred, zero_division=0))
            recall = float(recall_score(y_true_binary, y_pred, zero_division=0))
            f1 = float(f1_score(y_true_binary, y_pred, zero_division=0))
            
            # calculate FPR, FNR
            fp = np.sum((y_pred == 1) & (y_true_binary == 0))
            tn = np.sum((y_pred == 0) & (y_true_binary == 0))
            fn = np.sum((y_pred == 0) & (y_true_binary == 1))
            tp = np.sum((y_pred == 1) & (y_true_binary == 1))
            
            fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
            fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0
            
            candidate_metrics = {
                'threshold': float(thresh),
                'precision': precision,
                'recall': recall,
                'f1': f1,
                'fpr': fpr,
                'fnr': fnr
            }
            results.append(candidate_metrics)
            
            score = candidate_metrics[self.objective]
            if score > best_score:
                best_score = score
                best_threshold = float(thresh)
                
        return ThresholdSearchResult(
            optimal_threshold=best_threshold,
            objective=self.objective,
            optimal_score=best_score,
            candidates=results,
            data_partition='validation',
            n_samples=len(y_true_binary)
        )
