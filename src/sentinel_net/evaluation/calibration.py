"""
Calibration analysis for EIDOLON // SENTINEL-NET.

SCORE TYPE DISCIPLINE:
    - ANOMALY SCORE (Isolation Forest): NOT a probability. Calibration analysis
      is NOT APPLICABLE. Do not compute Brier score or ECE.
    - CLASSIFICATION SCORE (XGBoost, RF, LogReg): May be evaluated for
      calibration where a probabilistic interpretation is mathematically justified.
    - Logistic Regression with lbfgs solver produces reasonably calibrated outputs.
    - Tree ensemble scores (XGBoost, RF) are typically NOT well-calibrated.

This module never silently converts anomaly scores into probabilities.
"""

from dataclasses import dataclass, field
from typing import Any

import numpy as np


@dataclass
class CalibrationResult:
    """Result of calibration analysis for a single model.

    Attributes:
        model_name: Identifier of the model evaluated.
        score_type: 'classification_score' or 'anomaly_score'.
        calibration_applicable: Whether calibration analysis is mathematically valid.
        inapplicable_reason: Explanation if calibration is not applicable.
        brier_score: Brier score (lower is better). None if not applicable.
        expected_calibration_error: ECE with n_bins bins. None if not applicable.
        n_bins: Number of bins used for ECE and reliability diagram.
        reliability_diagram: List of {bin_center, observed_frequency, predicted_mean, count}.
        n_samples: Number of samples evaluated.
        notes: Additional context.
    """

    model_name: str
    score_type: str
    calibration_applicable: bool
    inapplicable_reason: str = ""
    brier_score: float | None = None
    expected_calibration_error: float | None = None
    n_bins: int = 10
    reliability_diagram: list[dict[str, float]] = field(default_factory=list)
    n_samples: int = 0
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "model_name": self.model_name,
            "score_type": self.score_type,
            "calibration_applicable": self.calibration_applicable,
            "inapplicable_reason": self.inapplicable_reason,
            "brier_score": self.brier_score,
            "expected_calibration_error": self.expected_calibration_error,
            "n_bins": self.n_bins,
            "reliability_diagram": self.reliability_diagram,
            "n_samples": self.n_samples,
            "notes": self.notes,
        }


# Models for which calibration analysis is NOT applicable
_ANOMALY_SCORE_MODELS = frozenset({"isolation_forest"})


def is_calibration_applicable(model_name: str) -> tuple[bool, str]:
    """Determine whether calibration analysis applies to this model's scores.

    Returns:
        (applicable, reason) — reason is empty if applicable.
    """
    if model_name in _ANOMALY_SCORE_MODELS:
        return False, (
            f"Model '{model_name}' produces ANOMALY SCORES, not probabilities. "
            "Calibration analysis (Brier score, ECE, reliability diagrams) is "
            "mathematically inapplicable to anomaly scores."
        )
    return True, ""


def compute_brier_score(y_true_binary: np.ndarray, scores: np.ndarray) -> float:
    """Compute Brier score for binary classification scores.

    Args:
        y_true_binary: Binary ground truth (0 or 1).
        scores: Predicted scores for the positive class.

    Returns:
        Brier score (mean squared error of scores vs labels).
    """
    return float(np.mean((scores - y_true_binary) ** 2))


def compute_ece(
    y_true_binary: np.ndarray,
    scores: np.ndarray,
    n_bins: int = 10,
) -> tuple[float, list[dict[str, float]]]:
    """Compute Expected Calibration Error and reliability diagram data.

    Args:
        y_true_binary: Binary ground truth (0 or 1).
        scores: Predicted scores for the positive class.
        n_bins: Number of equally-spaced bins.

    Returns:
        (ece, reliability_diagram) where reliability_diagram is a list of
        bin dicts with keys: bin_center, observed_frequency, predicted_mean, count.
    """
    bin_edges = np.linspace(0.0, 1.0, n_bins + 1)
    diagram: list[dict[str, float]] = []
    weighted_error = 0.0
    total = len(y_true_binary)

    for i in range(n_bins):
        lo, hi = bin_edges[i], bin_edges[i + 1]
        if i == n_bins - 1:
            mask = (scores >= lo) & (scores <= hi)
        else:
            mask = (scores >= lo) & (scores < hi)

        count = int(mask.sum())
        if count == 0:
            diagram.append({
                "bin_center": float((lo + hi) / 2),
                "observed_frequency": 0.0,
                "predicted_mean": 0.0,
                "count": 0,
            })
            continue

        observed = float(y_true_binary[mask].mean())
        predicted = float(scores[mask].mean())
        weighted_error += (count / total) * abs(observed - predicted)

        diagram.append({
            "bin_center": float((lo + hi) / 2),
            "observed_frequency": observed,
            "predicted_mean": predicted,
            "count": count,
        })

    return float(weighted_error), diagram


def calibration_analysis(
    model_name: str,
    y_true_binary: np.ndarray,
    scores: np.ndarray,
    n_bins: int = 10,
) -> CalibrationResult:
    """Run calibration analysis for a model.

    Checks whether calibration is applicable (based on score type) before
    computing metrics. Isolation Forest anomaly scores are explicitly excluded.

    Args:
        model_name: Model identifier.
        y_true_binary: Binary ground truth (0=benign, 1=threat).
        scores: Model output scores for the positive class.
        n_bins: Number of bins for ECE / reliability diagram.

    Returns:
        CalibrationResult with metrics or inapplicable status.
    """
    applicable, reason = is_calibration_applicable(model_name)

    if not applicable:
        return CalibrationResult(
            model_name=model_name,
            score_type="anomaly_score",
            calibration_applicable=False,
            inapplicable_reason=reason,
            n_samples=len(y_true_binary),
            notes="Calibration analysis skipped — anomaly scores are not probabilities.",
        )

    brier = compute_brier_score(y_true_binary, scores)
    ece, diagram = compute_ece(y_true_binary, scores, n_bins)

    return CalibrationResult(
        model_name=model_name,
        score_type="classification_score",
        calibration_applicable=True,
        brier_score=brier,
        expected_calibration_error=ece,
        n_bins=n_bins,
        reliability_diagram=diagram,
        n_samples=len(y_true_binary),
        notes=(
            "Calibration metrics computed on classification scores. "
            "These scores may or may not be well-calibrated depending on "
            "the model. Logistic Regression typically produces better-calibrated "
            "outputs than tree ensembles."
        ),
    )
"""
"""
