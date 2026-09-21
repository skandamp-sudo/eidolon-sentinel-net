"""
Detection failure taxonomy for EIDOLON // SENTINEL-NET.

Classifies detection failures by root cause based on EVIDENCE, not speculation.
This taxonomy is a foundation for future research and system improvement.

Each failure class has a code, description, and criteria for assignment.
Failures are assigned based on observable properties of the misclassified sample.
"""

from dataclasses import dataclass, field
from typing import Any

import numpy as np


# ─── Failure Classification Codes ─────────────────────────────────────

FAILURE_CODES: dict[str, str] = {
    "F1": "Feature representation limitation",
    "F2": "Insufficient directional visibility",
    "F3": "Threshold limitation",
    "F4": "Dataset bias",
    "F5": "Model instability",
    "F6": "Class imbalance",
    "F7": "Out-of-distribution behaviour",
    "F8": "Label ambiguity",
    "F9": "Flow reconstruction limitation",
    "F10": "Explanation limitation",
}


@dataclass
class FailureInstance:
    """A single detection failure with classification."""

    sample_index: int
    true_label: str
    predicted_label: str
    failure_type: str  # 'false_positive' or 'false_negative'
    failure_codes: list[str]  # e.g., ['F3', 'F6']
    anomaly_score: float | None = None
    confidence_score: float | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    notes: str = ""


@dataclass
class FailureTaxonomyReport:
    """Structured failure taxonomy report.

    Failures are classified based on evidence, not speculation.
    """

    total_failures: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    failures_by_code: dict[str, int] = field(default_factory=dict)
    instances: list[FailureInstance] = field(default_factory=list)
    code_definitions: dict[str, str] = field(default_factory=lambda: FAILURE_CODES.copy())
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_failures": self.total_failures,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "failures_by_code": self.failures_by_code,
            "code_definitions": self.code_definitions,
            "n_instances_recorded": len(self.instances),
            "notes": self.notes,
        }


class FailureTaxonomist:
    """Classifies detection failures by root cause.

    Assignment criteria (evidence-based):
        F1 — Feature values for the sample are within normal range for its
             predicted class. The feature representation may not capture the
             distinguishing characteristics.
        F2 — Reverse-direction features are zero or near-zero, and the sample
             is a false negative. Directional visibility may be insufficient.
        F3 — Anomaly score is near the threshold (within 0.1). A different
             threshold might change the outcome.
        F4 — The true class has very few training samples relative to others.
             The model may not have learned this class well.
        F5 — The same sample is classified differently across random seeds.
             Model predictions are unstable for this input.
        F6 — The true class is a minority class (< 5% of training data).
             Class imbalance may affect recall.
        F7 — Feature values are far from training distribution (> 3 sigma).
             The sample may be out-of-distribution.
        F8 — The true label may be ambiguous (e.g., 'other' category).
        F9 — Flow has very few packets (< 3). Flow-level features may be
             unreliable with insufficient packet counts.
        F10 — Explanation evidence is unavailable or inconsistent with
              the prediction.
    """

    def __init__(
        self,
        train_mean: np.ndarray,
        train_std: np.ndarray,
        class_counts: dict[str, int],
        threshold: float = 0.5,
    ) -> None:
        self.train_mean = train_mean
        self.train_std = train_std
        self.train_std[self.train_std == 0] = 1.0
        self.class_counts = class_counts
        self.threshold = threshold
        self.total_train = sum(class_counts.values())

    def classify_failure(
        self,
        sample_index: int,
        x: np.ndarray,
        true_label: str,
        predicted_label: str,
        anomaly_score: float | None = None,
        confidence_score: float | None = None,
    ) -> FailureInstance:
        """Classify a single detection failure by root cause.

        Args:
            sample_index: Index in the test set.
            x: Feature vector (raw, before preprocessing).
            true_label: Ground truth label.
            predicted_label: Model prediction.
            anomaly_score: Anomaly score if available.
            confidence_score: Classification confidence if available.

        Returns:
            FailureInstance with assigned failure codes.
        """
        is_fp = true_label == "benign" and predicted_label != "benign"
        failure_type = "false_positive" if is_fp else "false_negative"
        codes: list[str] = []
        evidence: dict[str, Any] = {}

        # F3: Threshold limitation
        if anomaly_score is not None and abs(anomaly_score - self.threshold) < 0.1:
            codes.append("F3")
            evidence["threshold_proximity"] = abs(anomaly_score - self.threshold)

        # F6: Class imbalance
        true_count = self.class_counts.get(true_label, 0)
        true_proportion = true_count / self.total_train if self.total_train > 0 else 0
        if true_proportion < 0.05:
            codes.append("F6")
            evidence["class_proportion"] = true_proportion
            evidence["class_count"] = true_count

        # F7: Out-of-distribution
        z_scores = np.abs((x - self.train_mean) / self.train_std)
        max_z = float(np.max(z_scores))
        n_extreme = int(np.sum(z_scores > 3.0))
        if n_extreme > 3 or max_z > 5.0:
            codes.append("F7")
            evidence["max_z_score"] = max_z
            evidence["n_features_gt_3sigma"] = n_extreme

        # F2: Insufficient directional visibility
        from sentinel_net.features.schema import FEATURE_SCHEMA
        rev_indices = [
            i for i, name in enumerate(FEATURE_SCHEMA)
            if name.startswith("reverse_") or name.startswith("rev_iat_")
        ]
        if len(rev_indices) > 0 and len(x) > max(rev_indices):
            rev_values = x[rev_indices]
            if np.allclose(rev_values, 0.0, atol=1e-10) and failure_type == "false_negative":
                codes.append("F2")
                evidence["reverse_features_zero"] = True

        # F9: Flow reconstruction limitation
        total_packets_idx = list(FEATURE_SCHEMA).index("total_packets")
        if len(x) > total_packets_idx and x[total_packets_idx] < 3:
            codes.append("F9")
            evidence["total_packets"] = float(x[total_packets_idx])

        # F8: Label ambiguity
        if true_label in ("other", "unknown"):
            codes.append("F8")
            evidence["ambiguous_label"] = true_label

        # F1: Feature representation limitation (fallback if no other code assigned)
        if not codes:
            codes.append("F1")
            evidence["assignment_reason"] = (
                "No specific structural cause identified. "
                "The feature representation may not capture the "
                "distinguishing characteristics for this sample."
            )

        return FailureInstance(
            sample_index=sample_index,
            true_label=true_label,
            predicted_label=predicted_label,
            failure_type=failure_type,
            failure_codes=codes,
            anomaly_score=anomaly_score,
            confidence_score=confidence_score,
            evidence=evidence,
        )

    def build_report(
        self,
        failures: list[FailureInstance],
    ) -> FailureTaxonomyReport:
        """Build a complete failure taxonomy report.

        Args:
            failures: List of classified failure instances.

        Returns:
            FailureTaxonomyReport with aggregate statistics.
        """
        code_counts: dict[str, int] = {code: 0 for code in FAILURE_CODES}
        n_fp = 0
        n_fn = 0

        for f in failures:
            if f.failure_type == "false_positive":
                n_fp += 1
            else:
                n_fn += 1
            for code in f.failure_codes:
                code_counts[code] = code_counts.get(code, 0) + 1

        return FailureTaxonomyReport(
            total_failures=len(failures),
            false_positives=n_fp,
            false_negatives=n_fn,
            failures_by_code=code_counts,
            instances=failures,
            notes=(
                "Failure codes are assigned based on observable properties of "
                "misclassified samples. Multiple codes may apply to a single failure. "
                "F1 (feature representation limitation) is a fallback when no "
                "specific structural cause is identified."
            ),
        )
