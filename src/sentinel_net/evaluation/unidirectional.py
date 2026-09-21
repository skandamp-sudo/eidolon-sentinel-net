"""
SIMULATED UNIDIRECTIONAL FEATURE ABLATION for EIDOLON // SENTINEL-NET.

This experiment simulates loss of reverse-direction telemetry by
zeroing reverse-direction feature values. It is NOT equivalent to
collecting naturally unidirectional traffic.

Real unidirectional observation would produce fundamentally different
flow aggregation behaviour:
    - No reverse-packet counting at all
    - No bidirectional IAT computation
    - Different ratio calculations (undefined, not zero)
    - Different flow key construction

This experiment measures: how much does the model depend on
reverse-direction information?

Compare:
    A. Full bidirectional features
    B. Simulated loss of reverse telemetry (this experiment)
    C. Real unidirectional observation (separate, only if real data exists)

Do not fabricate C if no real data exists.
"""

from dataclasses import dataclass, field
from typing import Any

import numpy as np
from sklearn.metrics import f1_score, precision_score, recall_score

from sentinel_net.features.schema import FEATURE_SCHEMA


# Features that represent reverse-direction information
REVERSE_DIRECTION_FEATURES: tuple[str, ...] = (
    "reverse_packets",
    "reverse_bytes",
    "rev_iat_mean",
    "rev_iat_std",
    "rev_iat_min",
    "rev_iat_max",
    "reverse_payload_bytes",
)

# Ratio features that depend on reverse-direction data
RATIO_FEATURES_AFFECTED: tuple[str, ...] = (
    "fwd_rev_packet_ratio",
    "fwd_rev_byte_ratio",
    "payload_ratio",
)

# Combined set: all features affected by loss of reverse telemetry
ALL_AFFECTED_FEATURES: tuple[str, ...] = REVERSE_DIRECTION_FEATURES + RATIO_FEATURES_AFFECTED


@dataclass
class UnidirectionalResult:
    """Results from Simulated Unidirectional Feature Ablation.

    This is a SIMULATED experiment, not real unidirectional observation.
    """

    result_category: str = "synthetic_robustness_test"
    dataset_size: int = 0
    full_macro_f1: float = 0.0
    full_precision: float = 0.0
    full_recall: float = 0.0
    unidirectional_macro_f1: float = 0.0
    unidirectional_precision: float = 0.0
    unidirectional_recall: float = 0.0
    f1_degradation: float = 0.0
    per_class_full: dict[str, dict[str, float]] = field(default_factory=dict)
    per_class_unidirectional: dict[str, dict[str, float]] = field(default_factory=dict)
    per_class_degradation: dict[str, float] = field(default_factory=dict)
    features_zeroed: list[str] = field(default_factory=list)
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "result_category": self.result_category,
            "dataset_size": self.dataset_size,
            "full_macro_f1": self.full_macro_f1,
            "full_precision": self.full_precision,
            "full_recall": self.full_recall,
            "unidirectional_macro_f1": self.unidirectional_macro_f1,
            "unidirectional_precision": self.unidirectional_precision,
            "unidirectional_recall": self.unidirectional_recall,
            "f1_degradation": self.f1_degradation,
            "per_class_degradation": self.per_class_degradation,
            "features_zeroed": self.features_zeroed,
            "notes": self.notes,
        }


class SimulatedUnidirectionalAblation:
    """SIMULATED UNIDIRECTIONAL FEATURE ABLATION.

    This experiment simulates loss of reverse-direction telemetry by
    zeroing reverse-direction feature values. It is NOT equivalent to
    collecting naturally unidirectional traffic.

    Real unidirectional observation would produce fundamentally different
    flow aggregation behaviour (no reverse-packet counting, no
    bidirectional IAT computation, different ratio calculations).

    This experiment measures: how much does the model depend on
    reverse-direction information?

    Compare:
        A. Full bidirectional features
        B. Simulated loss of reverse telemetry (this experiment)
        C. Real unidirectional observation (separate, only if real data exists)
    """

    def __init__(self, feature_names: list[str] | None = None):
        if feature_names is None:
            self.feature_names = list(FEATURE_SCHEMA)
        else:
            self.feature_names = feature_names
        self.reverse_indices = [
            i for i, name in enumerate(self.feature_names)
            if name in ALL_AFFECTED_FEATURES
        ]
        self.features_zeroed = [
            self.feature_names[i] for i in self.reverse_indices
        ]

    def simulate_unidirectional(self, X: np.ndarray) -> np.ndarray:
        """Zero all reverse-direction and affected ratio features.

        Returns a copy with reverse-direction features set to zero.
        This simulates complete loss of reverse telemetry, NOT real
        unidirectional observation.
        """
        X_uni = X.copy()
        if self.reverse_indices:
            X_uni[:, self.reverse_indices] = 0.0
        return X_uni

    def evaluate(
        self,
        X_test: np.ndarray,
        y_test: np.ndarray,
        model: Any,
        preprocessor: Any,
    ) -> UnidirectionalResult:
        """Compare full vs simulated-unidirectional detection.

        Args:
            X_test: Raw test features (before preprocessing).
            y_test: True test labels.
            model: Trained classifier with predict().
            preprocessor: Fitted preprocessor with transform().

        Returns:
            UnidirectionalResult with per-class degradation metrics.
        """
        # A: Full bidirectional
        X_full_pp = preprocessor.transform(X_test)
        y_pred_full = model.predict(X_full_pp)

        full_f1 = float(f1_score(y_test, y_pred_full, average="macro", zero_division=0))
        full_prec = float(precision_score(y_test, y_pred_full, average="macro", zero_division=0))
        full_rec = float(recall_score(y_test, y_pred_full, average="macro", zero_division=0))

        # B: Simulated unidirectional
        X_uni = self.simulate_unidirectional(X_test)
        X_uni_pp = preprocessor.transform(X_uni)
        y_pred_uni = model.predict(X_uni_pp)

        uni_f1 = float(f1_score(y_test, y_pred_uni, average="macro", zero_division=0))
        uni_prec = float(precision_score(y_test, y_pred_uni, average="macro", zero_division=0))
        uni_rec = float(recall_score(y_test, y_pred_uni, average="macro", zero_division=0))

        # Per-class metrics
        classes = np.unique(y_test)
        per_class_full: dict[str, dict[str, float]] = {}
        per_class_uni: dict[str, dict[str, float]] = {}
        per_class_deg: dict[str, float] = {}

        for cls in classes:
            cls_str = str(cls)
            cls_mask = y_test == cls
            if cls_mask.sum() == 0:
                continue

            # Full
            cls_pred_full = y_pred_full[cls_mask]
            cls_rec_full = float((cls_pred_full == cls).sum()) / float(cls_mask.sum())
            per_class_full[cls_str] = {"recall": cls_rec_full, "support": int(cls_mask.sum())}

            # Unidirectional
            cls_pred_uni = y_pred_uni[cls_mask]
            cls_rec_uni = float((cls_pred_uni == cls).sum()) / float(cls_mask.sum())
            per_class_uni[cls_str] = {"recall": cls_rec_uni, "support": int(cls_mask.sum())}

            per_class_deg[cls_str] = cls_rec_uni - cls_rec_full

        return UnidirectionalResult(
            dataset_size=len(y_test),
            full_macro_f1=full_f1,
            full_precision=full_prec,
            full_recall=full_rec,
            unidirectional_macro_f1=uni_f1,
            unidirectional_precision=uni_prec,
            unidirectional_recall=uni_rec,
            f1_degradation=uni_f1 - full_f1,
            per_class_full=per_class_full,
            per_class_unidirectional=per_class_uni,
            per_class_degradation=per_class_deg,
            features_zeroed=self.features_zeroed,
            notes=(
                "SIMULATED UNIDIRECTIONAL FEATURE ABLATION. "
                "This experiment simulates loss of reverse-direction telemetry. "
                "It is NOT equivalent to collecting naturally unidirectional traffic. "
                "Real unidirectional observation would produce fundamentally different "
                "flow aggregation behaviour."
            ),
        )
