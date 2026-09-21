"""
Controlled robustness experiments for EIDOLON // SENTINEL-NET.

These are CONTROLLED ROBUSTNESS EXPERIMENTS.
They evaluate prediction sensitivity to controlled perturbations.

They do NOT represent:
    - real attackers
    - real evasion campaigns
    - guaranteed adversarial behaviour

They do NOT optimize perturbations to evade the detector.
"""

from dataclasses import dataclass, field
from typing import Any

import numpy as np

from sentinel_net.features.schema import FEATURE_SCHEMA


@dataclass
class PerturbationResult:
    """Result of a CONTROLLED ROBUSTNESS EXPERIMENT.

    These are NOT real attackers, NOT real evasion campaigns.
    They evaluate prediction sensitivity to controlled perturbations.
    """

    perturbation_type: str
    n_samples: int
    classification_changed_count: int
    classification_changed_pct: float
    mean_score_change: float
    max_score_change: float
    details: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "perturbation_type": self.perturbation_type,
            "n_samples": self.n_samples,
            "classification_changed_count": self.classification_changed_count,
            "classification_changed_pct": self.classification_changed_pct,
            "mean_score_change": self.mean_score_change,
            "max_score_change": self.max_score_change,
            "n_details_recorded": len(self.details),
        }


# ─── Perturbation Functions ──────────────────────────────────────────


def get_feature_indices(prefix_or_names: list[str]) -> list[int]:
    """Get indices of features matching names in FEATURE_SCHEMA."""
    schema_list = list(FEATURE_SCHEMA)
    return [schema_list.index(name) for name in prefix_or_names if name in schema_list]


IAT_FEATURES = [n for n in FEATURE_SCHEMA if "iat_" in n]
PKT_SIZE_FEATURES = [n for n in FEATURE_SCHEMA if n.startswith("pkt_size_")]
REVERSE_FEATURES = [
    n for n in FEATURE_SCHEMA
    if n.startswith("reverse_") or n.startswith("rev_iat_")
]


def timing_jitter(
    X: np.ndarray,
    noise_std: float = 0.1,
    seed: int = 42,
) -> np.ndarray:
    """Apply Gaussian noise to IAT features.

    Simulates measurement timing uncertainty, NOT an attack.
    """
    rng = np.random.RandomState(seed)
    indices = get_feature_indices(IAT_FEATURES)
    X_pert = X.copy()
    noise = rng.normal(0, noise_std, size=(X.shape[0], len(indices)))
    X_pert[:, indices] += noise
    return X_pert


def packet_size_noise(
    X: np.ndarray,
    noise_std: float = 0.1,
    seed: int = 42,
) -> np.ndarray:
    """Apply Gaussian noise to packet size features.

    Simulates packet size measurement variation.
    """
    rng = np.random.RandomState(seed)
    indices = get_feature_indices(PKT_SIZE_FEATURES)
    X_pert = X.copy()
    noise = rng.normal(0, noise_std, size=(X.shape[0], len(indices)))
    X_pert[:, indices] += noise
    X_pert[:, indices] = np.maximum(X_pert[:, indices], 0)
    return X_pert


def flow_duration_perturbation(
    X: np.ndarray,
    scale: float = 0.2,
    seed: int = 42,
) -> np.ndarray:
    """Scale duration_sec by (1 ± scale).

    Simulates flow duration measurement uncertainty.
    """
    rng = np.random.RandomState(seed)
    dur_idx = list(FEATURE_SCHEMA).index("duration_sec")
    X_pert = X.copy()
    factors = 1.0 + rng.uniform(-scale, scale, size=X.shape[0])
    X_pert[:, dur_idx] *= factors
    return X_pert


def directional_imbalance(X: np.ndarray) -> np.ndarray:
    """Zero all reverse-direction features.

    Simulates complete loss of reverse-direction telemetry.
    """
    indices = get_feature_indices(REVERSE_FEATURES)
    X_pert = X.copy()
    X_pert[:, indices] = 0.0
    return X_pert


def missing_metadata(
    X: np.ndarray,
    drop_fraction: float = 0.2,
    seed: int = 42,
) -> np.ndarray:
    """Randomly zero a fraction of feature values.

    Simulates incomplete metadata extraction.
    """
    rng = np.random.RandomState(seed)
    X_pert = X.copy()
    mask = rng.rand(*X_pert.shape) < drop_fraction
    X_pert[mask] = 0.0
    return X_pert


# ─── Evaluator ────────────────────────────────────────────────────────


class RobustnessEvaluator:
    """Evaluates prediction sensitivity to controlled perturbations.

    Compares model predictions before and after perturbation.
    Records classification changes and score shifts.
    """

    def evaluate_perturbation(
        self,
        X_original: np.ndarray,
        X_perturbed: np.ndarray,
        model: Any,
        preprocessor: Any,
        perturbation_type: str = "unknown",
        max_details: int = 50,
    ) -> PerturbationResult:
        """Compare predictions before and after perturbation.

        Args:
            X_original: Original feature matrix (raw, pre-preprocessing).
            X_perturbed: Perturbed feature matrix (raw, pre-preprocessing).
            model: Trained classifier with predict() and predict_scores().
            preprocessor: Fitted preprocessor with transform().
            perturbation_type: Label for the perturbation.
            max_details: Maximum per-sample details to record.

        Returns:
            PerturbationResult with sensitivity metrics.
        """
        X_orig_pp = preprocessor.transform(X_original)
        X_pert_pp = preprocessor.transform(X_perturbed)

        pred_orig = model.predict(X_orig_pp)
        pred_pert = model.predict(X_pert_pp)

        scores_orig = model.predict_scores(X_orig_pp)
        scores_pert = model.predict_scores(X_pert_pp)

        # Compute max score per sample (across classes)
        max_score_orig = np.max(
            np.column_stack([scores_orig[c] for c in sorted(scores_orig)]),
            axis=1,
        )
        max_score_pert = np.max(
            np.column_stack([scores_pert[c] for c in sorted(scores_pert)]),
            axis=1,
        )
        score_changes = np.abs(max_score_pert - max_score_orig)

        changed_mask = pred_orig != pred_pert
        n_changed = int(changed_mask.sum())
        n_total = len(pred_orig)

        details: list[dict[str, Any]] = []
        changed_indices = np.where(changed_mask)[0]
        for idx in changed_indices[:max_details]:
            details.append({
                "index": int(idx),
                "original_prediction": str(pred_orig[idx]),
                "perturbed_prediction": str(pred_pert[idx]),
                "score_change": float(score_changes[idx]),
            })

        return PerturbationResult(
            perturbation_type=perturbation_type,
            n_samples=n_total,
            classification_changed_count=n_changed,
            classification_changed_pct=n_changed / n_total * 100 if n_total > 0 else 0.0,
            mean_score_change=float(np.mean(score_changes)) if len(score_changes) > 0 else 0.0,
            max_score_change=float(np.max(score_changes)) if len(score_changes) > 0 else 0.0,
            details=details,
        )
