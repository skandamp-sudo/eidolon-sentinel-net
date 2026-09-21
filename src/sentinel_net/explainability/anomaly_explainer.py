"""
Anomaly explainer for Isolation Forest.

Generates statistical deviation evidence from the training distribution.
Does NOT claim SHAP-like model contributions — uses evidence_type="statistical"
because the methodology computes z-score deviations, not Shapley values.

The Isolation Forest does not natively provide per-feature contribution
attributions. This explainer measures how far each feature value deviates
from the training distribution and presents this as statistical evidence.

SECURITY: No network I/O. No payload inspection. Pure computation.
"""

from __future__ import annotations

import logging

import numpy as np

from sentinel_net.explainability.evidence import Evidence, EvidenceCollection
from sentinel_net.features.schema import FEATURE_SCHEMA, FEATURE_SCHEMA_VERSION

logger = logging.getLogger(__name__)


class AnomalyExplainer:
    """Statistical deviation explainer for anomaly detection.

    Computes per-feature z-scores against the training distribution
    and presents significant deviations as statistical evidence.

    This is NOT a model-level explanation. It shows which features
    have unusual values relative to the training baseline, which may
    or may not correspond to the model's actual decision factors.
    """

    def __init__(
        self,
        model_name: str = "isolation_forest",
        model_version: str = "1.0.0",
        feature_names: list[str] | None = None,
    ) -> None:
        self._model_name = model_name
        self._model_version = model_version
        self._feature_names = list(feature_names or FEATURE_SCHEMA)
        self._is_fitted = False
        self._train_mean: np.ndarray | None = None
        self._train_std: np.ndarray | None = None
        self._z_threshold = 2.0  # Features with |z| > threshold are significant

    def fit(self, X_train: np.ndarray) -> AnomalyExplainer:
        """Compute training distribution statistics.

        Args:
            X_train: Training data of shape (n_samples, n_features).
                     Should be the same data used to train the anomaly detector.
        """
        self._train_mean = np.nanmean(X_train, axis=0)
        self._train_std = np.nanstd(X_train, axis=0)
        # Prevent division by zero: replace zero std with 1.0
        self._train_std[self._train_std < 1e-10] = 1.0
        self._is_fitted = True
        return self

    def explain(
        self,
        X: np.ndarray,
        anomaly_score: float,
    ) -> EvidenceCollection:
        """Generate statistical deviation evidence for a single sample.

        Args:
            X: Feature array of shape (1, n_features).
            anomaly_score: The anomaly score from the detector.

        Returns:
            EvidenceCollection with evidence_type="statistical" items.
            Evidence items are sorted by |z_score| descending.
        """
        if not self._is_fitted:
            return EvidenceCollection.unavailable(
                "AnomalyExplainer must be fitted with training data before use."
            )

        sample = X[0]
        z_scores = (sample - self._train_mean) / self._train_std

        items: list[Evidence] = []
        for i, feat_name in enumerate(self._feature_names):
            if i >= len(z_scores):
                break

            z = float(z_scores[i])
            if abs(z) < self._z_threshold:
                continue  # Not significantly different from training

            items.append(Evidence(
                feature_name=feat_name,
                observed_value=float(sample[i]),
                reference_value=float(self._train_mean[i]),
                contribution=abs(z),  # Magnitude of deviation
                direction="increase" if z > 0 else "decrease",
                evidence_type="statistical",
                source="training_distribution",
                model_name=self._model_name,
                model_version=self._model_version,
                feature_schema_version=FEATURE_SCHEMA_VERSION,
            ))

        # Sort by absolute z-score descending
        items.sort(key=lambda e: abs(e.contribution), reverse=True)
        return EvidenceCollection(items=items)

    @property
    def is_fitted(self) -> bool:
        return self._is_fitted

    @property
    def z_threshold(self) -> float:
        return self._z_threshold

    @z_threshold.setter
    def z_threshold(self, value: float) -> None:
        if value <= 0:
            raise ValueError("z_threshold must be positive")
        self._z_threshold = value
