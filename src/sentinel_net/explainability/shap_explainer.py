"""
SHAP-based model explainer for tree-based classifiers.

OPTIONAL DEPENDENCY: Requires `shap>=0.43`.
Install via: pip install sentinel-net[explainability]

If SHAP is not installed, this module returns structured
"explanation unavailable" results without crashing core detection.

Uses evidence_type="model" because SHAP TreeExplainer computes
actual model decision contributions via the Shapley value framework.

SECURITY: No network I/O. No payload inspection. Pure computation.
"""

from __future__ import annotations

import logging
from typing import Any

import numpy as np

from sentinel_net.explainability.evidence import Evidence, EvidenceCollection
from sentinel_net.features.schema import FEATURE_SCHEMA, FEATURE_SCHEMA_VERSION

logger = logging.getLogger(__name__)

# Lazy SHAP availability check
_SHAP_AVAILABLE: bool | None = None


def _check_shap() -> bool:
    """Check if shap is importable. Cached after first call."""
    global _SHAP_AVAILABLE
    if _SHAP_AVAILABLE is None:
        try:
            import shap  # noqa: F401
            _SHAP_AVAILABLE = True
        except ImportError:
            _SHAP_AVAILABLE = False
    return _SHAP_AVAILABLE


class SHAPExplainer:
    """SHAP TreeExplainer wrapper for XGBoost and Random Forest.

    Lazily imports shap only when explain() is called.
    If shap is unavailable, returns EvidenceCollection.unavailable().
    """

    def __init__(
        self,
        model: Any,
        model_name: str,
        model_version: str,
        class_names: list[str],
        feature_names: list[str] | None = None,
        training_data: np.ndarray | None = None,
    ) -> None:
        self._model = model
        self._model_name = model_name
        self._model_version = model_version
        self._class_names = class_names
        self._feature_names = list(feature_names or FEATURE_SCHEMA)
        self._training_data = training_data
        self._explainer: Any = None

        # Precompute training reference if available
        self._reference_values: dict[str, float] | None = None
        if training_data is not None and len(training_data) > 0:
            means = np.nanmean(training_data, axis=0)
            self._reference_values = {
                name: float(means[i])
                for i, name in enumerate(self._feature_names)
                if i < len(means)
            }

    def _init_explainer(self) -> bool:
        """Initialize the SHAP TreeExplainer. Returns False if SHAP unavailable."""
        if not _check_shap():
            return False

        if self._explainer is not None:
            return True

        try:
            import shap
            self._explainer = shap.TreeExplainer(self._model)
            return True
        except Exception as e:
            logger.warning("Failed to initialize SHAP TreeExplainer: %s", e)
            return False

    def explain(
        self,
        X: np.ndarray,
        predicted_class_idx: int = 0,
    ) -> EvidenceCollection:
        """Generate model evidence for a single sample.

        Args:
            X: Feature array of shape (1, n_features).
            predicted_class_idx: Index of the predicted class in class_names.

        Returns:
            EvidenceCollection with evidence_type="model" items.
        """
        if not self._init_explainer():
            return EvidenceCollection.unavailable(
                "SHAP is not installed. Install via: pip install sentinel-net[explainability]"
            )

        try:
            shap_values = self._explainer.shap_values(X)

            # Handle multi-class: shap_values is list of arrays or 3D array
            if isinstance(shap_values, list):
                # List of (n_samples, n_features) arrays, one per class
                if predicted_class_idx < len(shap_values):
                    values = shap_values[predicted_class_idx][0]
                else:
                    values = shap_values[0][0]
            elif isinstance(shap_values, np.ndarray):
                if shap_values.ndim == 3:
                    # (n_samples, n_features, n_classes)
                    values = shap_values[0, :, predicted_class_idx]
                elif shap_values.ndim == 2:
                    # Binary case: (n_samples, n_features)
                    values = shap_values[0]
                else:
                    values = shap_values
            else:
                # shap.Explanation object
                sv = shap_values.values
                if sv.ndim == 3:
                    values = sv[0, :, predicted_class_idx]
                elif sv.ndim == 2:
                    values = sv[0]
                else:
                    values = sv

            # Build evidence items
            items: list[Evidence] = []
            sample = X[0]

            for i, feat_name in enumerate(self._feature_names):
                if i >= len(values):
                    break
                contribution = float(values[i])
                if abs(contribution) < 1e-10:
                    continue  # Skip negligible contributions

                ref_val = (
                    self._reference_values.get(feat_name)
                    if self._reference_values
                    else None
                )

                items.append(Evidence(
                    feature_name=feat_name,
                    observed_value=float(sample[i]),
                    reference_value=ref_val,
                    contribution=contribution,
                    direction="increase" if contribution > 0 else "decrease",
                    evidence_type="model",
                    source="shap_tree_explainer",
                    model_name=self._model_name,
                    model_version=self._model_version,
                    feature_schema_version=FEATURE_SCHEMA_VERSION,
                ))

            # Sort by absolute contribution descending
            items.sort(key=lambda e: abs(e.contribution), reverse=True)
            return EvidenceCollection(items=items)

        except Exception as e:
            logger.warning("SHAP explanation failed: %s", e)
            return EvidenceCollection.unavailable(
                f"SHAP explanation failed: {e}"
            )

    @property
    def is_available(self) -> bool:
        """Check if SHAP is importable."""
        return _check_shap()
