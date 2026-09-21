import numpy as np
import joblib
from pathlib import Path
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import StandardScaler

from sentinel_net.features.schema import FEATURE_SCHEMA, FEATURE_COUNT, FEATURE_SCHEMA_VERSION
from sentinel_net.detection.audit import LINEAR_MODEL_FEATURES, TREE_MODEL_FEATURES

class FeaturePreprocessor:
    def __init__(self, feature_subset: tuple[str, ...] | None = None, random_state: int = 42) -> None:
        if feature_subset is None:
            self._feature_subset = TREE_MODEL_FEATURES
        else:
            self._feature_subset = feature_subset
            
        self._random_state = random_state
        
        # Build _feature_indices
        self._feature_indices = [
            FEATURE_SCHEMA.index(feat) for feat in self._feature_subset
        ]
        
        self._pipeline = Pipeline([
            ('imputer', SimpleImputer(strategy='median')),
            ('scaler', StandardScaler())
        ])
        
        self._is_fitted = False
        self._constant_features: list[str] = []
        
    def fit(self, X: np.ndarray) -> 'FeaturePreprocessor':
        if X.shape[1] != FEATURE_COUNT:
            raise ValueError(f"Expected {FEATURE_COUNT} features, got {X.shape[1]}")
            
        # Select subset
        X_sub = X[:, self._feature_indices].copy()
        
        # Replace inf with nan
        X_sub[np.isinf(X_sub)] = np.nan
        
        self._pipeline.fit(X_sub)
        
        # Find constant features (variance = 0)
        scaler = self._pipeline.named_steps['scaler']
        variances = scaler.var_
        constant_mask = np.isclose(variances, 0.0)
        
        self._constant_features = [
            feat for feat, is_const in zip(self._feature_subset, constant_mask) if is_const
        ]
        
        self._is_fitted = True
        return self

    def transform(self, X: np.ndarray) -> np.ndarray:
        if not self._is_fitted:
            raise RuntimeError("Preprocessor must be fitted before calling transform.")
            
        # Select subset
        X_sub = X[:, self._feature_indices].copy()
        
        # Replace inf with nan BEFORE pipeline.transform
        X_sub[np.isinf(X_sub)] = np.nan
        
        return self._pipeline.transform(X_sub)
        
    def fit_transform(self, X: np.ndarray) -> np.ndarray:
        return self.fit(X).transform(X)
        
    def save(self, path: Path) -> None:
        if not self._is_fitted:
            raise RuntimeError("Cannot save unfitted preprocessor")
        joblib.dump(self, path)
        
    @classmethod
    def load(cls, path: Path) -> 'FeaturePreprocessor':
        return joblib.load(path)
        
    @property
    def is_fitted(self) -> bool:
        return self._is_fitted
        
    @property
    def n_features_in(self) -> int:
        return len(self._feature_subset)
        
    @property
    def n_features_out(self) -> int:
        return len(self._feature_subset)
        
    @property
    def constant_features(self) -> list[str]:
        return self._constant_features
        
    @property
    def version(self) -> str:
        return FEATURE_SCHEMA_VERSION

    @property
    def output_feature_names(self) -> list[str]:
        """Actual transformed names, excluding columns dropped by the imputer."""
        if not self._is_fitted:
            raise RuntimeError('Preprocessor must be fitted before querying output names')
        return list(self._pipeline.named_steps['imputer'].get_feature_names_out(
            list(self._feature_subset)))
