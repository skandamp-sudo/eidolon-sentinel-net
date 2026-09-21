"""Tests for preprocessing pipeline."""

import numpy as np
import pytest
import tempfile
from pathlib import Path

from sentinel_net.detection.preprocessing import FeaturePreprocessor
from sentinel_net.features.schema import FEATURE_COUNT
from sentinel_net.detection.audit import LINEAR_MODEL_FEATURES, TREE_MODEL_FEATURES


class TestFeaturePreprocessor:
    """Test the sklearn-based preprocessing pipeline."""

    @pytest.fixture
    def rng(self):
        return np.random.RandomState(42)

    @pytest.fixture
    def train_data(self, rng):
        return rng.randn(50, FEATURE_COUNT) * 3.0 + 2.0

    @pytest.fixture
    def test_data(self, rng):
        return rng.randn(20, FEATURE_COUNT) * 3.0 + 2.0

    def test_fit_transform(self, train_data):
        pp = FeaturePreprocessor()
        result = pp.fit_transform(train_data)
        assert result.shape == train_data.shape
        assert pp.is_fitted

    def test_not_fitted_raises(self, test_data):
        pp = FeaturePreprocessor()
        assert not pp.is_fitted
        with pytest.raises((ValueError, RuntimeError)):
            pp.transform(test_data)

    def test_transform_normalizes(self, train_data):
        pp = FeaturePreprocessor()
        pp.fit(train_data)
        result = pp.transform(train_data)
        # Fitted data should be approximately zero-mean, unit-variance
        assert abs(result.mean()) < 0.3
        assert abs(result.std() - 1.0) < 0.3

    def test_nan_handling(self, train_data):
        """NaN values should be handled by imputer."""
        pp = FeaturePreprocessor()
        pp.fit(train_data)
        test_with_nan = train_data[:5].copy()
        test_with_nan[0, 0] = np.nan
        test_with_nan[1, 5] = np.nan
        result = pp.transform(test_with_nan)
        assert not np.any(np.isnan(result))

    def test_inf_handling(self, train_data):
        """Inf values should be replaced before pipeline."""
        pp = FeaturePreprocessor()
        pp.fit(train_data)
        test_with_inf = train_data[:5].copy()
        test_with_inf[0, 0] = np.inf
        test_with_inf[1, 5] = -np.inf
        result = pp.transform(test_with_inf)
        assert not np.any(np.isinf(result))
        assert not np.any(np.isnan(result))

    def test_feature_subset_tree(self, train_data):
        """Tree model features should use all 52."""
        pp = FeaturePreprocessor(feature_subset=TREE_MODEL_FEATURES)
        pp.fit(train_data)
        result = pp.transform(train_data)
        assert result.shape[1] == 52

    def test_feature_subset_linear(self, train_data):
        """Linear model features should use 50 (excluding nominal)."""
        pp = FeaturePreprocessor(feature_subset=LINEAR_MODEL_FEATURES)
        pp.fit(train_data)
        result = pp.transform(train_data)
        assert result.shape[1] == 50

    def test_save_load(self, train_data):
        """Serialization round-trip must preserve behavior."""
        pp = FeaturePreprocessor()
        pp.fit(train_data)
        original = pp.transform(train_data[:5])

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "preprocessor.joblib"
            pp.save(path)
            loaded = FeaturePreprocessor.load(path)

        result = loaded.transform(train_data[:5])
        np.testing.assert_array_almost_equal(original, result)

    def test_fit_only_on_train(self, rng):
        """Fitting on different data must produce different transformations."""
        X_a = rng.randn(50, FEATURE_COUNT) * 10.0 + 100.0
        X_b = rng.randn(50, FEATURE_COUNT) * 0.1 - 50.0

        pp_a = FeaturePreprocessor()
        pp_a.fit(X_a)
        pp_b = FeaturePreprocessor()
        pp_b.fit(X_b)

        # Same input, different preprocessors → different output
        test = rng.randn(5, FEATURE_COUNT)
        result_a = pp_a.transform(test)
        result_b = pp_b.transform(test)
        assert not np.allclose(result_a, result_b)

    def test_constant_features_detected(self):
        """Constant columns should be identified."""
        X = np.ones((50, FEATURE_COUNT))
        pp = FeaturePreprocessor()
        pp.fit(X)
        # All features are constant
        assert len(pp.constant_features) == FEATURE_COUNT

    def test_n_features(self, train_data):
        pp = FeaturePreprocessor()
        pp.fit(train_data)
        assert pp.n_features_in == FEATURE_COUNT
