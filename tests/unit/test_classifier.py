"""Tests for threat classifiers."""

import numpy as np
import pytest
import tempfile
from pathlib import Path

from sentinel_net.detection.classifier import (
    XGBoostClassifier,
    RandomForestBaseline,
    LogisticRegressionBaseline,
)
from sentinel_net.features.schema import FEATURE_COUNT


@pytest.fixture
def multiclass_data():
    """Deterministic 3-class synthetic dataset."""
    rng = np.random.RandomState(42)
    X = np.vstack([
        rng.randn(40, FEATURE_COUNT) * 0.5,       # benign
        rng.randn(30, FEATURE_COUNT) * 0.5 + 3.0,  # ddos
        rng.randn(20, FEATURE_COUNT) * 0.5 - 3.0,  # recon
    ])
    y = np.array(["benign"] * 40 + ["ddos"] * 30 + ["reconnaissance"] * 20)
    return X, y


@pytest.fixture
def binary_data():
    """Deterministic 2-class synthetic dataset."""
    rng = np.random.RandomState(42)
    X = np.vstack([
        rng.randn(50, FEATURE_COUNT) * 0.5,
        rng.randn(50, FEATURE_COUNT) * 0.5 + 3.0,
    ])
    y = np.array(["benign"] * 50 + ["ddos"] * 50)
    return X, y


class TestXGBoostClassifier:
    def test_train_predict(self, multiclass_data):
        X, y = multiclass_data
        clf = XGBoostClassifier(random_state=42)
        clf.train(X, y)
        preds = clf.predict(X)
        assert len(preds) == len(y)
        assert set(preds).issubset(set(y))

    def test_binary_case(self, binary_data):
        X, y = binary_data
        clf = XGBoostClassifier(random_state=42)
        clf.train(X, y)
        preds = clf.predict(X)
        assert set(preds).issubset({"benign", "ddos"})

    def test_predict_scores(self, multiclass_data):
        X, y = multiclass_data
        clf = XGBoostClassifier(random_state=42)
        clf.train(X, y)
        scores = clf.predict_scores(X)
        assert isinstance(scores, dict)
        assert "benign" in scores
        assert "ddos" in scores
        assert "reconnaissance" in scores
        for cls_name, s in scores.items():
            assert len(s) == len(X)
            assert np.all(s >= 0.0)

    def test_not_trained_raises(self):
        clf = XGBoostClassifier()
        with pytest.raises(ValueError):
            clf.predict(np.zeros((5, FEATURE_COUNT)))

    def test_single_class_raises(self):
        X = np.random.randn(20, FEATURE_COUNT)
        y = np.array(["benign"] * 20)
        clf = XGBoostClassifier()
        with pytest.raises(ValueError, match="at least 2 classes"):
            clf.train(X, y)

    def test_deterministic(self, multiclass_data):
        X, y = multiclass_data
        clf1 = XGBoostClassifier(random_state=42)
        clf1.train(X, y)
        p1 = clf1.predict(X)

        clf2 = XGBoostClassifier(random_state=42)
        clf2.train(X, y)
        p2 = clf2.predict(X)
        np.testing.assert_array_equal(p1, p2)

    def test_save_load(self, multiclass_data):
        X, y = multiclass_data
        clf = XGBoostClassifier(random_state=42)
        clf.train(X, y)
        original = clf.predict(X[:5])

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "xgb.joblib"
            clf.save(path)
            loaded = XGBoostClassifier.load(path)

        result = loaded.predict(X[:5])
        np.testing.assert_array_equal(original, result)

    def test_supported_classes(self, multiclass_data):
        X, y = multiclass_data
        clf = XGBoostClassifier(random_state=42)
        clf.train(X, y)
        assert set(clf.supported_classes) == {"benign", "ddos", "reconnaissance"}

    def test_model_metadata(self):
        clf = XGBoostClassifier(model_name="xgb_test", model_version="0.2.0")
        assert clf.model_name == "xgb_test"
        assert clf.model_version == "0.2.0"


class TestRandomForestBaseline:
    def test_train_predict(self, multiclass_data):
        X, y = multiclass_data
        clf = RandomForestBaseline(random_state=42)
        clf.train(X, y)
        preds = clf.predict(X)
        assert len(preds) == len(y)

    def test_predict_scores(self, multiclass_data):
        X, y = multiclass_data
        clf = RandomForestBaseline(random_state=42)
        clf.train(X, y)
        scores = clf.predict_scores(X)
        assert len(scores) == 3


class TestLogisticRegressionBaseline:
    def test_train_predict(self, multiclass_data):
        X, y = multiclass_data
        clf = LogisticRegressionBaseline(random_state=42)
        clf.train(X, y)
        preds = clf.predict(X)
        assert len(preds) == len(y)

    def test_predict_scores(self, multiclass_data):
        X, y = multiclass_data
        clf = LogisticRegressionBaseline(random_state=42)
        clf.train(X, y)
        scores = clf.predict_scores(X)
        assert len(scores) == 3
