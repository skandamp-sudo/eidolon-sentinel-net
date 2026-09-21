"""Tests for evaluation framework."""

import numpy as np
import pytest

from sentinel_net.detection.evaluation import (
    AnomalyReport,
    ClassificationReport,
    PerformanceReport,
)


class TestClassificationReport:
    def test_binary_classification(self):
        y_true = np.array(["benign", "benign", "ddos", "ddos", "benign"])
        y_pred = np.array(["benign", "ddos", "ddos", "ddos", "benign"])
        report = ClassificationReport.from_predictions(y_true, y_pred)
        assert 0.0 <= report.accuracy <= 1.0
        assert 0.0 <= report.f1_macro <= 1.0
        assert 0.0 <= report.f1_weighted <= 1.0
        assert report.accuracy == 4.0 / 5.0

    def test_multiclass(self):
        y_true = np.array(["a", "b", "c", "a", "b", "c"])
        y_pred = np.array(["a", "b", "c", "a", "c", "b"])
        report = ClassificationReport.from_predictions(y_true, y_pred)
        assert report.confusion_matrix.shape == (3, 3)
        assert len(report.per_class) == 3

    def test_perfect_classification(self):
        y = np.array(["benign", "ddos", "recon"] * 10)
        report = ClassificationReport.from_predictions(y, y)
        assert report.accuracy == 1.0
        assert report.f1_macro == 1.0

    def test_summary_string(self):
        y_true = np.array(["a", "b", "a", "b"])
        y_pred = np.array(["a", "b", "b", "a"])
        report = ClassificationReport.from_predictions(y_true, y_pred)
        summary = report.summary()
        assert isinstance(summary, str)
        assert "accuracy" in summary.lower() or "f1" in summary.lower()

    def test_per_class_metrics(self):
        y_true = np.array(["benign"] * 10 + ["ddos"] * 5)
        y_pred = np.array(["benign"] * 8 + ["ddos"] * 2 + ["ddos"] * 5)
        report = ClassificationReport.from_predictions(y_true, y_pred)
        assert "benign" in report.per_class
        assert "precision" in report.per_class["benign"]


class TestAnomalyReport:
    def test_basic_report(self):
        y_true = np.array([0, 0, 0, 1, 1])
        scores = np.array([0.1, 0.2, 0.3, 0.8, 0.9])
        report = AnomalyReport.from_scores(y_true, scores, threshold=0.5)
        assert 0.0 <= report.precision_at_threshold <= 1.0
        assert 0.0 <= report.recall_at_threshold <= 1.0
        assert report.threshold == 0.5

    def test_perfect_separation(self):
        y_true = np.array([0, 0, 0, 1, 1])
        scores = np.array([0.0, 0.1, 0.2, 0.9, 1.0])
        report = AnomalyReport.from_scores(y_true, scores, threshold=0.5)
        assert report.precision_at_threshold == 1.0
        assert report.recall_at_threshold == 1.0

    def test_single_class_roc_auc_none(self):
        """ROC-AUC should be None when only one class present."""
        y_true = np.array([0, 0, 0, 0])
        scores = np.array([0.1, 0.2, 0.3, 0.4])
        report = AnomalyReport.from_scores(y_true, scores)
        assert report.roc_auc is None


class TestPerformanceReport:
    def test_measure(self):
        """Performance measurement should return actual timing."""
        import time

        def preprocess(X):
            time.sleep(0.001)
            return X

        def predict(X):
            time.sleep(0.001)
            return np.zeros(X.shape[0])

        X = np.random.randn(10, 5)
        report = PerformanceReport.measure(preprocess, predict, X, n_warmup=1, n_runs=3)
        assert report.n_samples == 10
        assert report.total_latency_ms > 0
        assert report.latency_per_sample_ms > 0
