"""Performance benchmarks for detection and explanation.

Measures actual latency for:
1. Preprocessing
2. Anomaly inference
3. Classifier inference
4. Explanation generation (anomaly)
5. Full pipeline: inference + explanation

Uses deterministic local fixtures. No fabricated numbers.
"""

import time

import numpy as np
import pytest

from sentinel_net.detection.anomaly import AnomalyDetector
from sentinel_net.detection.classifier import XGBoostClassifier, RandomForestBaseline
from sentinel_net.detection.preprocessing import FeaturePreprocessor
from sentinel_net.explainability.anomaly_explainer import AnomalyExplainer
from sentinel_net.features.schema import FEATURE_COUNT


@pytest.fixture(scope="module")
def synthetic_data():
    rng = np.random.RandomState(42)
    X = np.vstack([
        rng.randn(200, FEATURE_COUNT) * 0.5,
        rng.randn(50, FEATURE_COUNT) * 0.5 + 3.0,
    ])
    y = np.array(["benign"] * 200 + ["ddos"] * 50)
    return X, y


@pytest.fixture(scope="module")
def trained_components(synthetic_data):
    X, y = synthetic_data

    pp = FeaturePreprocessor()
    pp.fit(X)
    X_pp = pp.transform(X)

    ad = AnomalyDetector(random_state=42)
    ad.train(X_pp[y == "benign"])

    xgb = XGBoostClassifier(random_state=42)
    xgb.train(X_pp, y)

    ae = AnomalyExplainer()
    ae.fit(X_pp[y == "benign"])

    return pp, ad, xgb, ae, X_pp


def _measure_ms(func, *args, n_runs=10, n_warmup=3):
    """Measure function execution time in milliseconds."""
    for _ in range(n_warmup):
        func(*args)

    times = []
    for _ in range(n_runs):
        t0 = time.perf_counter()
        func(*args)
        t1 = time.perf_counter()
        times.append((t1 - t0) * 1000.0)
    return {
        "mean_ms": np.mean(times),
        "median_ms": np.median(times),
        "p95_ms": np.percentile(times, 95),
        "n_runs": n_runs,
    }


class TestPerformanceBenchmarks:
    def test_preprocessing_latency(self, trained_components, synthetic_data):
        pp, _, _, _, _ = trained_components
        X, _ = synthetic_data
        result = _measure_ms(pp.transform, X)
        assert result["mean_ms"] > 0
        print(f"\nPreprocessing ({X.shape[0]} samples): "
              f"mean={result['mean_ms']:.2f}ms, "
              f"median={result['median_ms']:.2f}ms, "
              f"p95={result['p95_ms']:.2f}ms")

    def test_anomaly_scoring_latency(self, trained_components):
        _, ad, _, _, X_pp = trained_components
        result = _measure_ms(ad.score, X_pp)
        assert result["mean_ms"] > 0
        print(f"\nAnomaly scoring ({X_pp.shape[0]} samples): "
              f"mean={result['mean_ms']:.2f}ms, "
              f"median={result['median_ms']:.2f}ms, "
              f"p95={result['p95_ms']:.2f}ms")

    def test_classifier_inference_latency(self, trained_components):
        _, _, xgb, _, X_pp = trained_components
        result = _measure_ms(xgb.predict, X_pp)
        assert result["mean_ms"] > 0
        print(f"\nXGBoost inference ({X_pp.shape[0]} samples): "
              f"mean={result['mean_ms']:.2f}ms, "
              f"median={result['median_ms']:.2f}ms, "
              f"p95={result['p95_ms']:.2f}ms")

    def test_anomaly_explanation_latency(self, trained_components):
        _, _, _, ae, X_pp = trained_components
        single = X_pp[:1]
        result = _measure_ms(ae.explain, single, 0.8)
        assert result["mean_ms"] > 0
        print(f"\nAnomaly explanation (1 sample): "
              f"mean={result['mean_ms']:.2f}ms, "
              f"median={result['median_ms']:.2f}ms, "
              f"p95={result['p95_ms']:.2f}ms")

    def test_inference_only_vs_inference_plus_explanation(self, trained_components):
        """Compare: model inference only vs model inference + explanation."""
        pp, ad, xgb, ae, X_pp = trained_components
        single = X_pp[:1]

        # Inference only
        def inference_only(X):
            ad.score(X)
            xgb.predict(X)

        # Inference + explanation
        def inference_plus_explain(X):
            ad.score(X)
            xgb.predict(X)
            ae.explain(X, 0.8)

        result_inf = _measure_ms(inference_only, single)
        result_full = _measure_ms(inference_plus_explain, single)

        assert result_inf["mean_ms"] > 0
        assert result_full["mean_ms"] > 0

        overhead = result_full["mean_ms"] - result_inf["mean_ms"]
        print(f"\nInference only: {result_inf['mean_ms']:.2f}ms")
        print(f"Inference + explanation: {result_full['mean_ms']:.2f}ms")
        print(f"Explanation overhead: {overhead:.2f}ms")
