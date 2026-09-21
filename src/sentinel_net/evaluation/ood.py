"""
Out-of-distribution (OOD) analysis for EIDOLON // SENTINEL-NET.

Tests traffic distributions unlike the training distribution to evaluate
how the detector behaves on unseen patterns.

INTERPRETATION:
    High anomaly score on OOD input does NOT necessarily mean malicious.
    It means "unlike the training distribution."

    This module explicitly distinguishes:
        UNKNOWN (statistically unusual)
    from:
        MALICIOUS (confirmed threat behaviour).

    Sentinel-NET's anomaly detector flags novelty, not confirmed malice.
"""

from dataclasses import dataclass, field
from typing import Any

import numpy as np

from sentinel_net.features.schema import FEATURE_SCHEMA, FEATURE_COUNT


@dataclass
class OODSample:
    """A single out-of-distribution test sample."""

    description: str
    feature_values: np.ndarray
    anomaly_score: float | None = None
    predicted_class: str | None = None
    confidence_score: float | None = None
    notes: str = ""


@dataclass
class OODAnalysisResult:
    """Result of out-of-distribution analysis.

    This is a SYNTHETIC ROBUSTNESS TEST, not a real-data evaluation.
    Results indicate model behaviour on crafted inputs, not real-world
    OOD traffic.
    """

    result_category: str = "synthetic_robustness_test"
    samples: list[OODSample] = field(default_factory=list)
    mean_anomaly_score: float | None = None
    anomaly_score_std: float | None = None
    n_flagged_anomalous: int = 0
    n_total: int = 0
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "result_category": self.result_category,
            "n_total": self.n_total,
            "n_flagged_anomalous": self.n_flagged_anomalous,
            "mean_anomaly_score": self.mean_anomaly_score,
            "anomaly_score_std": self.anomaly_score_std,
            "notes": self.notes,
            "samples": [
                {
                    "description": s.description,
                    "anomaly_score": s.anomaly_score,
                    "predicted_class": s.predicted_class,
                    "confidence_score": s.confidence_score,
                    "notes": s.notes,
                }
                for s in self.samples
            ],
        }


def generate_ood_samples(
    X_train: np.ndarray,
    n_samples_per_type: int = 10,
    random_seed: int = 42,
) -> list[tuple[str, np.ndarray]]:
    """Generate synthetic OOD feature vectors unlike the training distribution.

    These are NOT real traffic. They are controlled synthetic inputs for
    evaluating detector behaviour on unseen patterns.

    Args:
        X_train: Training data to compute distributional statistics.
        n_samples_per_type: Number of samples per OOD type.
        random_seed: For reproducibility.

    Returns:
        List of (description, feature_vector) tuples.
    """
    rng = np.random.RandomState(random_seed)
    train_mean = np.mean(X_train, axis=0)
    train_std = np.std(X_train, axis=0)
    train_std[train_std == 0] = 1.0  # Avoid division by zero

    samples: list[tuple[str, np.ndarray]] = []

    # Type 1: Extreme packet sizes (5 sigma above mean)
    pkt_size_indices = [
        i for i, name in enumerate(FEATURE_SCHEMA)
        if name.startswith("pkt_size_")
    ]
    for _ in range(n_samples_per_type):
        x = train_mean.copy()
        for idx in pkt_size_indices:
            x[idx] = train_mean[idx] + 5 * train_std[idx]
        x += rng.normal(0, 0.01 * train_std, size=x.shape)
        samples.append(("extreme_packet_sizes", x))

    # Type 2: Extreme flow duration
    dur_idx = list(FEATURE_SCHEMA).index("duration_sec")
    for _ in range(n_samples_per_type):
        x = train_mean.copy()
        x[dur_idx] = train_mean[dur_idx] + 10 * train_std[dur_idx]
        x += rng.normal(0, 0.01 * train_std, size=x.shape)
        samples.append(("extreme_duration", x))

    # Type 3: All-zero features (degenerate flow)
    for _ in range(n_samples_per_type):
        x = np.zeros(FEATURE_COUNT, dtype=np.float64)
        samples.append(("all_zero_features", x))

    # Type 4: Unusual protocol distribution (non-TCP/UDP/ICMP)
    proto_idx = list(FEATURE_SCHEMA).index("protocol")
    tcp_idx = list(FEATURE_SCHEMA).index("is_tcp")
    udp_idx = list(FEATURE_SCHEMA).index("is_udp")
    icmp_idx = list(FEATURE_SCHEMA).index("is_icmp")
    for _ in range(n_samples_per_type):
        x = train_mean.copy()
        x[proto_idx] = 47  # GRE — unusual protocol
        x[tcp_idx] = 0
        x[udp_idx] = 0
        x[icmp_idx] = 0
        x += rng.normal(0, 0.01 * train_std, size=x.shape)
        samples.append(("unusual_protocol", x))

    # Type 5: Extremely asymmetric (all forward, no reverse)
    rev_indices = [
        i for i, name in enumerate(FEATURE_SCHEMA)
        if name.startswith("reverse_") or name.startswith("rev_iat_")
    ]
    for _ in range(n_samples_per_type):
        x = train_mean.copy()
        for idx in rev_indices:
            x[idx] = 0.0
        x += rng.normal(0, 0.01 * train_std, size=x.shape)
        for idx in rev_indices:
            x[idx] = max(0.0, x[idx])  # Keep non-negative
        samples.append(("fully_asymmetric", x))

    return samples


class OODAnalyzer:
    """Analyzes detector behaviour on out-of-distribution inputs.

    Results explicitly distinguish UNKNOWN (novel) from MALICIOUS (threat).
    High anomaly score on OOD input means 'unlike training data', not
    'confirmed attack'.
    """

    def analyze(
        self,
        ood_samples: list[tuple[str, np.ndarray]],
        anomaly_detector: Any,
        classifier: Any,
        preprocessor: Any,
        threshold: float = 0.5,
    ) -> OODAnalysisResult:
        """Run OOD analysis on synthetic samples.

        Args:
            ood_samples: List of (description, feature_vector).
            anomaly_detector: Trained AnomalyDetector.
            classifier: Trained BaseClassifier.
            preprocessor: Fitted FeaturePreprocessor.
            threshold: Anomaly threshold for flagging.

        Returns:
            OODAnalysisResult with per-sample and aggregate analysis.
        """
        results: list[OODSample] = []

        for desc, x_raw in ood_samples:
            x = x_raw.reshape(1, -1)
            try:
                x_pp = preprocessor.transform(x)
                a_score = float(anomaly_detector.score(x_pp)[0])
                pred = str(classifier.predict(x_pp)[0])
                scores_dict = classifier.predict_scores(x_pp)
                conf = float(scores_dict.get(pred, np.zeros(1))[0])
            except Exception as e:
                results.append(OODSample(
                    description=desc,
                    notes=f"Inference failed: {type(e).__name__}",
                ))
                continue

            is_flagged = a_score >= threshold
            results.append(OODSample(
                description=desc,
                feature_values=x_raw,
                anomaly_score=a_score,
                predicted_class=pred,
                confidence_score=conf,
                notes=(
                    f"Flagged as anomalous: {is_flagged}. "
                    "High anomaly score indicates novelty (unlike training data), "
                    "not confirmed malice."
                ),
            ))

        scores = [s.anomaly_score for s in results if s.anomaly_score is not None]

        return OODAnalysisResult(
            samples=results,
            mean_anomaly_score=float(np.mean(scores)) if scores else None,
            anomaly_score_std=float(np.std(scores)) if scores else None,
            n_flagged_anomalous=sum(
                1 for s in results
                if s.anomaly_score is not None and s.anomaly_score >= threshold
            ),
            n_total=len(results),
            notes=(
                "SYNTHETIC ROBUSTNESS TEST. These samples are crafted inputs, "
                "not real traffic. Results indicate detector behaviour on "
                "out-of-distribution patterns, not real-world OOD performance."
            ),
        )
