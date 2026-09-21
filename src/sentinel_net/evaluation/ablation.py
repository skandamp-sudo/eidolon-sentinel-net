"""
Feature ablation experiments for EIDOLON // SENTINEL-NET.

INTERPRETATION: Ablation measures how much the model RELIES on each
feature group. It does NOT prove causal importance, real-world necessity,
or attack causality.

Use language: "removing X reduced F1 by Y"
NOT: "X caused detection"
"""

from dataclasses import dataclass
from typing import Any

import numpy as np
from sklearn.metrics import f1_score, precision_score, recall_score

from sentinel_net.features.schema import FEATURE_SCHEMA

# Feature groups based on FEATURE_AUDIT categories
FEATURE_GROUPS: dict[str, list[str]] = {
    "basic": [
        "duration_sec", "total_packets", "total_bytes",
        "packets_per_sec", "bytes_per_sec",
    ],
    "directional": [
        "forward_packets", "reverse_packets", "forward_bytes", "reverse_bytes",
        "fwd_rev_packet_ratio", "fwd_rev_byte_ratio",
    ],
    "packet_size_stats": [
        "pkt_size_mean", "pkt_size_std", "pkt_size_min", "pkt_size_max",
        "pkt_size_median", "pkt_size_p25", "pkt_size_p75", "pkt_size_p90",
    ],
    "inter_arrival_time": [
        "iat_mean", "iat_std", "iat_min", "iat_max", "iat_median",
        "fwd_iat_mean", "fwd_iat_std", "fwd_iat_min", "fwd_iat_max",
        "rev_iat_mean", "rev_iat_std", "rev_iat_min", "rev_iat_max",
    ],
    "tcp_flags": [
        "syn_count", "syn_ack_count", "ack_count", "fin_count", "rst_count",
        "psh_count", "syn_ratio", "ack_ratio", "fin_ratio", "rst_ratio", "psh_ratio",
    ],
    "protocol": [
        "protocol", "ip_version", "is_tcp", "is_udp", "is_icmp",
    ],
    "payload_metadata": [
        "payload_bytes_total", "forward_payload_bytes",
        "reverse_payload_bytes", "payload_ratio",
    ],
}


@dataclass
class AblationResult:
    """Result of removing a feature group and measuring impact."""

    group_name: str
    features_removed: list[str]
    n_features_remaining: int
    full_f1: float
    ablated_f1: float
    delta_f1: float
    full_precision: float
    ablated_precision: float
    full_recall: float
    ablated_recall: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "group_name": self.group_name,
            "features_removed": self.features_removed,
            "n_features_remaining": self.n_features_remaining,
            "full_f1": self.full_f1,
            "ablated_f1": self.ablated_f1,
            "delta_f1": self.delta_f1,
            "full_precision": self.full_precision,
            "ablated_precision": self.ablated_precision,
            "full_recall": self.full_recall,
            "ablated_recall": self.ablated_recall,
        }


class FeatureAblation:
    """Measures model dependence on feature groups.

    INTERPRETATION: Ablation measures how much the model relies on each
    feature group. It does NOT prove causal importance, real-world necessity,
    or attack causality.

    Method: For each feature group, zero out those features in both train
    and test, retrain the model, and measure the change in metrics.
    """

    def __init__(self, feature_names: list[str] | None = None):
        if feature_names is None:
            self.feature_names = list(FEATURE_SCHEMA)
        else:
            self.feature_names = feature_names

    def _get_group_indices(self, group_features: list[str]) -> list[int]:
        """Get column indices for a feature group."""
        return [
            i for i, name in enumerate(self.feature_names)
            if name in group_features
        ]

    def run(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_test: np.ndarray,
        y_test: np.ndarray,
        model_class: Any,
        random_seed: int = 42,
        **model_kwargs: Any,
    ) -> list[AblationResult]:
        """Run ablation for each feature group.

        Method: zero out features in both train/test, retrain, measure impact.

        Args:
            X_train, y_train: Training data (preprocessed).
            X_test, y_test: Test data (preprocessed).
            model_class: Uninstantiated model class.
            random_seed: For reproducible training.

        Returns:
            List of AblationResult detailing model dependence on each group.
        """
        # Baseline: full feature set
        baseline_model = model_class(random_state=random_seed, **model_kwargs)
        baseline_model.train(X_train, y_train)
        y_pred_full = baseline_model.predict(X_test)

        full_f1 = float(f1_score(y_test, y_pred_full, average="macro", zero_division=0))
        full_prec = float(precision_score(y_test, y_pred_full, average="macro", zero_division=0))
        full_rec = float(recall_score(y_test, y_pred_full, average="macro", zero_division=0))

        results: list[AblationResult] = []

        for group_name, group_features in FEATURE_GROUPS.items():
            indices = self._get_group_indices(group_features)
            if not indices:
                continue

            # Zero out the feature group
            X_train_ablated = X_train.copy()
            X_test_ablated = X_test.copy()
            X_train_ablated[:, indices] = 0.0
            X_test_ablated[:, indices] = 0.0

            # Retrain with ablated features
            ablated_model = model_class(random_state=random_seed, **model_kwargs)
            try:
                ablated_model.train(X_train_ablated, y_train)
                y_pred_ablated = ablated_model.predict(X_test_ablated)
            except Exception:
                # If training fails, record as maximum degradation
                results.append(AblationResult(
                    group_name=group_name,
                    features_removed=group_features,
                    n_features_remaining=len(self.feature_names) - len(indices),
                    full_f1=full_f1,
                    ablated_f1=0.0,
                    delta_f1=-full_f1,
                    full_precision=full_prec,
                    ablated_precision=0.0,
                    full_recall=full_rec,
                    ablated_recall=0.0,
                ))
                continue

            ablated_f1 = float(f1_score(y_test, y_pred_ablated, average="macro", zero_division=0))
            ablated_prec = float(precision_score(y_test, y_pred_ablated, average="macro", zero_division=0))
            ablated_rec = float(recall_score(y_test, y_pred_ablated, average="macro", zero_division=0))

            results.append(AblationResult(
                group_name=group_name,
                features_removed=group_features,
                n_features_remaining=len(self.feature_names) - len(indices),
                full_f1=full_f1,
                ablated_f1=ablated_f1,
                delta_f1=ablated_f1 - full_f1,
                full_precision=full_prec,
                ablated_precision=ablated_prec,
                full_recall=full_rec,
                ablated_recall=ablated_rec,
            ))

        return results
