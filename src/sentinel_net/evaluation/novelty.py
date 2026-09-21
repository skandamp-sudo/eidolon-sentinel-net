"""
Phase 8 — Novel Threat & Generalization Hardening.

Evaluates whether Sentinel-NET's anomaly detector can identify
attack behavior that supervised classifiers have not previously
observed during training.

All experiments classify results as:
    REAL_DATA | SIMULATED | SYNTHETIC | DOCUMENTATION_ONLY | NOT_APPLICABLE

INTERPRETATION:
    A high anomaly score indicates behaviour unlike the training distribution.
    It does NOT confirm an attack. Anomaly scores are NOT probabilities.
"""

from __future__ import annotations

import json
import time
from collections import Counter
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

import numpy as np
from sklearn.metrics import (
    precision_recall_fscore_support,
    roc_auc_score,
    average_precision_score,
    roc_curve,
    precision_recall_curve,
    f1_score,
)


# ═══════════════════════════════════════════════════════════════════════
# RESULT CATEGORIES
# ═══════════════════════════════════════════════════════════════════════

RESULT_CATEGORIES = frozenset({
    "REAL_DATA",
    "SIMULATED",
    "SYNTHETIC",
    "DOCUMENTATION_ONLY",
    "NOT_APPLICABLE",
})


def validate_result_category(category: str) -> str:
    """Validate and return a result category string."""
    if category not in RESULT_CATEGORIES:
        raise ValueError(
            f"Invalid result_category '{category}'. "
            f"Must be one of: {sorted(RESULT_CATEGORIES)}"
        )
    return category


# ═══════════════════════════════════════════════════════════════════════
# PROTOCOL STATE MACHINE
# ═══════════════════════════════════════════════════════════════════════

class ProtocolViolation(Exception):
    """Raised when an experiment protocol rule is violated."""


class Phase8Protocol:
    """Extended experiment state machine for Phase 8.

    States:
        DATA_LOADED → SPLIT_CREATED → TRAIN_LOCKED → VALIDATION_LOCKED
        → THRESHOLD_LOCKED → FINAL_TEST_LOCKED → EVALUATED → ARTIFACT_WRITTEN

    Once FINAL_TEST_LOCKED is reached:
        - no threshold changes
        - no hyperparameter changes
        - no feature selection changes
        - no retraining based on test results

    Attempting prohibited operations fails loudly with ProtocolViolation.
    """

    STATES = (
        "DATA_LOADED",
        "SPLIT_CREATED",
        "TRAIN_LOCKED",
        "VALIDATION_LOCKED",
        "THRESHOLD_LOCKED",
        "FINAL_TEST_LOCKED",
        "EVALUATED",
        "ARTIFACT_WRITTEN",
    )

    def __init__(self, experiment_id: str, random_seed: int = 42):
        self.experiment_id = experiment_id
        self.random_seed = random_seed
        self.state = "DATA_LOADED"
        self._split_info: dict[str, Any] | None = None
        self._train_info: dict[str, Any] | None = None
        self._val_info: dict[str, Any] | None = None
        self._threshold: float | None = None
        self._threshold_source: str | None = None
        self._test_info: dict[str, Any] | None = None
        self._metrics: dict[str, Any] | None = None
        self._start_time = time.time()

    def _require_state(self, *allowed: str) -> None:
        if self.state not in allowed:
            raise ProtocolViolation(
                f"Operation requires state in {allowed}, "
                f"current state: {self.state}"
            )

    def _advance(self, target: str) -> None:
        idx = self.STATES.index(target)
        cur = self.STATES.index(self.state)
        if idx != cur + 1:
            raise ProtocolViolation(
                f"Cannot advance from {self.state} to {target}. "
                f"Expected next state: {self.STATES[cur + 1]}"
            )
        self.state = target

    # ── Transitions ──

    def register_split(
        self,
        train_scenarios: list[str],
        val_scenarios: list[str],
        test_scenarios: list[str],
        n_train: int,
        n_val: int,
        n_test: int,
    ) -> None:
        """DATA_LOADED → SPLIT_CREATED."""
        self._require_state("DATA_LOADED")
        # Verify disjointness
        ts = set(train_scenarios)
        vs = set(val_scenarios)
        es = set(test_scenarios)
        if ts & vs or ts & es or vs & es:
            raise ProtocolViolation(
                "Scenario sets must be pairwise disjoint. "
                f"Overlaps: train∩val={ts & vs}, train∩test={ts & es}, val∩test={vs & es}"
            )
        self._split_info = {
            "train_scenarios": train_scenarios,
            "val_scenarios": val_scenarios,
            "test_scenarios": test_scenarios,
            "n_train": n_train,
            "n_val": n_val,
            "n_test": n_test,
        }
        self._advance("SPLIT_CREATED")

    def lock_training(self, train_classes: dict[str, int]) -> None:
        """SPLIT_CREATED → TRAIN_LOCKED."""
        self._require_state("SPLIT_CREATED")
        self._train_info = {"train_classes": train_classes}
        self._advance("TRAIN_LOCKED")

    def lock_validation(self, val_classes: dict[str, int]) -> None:
        """TRAIN_LOCKED → VALIDATION_LOCKED."""
        self._require_state("TRAIN_LOCKED")
        self._val_info = {"val_classes": val_classes}
        self._advance("VALIDATION_LOCKED")

    def lock_threshold(
        self, threshold: float, source: str
    ) -> None:
        """VALIDATION_LOCKED → THRESHOLD_LOCKED."""
        self._require_state("VALIDATION_LOCKED")
        if source not in ("default", "validation_optimized"):
            raise ValueError(
                f"source must be 'default' or 'validation_optimized', got '{source}'"
            )
        self._threshold = threshold
        self._threshold_source = source
        self._advance("THRESHOLD_LOCKED")

    def lock_test(self, test_classes: dict[str, int]) -> None:
        """THRESHOLD_LOCKED → FINAL_TEST_LOCKED."""
        self._require_state("THRESHOLD_LOCKED")
        self._test_info = {"test_classes": test_classes}
        self._advance("FINAL_TEST_LOCKED")

    def record_evaluation(self, metrics: dict[str, Any]) -> None:
        """FINAL_TEST_LOCKED → EVALUATED."""
        self._require_state("FINAL_TEST_LOCKED")
        self._metrics = metrics
        self._advance("EVALUATED")

    def write_artifact(self, artifact_path: str) -> None:
        """EVALUATED → ARTIFACT_WRITTEN."""
        self._require_state("EVALUATED")
        self._advance("ARTIFACT_WRITTEN")

    # ── Prohibited operations ──

    def assert_no_threshold_change(self) -> None:
        """Raise if we're past THRESHOLD_LOCKED."""
        locked_states = {"FINAL_TEST_LOCKED", "EVALUATED", "ARTIFACT_WRITTEN"}
        if self.state in locked_states:
            raise ProtocolViolation(
                f"Threshold changes prohibited in state {self.state}"
            )

    def assert_no_retraining(self) -> None:
        """Raise if we're past FINAL_TEST_LOCKED."""
        locked_states = {"FINAL_TEST_LOCKED", "EVALUATED", "ARTIFACT_WRITTEN"}
        if self.state in locked_states:
            raise ProtocolViolation(
                f"Retraining prohibited in state {self.state}"
            )

    # ── Manifest ──

    def to_manifest(self) -> dict[str, Any]:
        """Generate reproducibility manifest from current state."""
        runtime = time.time() - self._start_time
        return {
            "experiment_id": self.experiment_id,
            "random_seed": self.random_seed,
            "state": self.state,
            "split": self._split_info,
            "training": self._train_info,
            "validation": self._val_info,
            "threshold": self._threshold,
            "threshold_source": self._threshold_source,
            "test": self._test_info,
            "metrics_summary": bool(self._metrics),
            "runtime_seconds": round(runtime, 2),
        }


# ═══════════════════════════════════════════════════════════════════════
# DATA STRUCTURES
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class AttackFamilyFold:
    """Configuration for one leave-one-attack-family-out fold."""
    held_out_family: str
    held_out_scenarios: list[str]
    train_scenarios: list[str]
    val_scenarios: list[str]
    test_scenarios: list[str]
    n_train: int = 0
    n_val: int = 0
    n_test: int = 0
    train_classes: dict[str, int] = field(default_factory=dict)
    val_classes: dict[str, int] = field(default_factory=dict)
    test_classes: dict[str, int] = field(default_factory=dict)
    attack_prevalence: float = 0.0
    feasible: bool = True
    result_category: str = "REAL_DATA"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class NoveltyRankingResult:
    """Score distribution comparison between benign and unseen attacks."""
    benign_stats: dict[str, float]
    attack_stats: dict[str, float]
    roc_auc: float
    pr_auc: float
    score_separation: float  # median_attack - median_benign
    n_benign: int
    n_attack: int
    result_category: str = "REAL_DATA"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FusionPrediction:
    """A single fusion prediction."""
    category: str  # KNOWN_ATTACK, NOVEL_ANOMALY, BENIGN, UNCERTAIN
    supervised_pred: str
    supervised_confidence: float
    anomaly_score: float


# ═══════════════════════════════════════════════════════════════════════
# LEAVE-ONE-ATTACK-FAMILY-OUT
# ═══════════════════════════════════════════════════════════════════════

class LeaveOneAttackOut:
    """Leave-one-attack-family-out evaluation.

    For each eligible attack family:
        1. Hold out ALL scenarios containing that family
        2. Split remaining scenarios into train/val
        3. Train supervised + IForest on train
        4. Optimize threshold on val
        5. Evaluate on held-out scenarios
    """

    MIN_SAMPLES = 50  # Minimum attack samples for a feasible fold

    def __init__(self, random_seed: int = 42):
        self.random_seed = random_seed

    def _get_scenario_attack_map(
        self, labels: np.ndarray, scenarios: np.ndarray
    ) -> dict[str, set[str]]:
        """Map each scenario to the attack families it contains."""
        scenario_attacks: dict[str, set[str]] = {}
        for sc in np.unique(scenarios):
            mask = scenarios == sc
            classes = set(np.unique(labels[mask]))
            classes.discard("benign")
            scenario_attacks[sc] = classes
        return scenario_attacks

    def _get_family_scenarios(
        self, labels: np.ndarray, scenarios: np.ndarray
    ) -> dict[str, list[str]]:
        """Map each attack family to the scenarios containing it."""
        sc_map = self._get_scenario_attack_map(labels, scenarios)
        family_scenarios: dict[str, list[str]] = {}
        for sc, attacks in sc_map.items():
            for atk in attacks:
                family_scenarios.setdefault(atk, []).append(sc)
        return family_scenarios

    def get_eligible_families(
        self, labels: np.ndarray, scenarios: np.ndarray
    ) -> tuple[list[str], list[str]]:
        """Return (eligible, ineligible) attack families.

        A family is eligible if it has >= MIN_SAMPLES attack samples.
        """
        all_families = sorted(set(np.unique(labels)) - {"benign"})
        eligible = []
        ineligible = []
        for fam in all_families:
            count = int((labels == fam).sum())
            if count >= self.MIN_SAMPLES:
                eligible.append(fam)
            else:
                ineligible.append(fam)
        return eligible, ineligible

    def build_folds(
        self,
        labels: np.ndarray,
        scenarios: np.ndarray,
        val_ratio: float = 0.15,
    ) -> list[AttackFamilyFold]:
        """Build all LOAO folds.

        For each eligible family:
        - test_scenarios = all scenarios containing the family
        - remaining scenarios split into train/val by scenario count
        """
        eligible, ineligible = self.get_eligible_families(labels, scenarios)
        family_scen = self._get_family_scenarios(labels, scenarios)
        all_scenarios = sorted(np.unique(scenarios))
        rng = np.random.RandomState(self.random_seed)
        folds: list[AttackFamilyFold] = []

        for fam in eligible:
            # Test = scenarios containing the held-out family
            test_scens = sorted(family_scen.get(fam, []))
            # Remaining scenarios
            remaining = [s for s in all_scenarios if s not in test_scens]
            rng_fold = np.random.RandomState(self.random_seed)
            rng_fold.shuffle(remaining)

            # Split remaining into train/val by scenario count
            n_val = max(1, int(round(len(remaining) * val_ratio)))
            val_scens = sorted(remaining[:n_val])
            train_scens = sorted(remaining[n_val:])

            # Count samples
            train_mask = np.isin(scenarios, train_scens)
            val_mask = np.isin(scenarios, val_scens)
            test_mask = np.isin(scenarios, test_scens)

            train_cls = dict(Counter(labels[train_mask].tolist()))
            val_cls = dict(Counter(labels[val_mask].tolist()))
            test_cls = dict(Counter(labels[test_mask].tolist()))

            n_test = int(test_mask.sum())
            n_attack_test = int((labels[test_mask] != "benign").sum())
            prevalence = n_attack_test / n_test if n_test > 0 else 0.0

            fold = AttackFamilyFold(
                held_out_family=fam,
                held_out_scenarios=test_scens,
                train_scenarios=train_scens,
                val_scenarios=val_scens,
                test_scenarios=test_scens,
                n_train=int(train_mask.sum()),
                n_val=int(val_mask.sum()),
                n_test=n_test,
                train_classes=train_cls,
                val_classes=val_cls,
                test_classes=test_cls,
                attack_prevalence=round(prevalence, 6),
            )
            folds.append(fold)

        # Add NOT_APPLICABLE folds for ineligible families
        for fam in ineligible:
            count = int((labels == fam).sum())
            fold = AttackFamilyFold(
                held_out_family=fam,
                held_out_scenarios=family_scen.get(fam, []),
                train_scenarios=[],
                val_scenarios=[],
                test_scenarios=[],
                n_train=0,
                n_val=0,
                n_test=count,
                feasible=False,
                result_category="NOT_APPLICABLE",
            )
            folds.append(fold)

        return folds

    @staticmethod
    def get_fold_data(
        X: np.ndarray,
        labels: np.ndarray,
        scenarios: np.ndarray,
        fold: AttackFamilyFold,
    ) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        """Extract train/val/test arrays for a fold.

        Returns: (X_train, y_train, X_val, y_val, X_test, y_test)
        """
        train_mask = np.isin(scenarios, fold.train_scenarios)
        val_mask = np.isin(scenarios, fold.val_scenarios)
        test_mask = np.isin(scenarios, fold.test_scenarios)
        return (
            X[train_mask], labels[train_mask],
            X[val_mask], labels[val_mask],
            X[test_mask], labels[test_mask],
        )

    @staticmethod
    def verify_no_leakage(
        fold: AttackFamilyFold,
        y_train: np.ndarray,
    ) -> bool:
        """Verify the held-out family does NOT appear in training labels."""
        return fold.held_out_family not in set(y_train)


# ═══════════════════════════════════════════════════════════════════════
# NOVELTY RANKING
# ═══════════════════════════════════════════════════════════════════════

class NoveltyRanking:
    """Analyzes whether anomaly scores rank unseen attacks above benign traffic.

    INTERPRETATION:
        Anomaly scores are NOT probabilities.
        Higher score = more unlike training distribution.
    """

    @staticmethod
    def _distribution_stats(scores: np.ndarray) -> dict[str, float]:
        """Compute distribution statistics for a score array."""
        if len(scores) == 0:
            return {k: 0.0 for k in [
                "mean", "std", "median", "p25", "p75", "p90", "p95", "min", "max"
            ]}
        return {
            "mean": float(np.mean(scores)),
            "std": float(np.std(scores)),
            "median": float(np.median(scores)),
            "p25": float(np.percentile(scores, 25)),
            "p75": float(np.percentile(scores, 75)),
            "p90": float(np.percentile(scores, 90)),
            "p95": float(np.percentile(scores, 95)),
            "min": float(np.min(scores)),
            "max": float(np.max(scores)),
        }

    def analyze(
        self,
        benign_scores: np.ndarray,
        attack_scores: np.ndarray,
    ) -> NoveltyRankingResult:
        """Compute score distribution separation and ranking metrics.

        Args:
            benign_scores: Anomaly scores for benign samples.
            attack_scores: Anomaly scores for unseen-attack samples.

        Returns:
            NoveltyRankingResult with distribution stats and AUC metrics.
        """
        benign_stats = self._distribution_stats(benign_scores)
        attack_stats = self._distribution_stats(attack_scores)

        separation = attack_stats["median"] - benign_stats["median"]

        # Binary labels: 0=benign, 1=attack
        all_scores = np.concatenate([benign_scores, attack_scores])
        all_labels = np.concatenate([
            np.zeros(len(benign_scores), dtype=int),
            np.ones(len(attack_scores), dtype=int),
        ])

        try:
            roc_auc_val = float(roc_auc_score(all_labels, all_scores))
            if np.isnan(roc_auc_val):
                roc_auc_val = 0.0
            roc_auc = roc_auc_val
        except ValueError:
            roc_auc = 0.0

        try:
            pr_auc_val = float(average_precision_score(all_labels, all_scores))
            if np.isnan(pr_auc_val):
                pr_auc_val = 0.0
            pr_auc = pr_auc_val
        except ValueError:
            pr_auc = 0.0

        return NoveltyRankingResult(
            benign_stats=benign_stats,
            attack_stats=attack_stats,
            roc_auc=roc_auc,
            pr_auc=pr_auc,
            score_separation=round(separation, 6),
            n_benign=len(benign_scores),
            n_attack=len(attack_scores),
        )


# ═══════════════════════════════════════════════════════════════════════
# SUPERVISED + ANOMALY FUSION
# ═══════════════════════════════════════════════════════════════════════

class SupervisedAnomalyFusion:
    """Cascaded fusion of supervised classifier and anomaly detector.

    Strategy (cascade on validation-tuned thresholds):
        1. If supervised predicts a known attack class with
           confidence > tau_known → KNOWN_ATTACK
        2. Else if anomaly score > tau_anomaly → NOVEL_ANOMALY
        3. Else if supervised predicts benign AND
           anomaly score < tau_benign → BENIGN
        4. Else → UNCERTAIN

    All thresholds (tau_known, tau_anomaly, tau_benign) are selected
    on VALIDATION data only. No test-set tuning.
    """

    KNOWN_ATTACK = "KNOWN_ATTACK"
    NOVEL_ANOMALY = "NOVEL_ANOMALY"
    BENIGN = "BENIGN"
    UNCERTAIN = "UNCERTAIN"

    CATEGORIES = (KNOWN_ATTACK, NOVEL_ANOMALY, BENIGN, UNCERTAIN)

    def __init__(self) -> None:
        self.tau_known: float | None = None
        self.tau_anomaly: float | None = None
        self.tau_benign: float | None = None
        self._fitted = False

    def fit_thresholds(
        self,
        y_true: np.ndarray,
        supervised_preds: np.ndarray,
        supervised_conf: np.ndarray,
        anomaly_scores: np.ndarray,
        anomaly_threshold_candidates: list[float] | None = None,
    ) -> dict[str, float]:
        """Learn fusion thresholds on validation data.

        Strategy:
            - tau_known: supervised confidence threshold that maximizes
              precision for known-attack predictions on validation.
            - tau_anomaly: anomaly score threshold optimized for F1
              on validation binary labels (attack vs benign).
            - tau_benign: anomaly score below which we're confident
              the sample is benign (25th percentile of benign scores).

        Returns dict of selected thresholds.
        """
        if anomaly_threshold_candidates is None:
            anomaly_threshold_candidates = [
                round(t, 2) for t in np.arange(0.2, 0.9, 0.05)
            ]

        # tau_known: find confidence threshold that gives >=80% precision
        # for non-benign predictions
        known_attack_mask = (supervised_preds != "benign")
        if known_attack_mask.any():
            known_confs = supervised_conf[known_attack_mask]
            known_correct = (
                (y_true[known_attack_mask] != "benign")
                & (supervised_preds[known_attack_mask] == y_true[known_attack_mask])
            )
            # Try thresholds from 0.5 to 0.95
            best_tau = 0.5
            best_f1 = 0.0
            for tau in np.arange(0.5, 0.96, 0.05):
                above = known_confs >= tau
                if above.sum() == 0:
                    continue
                prec = known_correct[above].mean()
                rec = above.sum() / max(len(known_confs), 1)
                f1_val = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
                if f1_val > best_f1:
                    best_f1 = f1_val
                    best_tau = float(tau)
            self.tau_known = best_tau
        else:
            self.tau_known = 0.8  # Default if no attack predictions

        # tau_anomaly: maximize F1 for binary anomaly detection
        y_binary = (y_true != "benign").astype(int)
        best_tau_a = 0.5
        best_f1_a = 0.0
        for tau in anomaly_threshold_candidates:
            preds = (anomaly_scores >= tau).astype(int)
            f1_val = float(f1_score(y_binary, preds, zero_division=0))
            if f1_val > best_f1_a:
                best_f1_a = f1_val
                best_tau_a = tau
        self.tau_anomaly = best_tau_a

        # tau_benign: 25th percentile of benign anomaly scores
        benign_scores = anomaly_scores[y_true == "benign"]
        if len(benign_scores) > 0:
            self.tau_benign = float(np.percentile(benign_scores, 25))
        else:
            self.tau_benign = 0.3

        self._fitted = True
        return {
            "tau_known": self.tau_known,
            "tau_anomaly": self.tau_anomaly,
            "tau_benign": self.tau_benign,
        }

    def predict(
        self,
        supervised_preds: np.ndarray,
        supervised_conf: np.ndarray,
        anomaly_scores: np.ndarray,
    ) -> np.ndarray:
        """Classify samples using cascaded fusion.

        Returns array of fusion categories:
            KNOWN_ATTACK | NOVEL_ANOMALY | BENIGN | UNCERTAIN
        """
        if not self._fitted:
            raise RuntimeError(
                "Fusion thresholds not fitted. Call fit_thresholds() first."
            )

        n = len(supervised_preds)
        result = np.full(n, self.UNCERTAIN, dtype=object)

        for i in range(n):
            # Step 1: Known attack?
            if (
                supervised_preds[i] != "benign"
                and supervised_conf[i] >= self.tau_known
            ):
                result[i] = self.KNOWN_ATTACK
            # Step 2: Novel anomaly?
            elif anomaly_scores[i] >= self.tau_anomaly:
                result[i] = self.NOVEL_ANOMALY
            # Step 3: Confident benign?
            elif (
                supervised_preds[i] == "benign"
                and anomaly_scores[i] < self.tau_benign
            ):
                result[i] = self.BENIGN
            # Step 4: Uncertain
            else:
                result[i] = self.UNCERTAIN

        return result

    def evaluate(
        self,
        y_true: np.ndarray,
        fusion_preds: np.ndarray,
        known_classes: set[str] | None = None,
    ) -> dict[str, Any]:
        """Evaluate fusion predictions against ground truth.

        Args:
            y_true: True labels (class names).
            fusion_preds: Array of fusion categories.
            known_classes: Classes that were in the training set.

        Returns:
            Dictionary with per-category counts and metrics.
        """
        if known_classes is None:
            known_classes = set()

        n = len(y_true)
        counts = Counter(fusion_preds.tolist())

        # True positive analysis
        tp_known = 0  # Known attack correctly caught
        tp_novel = 0  # Unseen attack caught by anomaly
        tn_benign = 0  # Benign correctly identified
        fp_novel = 0  # Benign falsely flagged as novel
        fp_known = 0  # Benign falsely flagged as known
        fn_missed = 0  # Attack classified as benign

        for i in range(n):
            true_is_benign = y_true[i] == "benign"
            true_is_known_attack = (
                not true_is_benign and y_true[i] in known_classes
            )
            true_is_unseen_attack = (
                not true_is_benign and y_true[i] not in known_classes
            )

            pred = fusion_preds[i]
            if pred == self.KNOWN_ATTACK:
                if true_is_known_attack:
                    tp_known += 1
                elif true_is_benign:
                    fp_known += 1
            elif pred == self.NOVEL_ANOMALY:
                if not true_is_benign:
                    tp_novel += 1
                else:
                    fp_novel += 1
            elif pred == self.BENIGN:
                if true_is_benign:
                    tn_benign += 1
                else:
                    fn_missed += 1

        # Binary detection: any non-benign prediction = "detected"
        y_binary_true = (y_true != "benign").astype(int)
        y_binary_pred = np.where(
            np.isin(fusion_preds, [self.KNOWN_ATTACK, self.NOVEL_ANOMALY]),
            1, 0,
        )
        precision, recall, f1, _ = precision_recall_fscore_support(
            y_binary_true, y_binary_pred, average="binary", zero_division=0
        )

        return {
            "category_counts": dict(counts),
            "tp_known_attack": tp_known,
            "tp_novel_anomaly": tp_novel,
            "tn_benign": tn_benign,
            "fp_known": fp_known,
            "fp_novel": fp_novel,
            "fn_missed_as_benign": fn_missed,
            "n_uncertain": int(counts.get(self.UNCERTAIN, 0)),
            "binary_precision": float(precision),
            "binary_recall": float(recall),
            "binary_f1": float(f1),
            "n_total": n,
            "thresholds": {
                "tau_known": self.tau_known,
                "tau_anomaly": self.tau_anomaly,
                "tau_benign": self.tau_benign,
            },
        }


# ═══════════════════════════════════════════════════════════════════════
# THRESHOLD ANALYSIS (MULTI-OPERATING-POINT)
# ═══════════════════════════════════════════════════════════════════════

class MultiOperatingPointAnalysis:
    """Evaluate anomaly detection at multiple operating points.

    Reports: default, validation-optimal, recall@1%FPR, recall@5%FPR,
    full ROC curve, full PR curve.
    """

    @staticmethod
    def analyze(
        y_true_binary: np.ndarray,
        scores: np.ndarray,
        val_optimal_threshold: float,
        default_threshold: float = 0.5,
    ) -> dict[str, Any]:
        """Compute multi-operating-point analysis.

        Args:
            y_true_binary: Binary labels (0=benign, 1=attack).
            scores: Anomaly scores.
            val_optimal_threshold: Threshold from validation optimization.
            default_threshold: Default threshold.

        Returns:
            Dictionary with operating points and curve data.
        """
        results: dict[str, Any] = {}

        try:
            fpr_curve, tpr_curve, roc_thresholds = roc_curve(
                y_true_binary, scores
            )
            roc_auc = float(roc_auc_score(y_true_binary, scores))
            if np.isnan(roc_auc):
                roc_auc = 0.0
        except ValueError:
            fpr_curve = np.array([0.0, 1.0])
            tpr_curve = np.array([0.0, 1.0])
            roc_thresholds = np.array([1.0, 0.0])
            roc_auc = 0.0

        results["roc_auc"] = roc_auc
        # Subsample ROC curve for storage
        if len(fpr_curve) > 200:
            indices = np.linspace(0, len(fpr_curve) - 1, 200, dtype=int)
            fpr_sub = fpr_curve[indices]
            tpr_sub = tpr_curve[indices]
        else:
            fpr_sub = fpr_curve
            tpr_sub = tpr_curve
        results["roc_curve"] = {
            "fpr": [round(float(v), 6) for v in fpr_sub],
            "tpr": [round(float(v), 6) for v in tpr_sub],
        }

        try:
            prec_curve, rec_curve, pr_thresholds = precision_recall_curve(
                y_true_binary, scores
            )
            pr_auc = float(average_precision_score(y_true_binary, scores))
            if np.isnan(pr_auc):
                pr_auc = 0.0
        except ValueError:
            prec_curve = np.array([0.0])
            rec_curve = np.array([1.0])
            pr_auc = 0.0
        results["pr_auc"] = pr_auc

        # Operating points
        def _metrics_at_threshold(thresh: float) -> dict[str, float]:
            preds = (scores >= thresh).astype(int)
            tp = int(((preds == 1) & (y_true_binary == 1)).sum())
            fp = int(((preds == 1) & (y_true_binary == 0)).sum())
            fn = int(((preds == 0) & (y_true_binary == 1)).sum())
            tn = int(((preds == 0) & (y_true_binary == 0)).sum())
            prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
            fpr_val = fp / (fp + tn) if (fp + tn) > 0 else 0.0
            return {
                "threshold": thresh,
                "precision": round(prec, 6),
                "recall": round(rec, 6),
                "f1": round(f1, 6),
                "fpr": round(fpr_val, 6),
                "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            }

        results["default"] = _metrics_at_threshold(default_threshold)
        results["validation_optimal"] = _metrics_at_threshold(
            val_optimal_threshold
        )

        # Recall at fixed FPR
        for target_fpr in [0.01, 0.05]:
            label = f"recall_at_{int(target_fpr * 100)}pct_fpr"
            # Find threshold closest to target FPR on ROC curve
            idx = np.argmin(np.abs(fpr_curve - target_fpr))
            actual_fpr = float(fpr_curve[idx])
            recall_at_fpr = float(tpr_curve[idx])
            # Find corresponding threshold
            if idx < len(roc_thresholds):
                thresh_at_fpr = float(roc_thresholds[idx])
            else:
                thresh_at_fpr = float(roc_thresholds[-1])
            results[label] = {
                "target_fpr": target_fpr,
                "actual_fpr": round(actual_fpr, 6),
                "recall": round(recall_at_fpr, 6),
                "threshold": round(thresh_at_fpr, 6),
            }

        return results


# ═══════════════════════════════════════════════════════════════════════
# FALSE POSITIVE ANALYSIS (CATEGORIZED)
# ═══════════════════════════════════════════════════════════════════════

class CategorizedFPAnalysis:
    """Categorize anomaly-based false positives by scenario, score range,
    and feature group.

    Does NOT claim production SOC suitability from a single dataset.
    """

    SCORE_RANGES = [
        (0.0, 0.4, "0.0-0.4"),
        (0.4, 0.5, "0.4-0.5"),
        (0.5, 0.6, "0.5-0.6"),
        (0.6, 0.7, "0.6-0.7"),
        (0.7, 1.0, "0.7-1.0"),
    ]

    @staticmethod
    def analyze(
        anomaly_scores: np.ndarray,
        y_true: np.ndarray,
        anomaly_preds: np.ndarray,
        scenarios: np.ndarray,
        threshold: float,
    ) -> dict[str, Any]:
        """Analyze false positives from anomaly detection.

        Args:
            anomaly_scores: Raw anomaly scores.
            y_true: True labels.
            anomaly_preds: Binary predictions (1=anomaly).
            scenarios: Scenario IDs per sample.
            threshold: Threshold used for predictions.

        Returns:
            Categorized FP analysis.
        """
        # FP = benign predicted as anomaly
        fp_mask = (y_true == "benign") & (anomaly_preds == 1)
        total_fp = int(fp_mask.sum())
        total_benign = int((y_true == "benign").sum())

        # By scenario
        by_scenario: dict[str, dict[str, Any]] = {}
        for sc in np.unique(scenarios):
            sc_mask = (scenarios == sc) & (y_true == "benign")
            sc_fp = int((sc_mask & fp_mask).sum())
            sc_total = int(sc_mask.sum())
            by_scenario[str(sc)] = {
                "false_positives": sc_fp,
                "total_benign": sc_total,
                "fp_rate": round(sc_fp / max(sc_total, 1), 6),
            }

        # By score range
        by_score_range: dict[str, int] = {}
        fp_scores = anomaly_scores[fp_mask]
        for lo, hi, label in CategorizedFPAnalysis.SCORE_RANGES:
            count = int(((fp_scores >= lo) & (fp_scores < hi)).sum())
            by_score_range[label] = count

        return {
            "total_false_positives": total_fp,
            "total_benign": total_benign,
            "fpr": round(total_fp / max(total_benign, 1), 6),
            "threshold": threshold,
            "by_scenario": by_scenario,
            "by_score_range": by_score_range,
        }
