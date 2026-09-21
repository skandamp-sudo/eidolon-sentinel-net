"""Explicit offline training; never imported by deployment runtime."""

import logging
import time
from pathlib import Path
from sentinel_net.detection.anomaly import AnomalyDetector
from sentinel_net.detection.audit import TREE_MODEL_FEATURES
from sentinel_net.detection.classifier import XGBoostClassifier
from sentinel_net.detection.inference import DetectionPipeline
from sentinel_net.detection.preprocessing import FeaturePreprocessor
from sentinel_net.detection.thresholds import ThresholdConfig
from sentinel_net.evaluation.adapters import CICIDSAdapter
from sentinel_net.explainability.anomaly_explainer import AnomalyExplainer

logger = logging.getLogger(__name__)
RANDOM_SEED = 42


async def train_detection_pipeline(
    dataset_dir: Path,
) -> DetectionPipeline:
    """Train the production ML pipeline from CICIDS2017 data.

    This mirrors the Phase 7 evaluation training (Experiment A) but uses
    only the XGBoost classifier + IsolationForest anomaly detector, which
    are the production models.

    Returns:
        A fully trained DetectionPipeline ready for inference.
    """
    logger.info("Loading CICIDS2017 dataset from %s ...", dataset_dir)
    t0 = time.time()
    X, labels, _scenarios = CICIDSAdapter.load_all(dataset_dir)
    logger.info(
        "  Loaded %s rows × %d features in %.1fs",
        f"{X.shape[0]:,}",
        X.shape[1],
        time.time() - t0,
    )

    # Preprocessor (tree-model feature subset — handles NaN imputation)
    logger.info("Fitting preprocessor ...")
    preprocessor = FeaturePreprocessor(feature_subset=TREE_MODEL_FEATURES, random_state=RANDOM_SEED)
    X_pp = preprocessor.fit_transform(X)

    # XGBoost classifier
    logger.info("Training XGBoost classifier ...")
    t0 = time.time()
    classifier = XGBoostClassifier(n_estimators=100, max_depth=6, random_state=RANDOM_SEED)
    classifier.train(X_pp, labels)
    logger.info("  XGBoost trained in %.1fs", time.time() - t0)

    # Isolation Forest (benign only)
    logger.info("Training IsolationForest anomaly detector ...")
    t0 = time.time()
    benign_mask = labels == "benign"
    anomaly_detector = AnomalyDetector(n_estimators=100, random_state=RANDOM_SEED)
    anomaly_detector.train(X_pp[benign_mask])
    logger.info(
        "  IForest trained in %.1fs on %s benign samples",
        time.time() - t0,
        f"{benign_mask.sum():,}",
    )

    return DetectionPipeline(
        preprocessor=preprocessor,
        anomaly_detector=anomaly_detector,
        classifier=classifier,
        thresholds=ThresholdConfig(),
        anomaly_explainer=AnomalyExplainer(feature_names=preprocessor.output_feature_names).fit(
            X_pp[benign_mask]
        ),
    )
