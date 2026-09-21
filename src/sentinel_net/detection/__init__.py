"""
Detection module for EIDOLON // SENTINEL-NET.
"""

from .anomaly import AnomalyDetector
from .classifier import BaseClassifier, XGBoostClassifier, RandomForestBaseline, LogisticRegressionBaseline
from .dataset import DatasetBuilder, DatasetSplit, LabelMapper
from .inference import DetectionPipeline
from .preprocessing import FeaturePreprocessor
from .registry import ModelRegistry, ModelManifest
from .evaluation import ClassificationReport, AnomalyReport
from .thresholds import ThresholdConfig
from .audit import FEATURE_AUDIT, ML_SAFE_FEATURES, NOMINAL_FEATURES, TREE_MODEL_FEATURES, LINEAR_MODEL_FEATURES

__all__ = [
    "AnomalyDetector",
    "BaseClassifier",
    "XGBoostClassifier",
    "RandomForestBaseline",
    "LogisticRegressionBaseline",
    "DatasetBuilder",
    "DatasetSplit",
    "LabelMapper",
    "DetectionPipeline",
    "FeaturePreprocessor",
    "ModelRegistry",
    "ModelManifest",
    "ClassificationReport",
    "AnomalyReport",
    "ThresholdConfig",
    "FEATURE_AUDIT",
    "ML_SAFE_FEATURES",
    "NOMINAL_FEATURES",
    "TREE_MODEL_FEATURES",
    "LINEAR_MODEL_FEATURES",
]
