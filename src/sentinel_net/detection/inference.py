"""
Detection inference pipeline for EIDOLON // SENTINEL-NET.

Chains: FeatureVector → Preprocessing → Anomaly Detection → Classification → DetectionEvent

SECURITY: No network I/O. No payload inspection. No traffic decryption.
Pure computation pipeline consuming pre-extracted FeatureVectors.
"""

import logging
import time
import uuid

import numpy as np

from sentinel_net.detection.anomaly import AnomalyDetector
from sentinel_net.detection.classifier import BaseClassifier
from sentinel_net.detection.preprocessing import FeaturePreprocessor
from sentinel_net.detection.thresholds import ThresholdConfig
from sentinel_net.features.schema import FEATURE_SCHEMA_VERSION
from sentinel_net.models.enums import Severity
from sentinel_net.models.types import (
    AnomalyResult,
    DetectionEvent,
    FeatureVector,
    ObservedFlow,
    ThreatClassification,
)

logger = logging.getLogger(__name__)


class DetectionPipeline:
    """Complete detection pipeline: FeatureVector → DetectionEvent.

    Chains preprocessing, anomaly scoring, and threat classification
    to produce structured detection events with full evidence provenance.
    """

    def __init__(
        self,
        preprocessor: FeaturePreprocessor,
        anomaly_detector: AnomalyDetector,
        classifier: BaseClassifier,
        thresholds: ThresholdConfig | None = None,
        anomaly_explainer=None,
    ) -> None:
        self.preprocessor = preprocessor
        self.anomaly_detector = anomaly_detector
        self.classifier = classifier
        self.thresholds = thresholds or ThresholdConfig()
        self._anomaly_explainer = anomaly_explainer
        self._enricher = None

    def _enrich(self, event, transformed):
        from sentinel_net.explainability.enrichment import EventEnricher
        if self._enricher is None:
            self._enricher = EventEnricher(
                self.classifier, self.preprocessor.output_feature_names, self._anomaly_explainer)
        return self._enricher.enrich(event, transformed)

    def detect_single(
        self, fv: FeatureVector, flow: ObservedFlow | None = None
    ) -> DetectionEvent:
        """Detect threats from a single FeatureVector.

        Args:
            fv: Extracted feature vector.
            flow: Optional source ObservedFlow for provenance.

        Returns:
            DetectionEvent with anomaly score, threat label, and evidence.
        """
        # Use fv.values (ordered list), NOT fv.features (dict)
        X = np.array(fv.values, dtype=np.float64).reshape(1, -1)

        # Preprocess
        X_pp = self.preprocessor.transform(X)

        # Anomaly score (normalized to [0, 1])
        anomaly_score = float(self.anomaly_detector.score(X_pp)[0])
        is_anomalous = self.thresholds.is_anomalous(anomaly_score)

        # Classification
        threat_label = str(self.classifier.predict(X_pp)[0])
        scored_class = threat_label
        scores_dict = self.classifier.predict_scores(X_pp)
        # Get confidence for predicted class
        confidence = float(scores_dict.get(threat_label, np.zeros(1))[0])

        # If confidence is below minimum, mark as unknown
        if confidence < self.thresholds.min_confidence:
            threat_label = "unknown"

        # Severity
        severity = self.thresholds.get_severity(anomaly_score)

        now = time.time()

        anomaly_result = AnomalyResult(
            flow_key=fv.flow_key,
            timestamp=now,
            anomaly_score=anomaly_score,
            is_anomalous=is_anomalous,
            model_name=self.anomaly_detector.model_name,
            model_version=self.anomaly_detector.model_version,
        )

        threat_classification = ThreatClassification(
            flow_key=fv.flow_key,
            timestamp=now,
            threat_type=threat_label,
            confidence=confidence,
            model_name=self.classifier.model_name,
            model_version=self.classifier.model_version,
        )

        rationale = (
            f"Anomaly score: {anomaly_score:.2f} "
            f"(threshold: {self.thresholds.anomaly_threshold}). "
            f"Classified as {threat_label} with confidence {confidence:.2f}."
        )

        event = DetectionEvent(
            id=str(uuid.uuid4()),
            timestamp=now,
            flow_key=fv.flow_key,
            observed_flow=flow,
            feature_vector=fv,
            anomaly_result=anomaly_result,
            threat_classification=threat_classification,
            severity=severity,
            rationale=rationale,
            metadata={
                "classification_score_class": scored_class,
                "feature_schema_version": FEATURE_SCHEMA_VERSION,
                "anomaly_model": self.anomaly_detector.model_name,
                "classifier_model": self.classifier.model_name,
            },
        )
        return self._enrich(event, X_pp)

    def detect_batch(
        self,
        feature_vectors: list[FeatureVector],
        flows: list[ObservedFlow] | None = None,
    ) -> list[DetectionEvent]:
        """Detect threats from multiple FeatureVectors efficiently.

        Preprocesses and scores in batch, then builds individual events.
        """
        if not feature_vectors:
            return []

        # Stack feature values (use .values, not .features)
        X = np.array([fv.values for fv in feature_vectors], dtype=np.float64)

        # Preprocess once
        X_pp = self.preprocessor.transform(X)

        # Score and classify once
        anomaly_scores = self.anomaly_detector.score(X_pp)
        threat_labels = self.classifier.predict(X_pp)
        scores_dict = self.classifier.predict_scores(X_pp)

        now = time.time()
        events = []

        for i, fv in enumerate(feature_vectors):
            flow = flows[i] if flows else None
            a_score = float(anomaly_scores[i])
            is_anom = self.thresholds.is_anomalous(a_score)
            label = str(threat_labels[i])
            scored_class = label
            conf = float(scores_dict.get(label, np.zeros(len(X)))[i])

            if conf < self.thresholds.min_confidence:
                label = "unknown"

            severity = self.thresholds.get_severity(a_score)

            anomaly_result = AnomalyResult(
                flow_key=fv.flow_key,
                timestamp=now,
                anomaly_score=a_score,
                is_anomalous=is_anom,
                model_name=self.anomaly_detector.model_name,
                model_version=self.anomaly_detector.model_version,
            )

            threat_classification = ThreatClassification(
                flow_key=fv.flow_key,
                timestamp=now,
                threat_type=label,
                confidence=conf,
                model_name=self.classifier.model_name,
                model_version=self.classifier.model_version,
            )

            rationale = (
                f"Anomaly score: {a_score:.2f} "
                f"(threshold: {self.thresholds.anomaly_threshold}). "
                f"Classified as {label} with confidence {conf:.2f}."
            )

            events.append(DetectionEvent(
                id=str(uuid.uuid4()),
                timestamp=now,
                flow_key=fv.flow_key,
                observed_flow=flow,
                feature_vector=fv,
                anomaly_result=anomaly_result,
                threat_classification=threat_classification,
                severity=severity,
                rationale=rationale,
                metadata={
                    "classification_score_class": scored_class,
                    "feature_schema_version": FEATURE_SCHEMA_VERSION,
                    "anomaly_model": self.anomaly_detector.model_name,
                    "classifier_model": self.classifier.model_name,
                },
            ))
            self._enrich(events[-1], X_pp[i:i + 1])

        return events
