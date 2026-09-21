"""Attach existing explainers without changing model scores or thresholds."""
import logging

from sentinel_net.explainability.attack_mapping import ATTACKMapper
from sentinel_net.explainability.evidence import EvidenceCollection
from sentinel_net.explainability.explainable_detection import ExplainableDetection
from sentinel_net.explainability.rationale import RationaleGenerator
from sentinel_net.explainability.shap_explainer import SHAPExplainer

logger = logging.getLogger(__name__)


class EventEnricher:
    def __init__(self, classifier, feature_names, anomaly_explainer=None):
        self.classifier = classifier
        self.anomaly_explainer = anomaly_explainer
        self.classifier_explainer = SHAPExplainer(
            getattr(classifier, '_model', None), classifier.model_name,
            classifier.model_version, classifier.supported_classes,
            feature_names=feature_names,
        )

    def enrich(self, event, transformed):
        tc, ar = event.threat_classification, event.anomaly_result
        label = event.metadata.get('classification_score_class', tc.threat_type)
        try:
            idx = self.classifier.supported_classes.index(label)
            classifier_evidence = self.classifier_explainer.explain(transformed, idx)
        except Exception:
            logger.exception('Classifier explanation failed for event %s', event.id)
            classifier_evidence = EvidenceCollection.unavailable('Classifier explanation failed.')
        anomaly_evidence = EvidenceCollection.unavailable('Training baseline not supplied to anomaly explainer.')
        if self.anomaly_explainer is not None:
            try:
                anomaly_evidence = self.anomaly_explainer.explain(transformed, ar.anomaly_score)
            except Exception:
                logger.exception('Anomaly explanation failed for event %s', event.id)
                anomaly_evidence = EvidenceCollection.unavailable('Anomaly explanation failed.')
        # Classification alone supports only a possible contextual mapping.
        mappings = ATTACKMapper().map(tc.threat_type)
        explanation = ExplainableDetection(
            event, classifier_evidence, anomaly_evidence, attack_mappings=mappings)
        explanation.rationale = RationaleGenerator().generate(
            tc.threat_type, ar.anomaly_score, tc.model_name, explanation.all_evidence,
            mappings, confidence=tc.confidence)
        data = explanation.to_dict()
        data['evidence'] = explanation.all_evidence.to_dict()
        data['evidence_value_space'] = 'standardized_model_input'
        event.metadata['explanation'] = data
        return event
