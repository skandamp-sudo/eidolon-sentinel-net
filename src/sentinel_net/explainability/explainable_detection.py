"""
Composite ExplainableDetection — combines DetectionEvent + Evidence + Rationale + ATT&CK.

Does NOT mutate the original DetectionEvent.
Preserves complete model provenance and explanation versioning.

SECURITY: No network I/O. Pure data composition.
"""

from __future__ import annotations

import dataclasses
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from sentinel_net.explainability.attack_mapping import ATTACKMapping
from sentinel_net.explainability.evidence import EvidenceCollection
from sentinel_net.models.types import DetectionEvent

EXPLANATION_VERSION = "1.0.0"


@dataclass
class ExplainableDetection:
    """Composite type: DetectionEvent + Evidence + Rationale + ATT&CK mapping.

    The original DetectionEvent is NOT modified. This wraps it with
    additional explanation metadata for forensic auditability.

    Attributes:
        detection_event: The original, unmodified DetectionEvent.
        classifier_evidence: Model-derived evidence from SHAP (if available).
        anomaly_evidence: Statistical deviation evidence from anomaly explainer.
        rationale: Human-readable explanation string.
        attack_mappings: Potential MITRE ATT&CK technique mappings.
        explanation_version: Version of the explanation format.
        generation_timestamp: When this explanation was generated.
        explanation_id: Unique ID for this explanation instance.
    """

    detection_event: DetectionEvent
    classifier_evidence: EvidenceCollection = field(
        default_factory=EvidenceCollection
    )
    anomaly_evidence: EvidenceCollection = field(
        default_factory=EvidenceCollection
    )
    rationale: str = ""
    attack_mappings: list[ATTACKMapping] = field(default_factory=list)
    explanation_version: str = EXPLANATION_VERSION
    generation_timestamp: float = field(default_factory=time.time)
    explanation_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    @property
    def detection_event_id(self) -> str:
        return self.detection_event.id

    @property
    def threat_type(self) -> str:
        tc = self.detection_event.threat_classification
        return tc.threat_type if tc else "unknown"

    @property
    def anomaly_score(self) -> float | None:
        ar = self.detection_event.anomaly_result
        return ar.anomaly_score if ar else None

    @property
    def confidence(self) -> float | None:
        tc = self.detection_event.threat_classification
        return tc.confidence if tc else None

    @property
    def severity(self) -> str:
        return self.detection_event.severity

    @property
    def all_evidence(self) -> EvidenceCollection:
        """Merge classifier and anomaly evidence into one collection."""
        all_items = (
            self.classifier_evidence.items + self.anomaly_evidence.items
        )
        available = (
            self.classifier_evidence.explanation_available
            or self.anomaly_evidence.explanation_available
        )
        reason = None
        if not available:
            reasons = []
            if self.classifier_evidence.unavailable_reason:
                reasons.append(self.classifier_evidence.unavailable_reason)
            if self.anomaly_evidence.unavailable_reason:
                reasons.append(self.anomaly_evidence.unavailable_reason)
            reason = "; ".join(reasons)

        return EvidenceCollection(
            items=sorted(all_items, key=lambda e: abs(e.contribution), reverse=True),
            explanation_available=available,
            unavailable_reason=reason,
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize for storage/API."""
        return {
            "explanation_id": self.explanation_id,
            "detection_event_id": self.detection_event_id,
            "explanation_version": self.explanation_version,
            "generation_timestamp": self.generation_timestamp,
            "threat_type": self.threat_type,
            "anomaly_score": self.anomaly_score,
            "confidence": self.confidence,
            "severity": self.severity,
            "rationale": self.rationale,
            "classifier_evidence": self.classifier_evidence.to_dict(),
            "anomaly_evidence": self.anomaly_evidence.to_dict(),
            "attack_mappings": [m.to_dict() for m in self.attack_mappings],
        }
