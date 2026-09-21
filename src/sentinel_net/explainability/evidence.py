"""
Structured evidence model for explainable detections.

Every Evidence item is traceable to actual FeatureVector data.
No invented evidence. No causal claims.

Evidence types:
- "model": Contribution derived from model's decision mechanism (e.g., SHAP values)
- "statistical": Deviation from training distribution (mean ± std)
- "heuristic": Rule-based or threshold-based evidence

SECURITY: Pure data structures. No I/O.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Evidence:
    """A single piece of evidence supporting a detection decision.

    Attributes:
        feature_name: Name from canonical FEATURE_SCHEMA.
        observed_value: The actual value from the FeatureVector.
        reference_value: Baseline/expected value (e.g., training mean). None if unavailable.
        contribution: Numerical contribution to the decision. Interpretation depends on evidence_type.
        direction: "increase" or "decrease" — how this feature influenced the decision.
        evidence_type: "model" (SHAP/model-derived), "statistical" (distributional), "heuristic" (rule-based).
        source: What generated this evidence (e.g., "shap_tree_explainer", "training_distribution").
        model_name: Name of the model that produced this evidence.
        model_version: Version of the model.
        feature_schema_version: Schema version of the FeatureVector.
    """

    feature_name: str
    observed_value: float
    reference_value: float | None
    contribution: float
    direction: str  # "increase" | "decrease"
    evidence_type: str  # "model" | "statistical" | "heuristic"
    source: str
    model_name: str
    model_version: str
    feature_schema_version: str

    def __post_init__(self) -> None:
        if self.evidence_type not in ("model", "statistical", "heuristic"):
            raise ValueError(
                f"evidence_type must be 'model', 'statistical', or 'heuristic', "
                f"got '{self.evidence_type}'"
            )
        if self.direction not in ("increase", "decrease"):
            raise ValueError(
                f"direction must be 'increase' or 'decrease', got '{self.direction}'"
            )

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Evidence:
        return cls(**d)


@dataclass
class EvidenceCollection:
    """Ordered collection of evidence items with metadata.

    Evidence is sorted by |contribution| descending.
    """

    items: list[Evidence] = field(default_factory=list)
    explanation_available: bool = True
    unavailable_reason: str | None = None

    @classmethod
    def unavailable(cls, reason: str) -> EvidenceCollection:
        """Create a collection indicating explanation is unavailable."""
        return cls(
            items=[],
            explanation_available=False,
            unavailable_reason=reason,
        )

    @property
    def top_k(self) -> list[Evidence]:
        """Return top 5 evidence items by absolute contribution."""
        return sorted(self.items, key=lambda e: abs(e.contribution), reverse=True)[:5]

    @property
    def model_evidence(self) -> list[Evidence]:
        return [e for e in self.items if e.evidence_type == "model"]

    @property
    def statistical_evidence(self) -> list[Evidence]:
        return [e for e in self.items if e.evidence_type == "statistical"]

    def to_dict(self) -> dict[str, Any]:
        return {
            "items": [e.to_dict() for e in self.items],
            "explanation_available": self.explanation_available,
            "unavailable_reason": self.unavailable_reason,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> EvidenceCollection:
        items = [Evidence.from_dict(item) for item in d.get("items", [])]
        return cls(
            items=items,
            explanation_available=d.get("explanation_available", True),
            unavailable_reason=d.get("unavailable_reason"),
        )
