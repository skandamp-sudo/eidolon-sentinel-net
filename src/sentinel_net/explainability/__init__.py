"""
Explainability subsystem for EIDOLON // SENTINEL-NET.

Provides structured evidence, SHAP-based model explanations,
anomaly explanations, human-readable rationale, MITRE ATT&CK mapping,
and composite ExplainableDetection objects.

SECURITY: No network I/O. No payload inspection. No traffic decryption.
SHAP is an OPTIONAL dependency — core detection works without it.
"""

from sentinel_net.explainability.evidence import Evidence, EvidenceCollection
from sentinel_net.explainability.explainable_detection import ExplainableDetection
from sentinel_net.explainability.rationale import RationaleGenerator
from sentinel_net.explainability.anomaly_explainer import AnomalyExplainer
from sentinel_net.explainability.attack_mapping import ATTACKMapping, ATTACKMapper

__all__ = [
    "Evidence",
    "EvidenceCollection",
    "ExplainableDetection",
    "RationaleGenerator",
    "AnomalyExplainer",
    "ATTACKMapping",
    "ATTACKMapper",
]
