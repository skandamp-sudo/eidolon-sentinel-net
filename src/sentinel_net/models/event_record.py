"""Versioned public event contract shared by persistence, REST and WebSocket."""
from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator


def metadata_evidence(metadata: dict) -> dict:
    """Preserve existing explanation layouts, including historical enriched rows."""
    explanation = metadata.get('explanation', metadata)
    if not isinstance(explanation, dict):
        explanation = metadata
    if isinstance(explanation.get('evidence'), dict):
        return explanation['evidence']
    collections = [explanation[k] for k in ('classifier_evidence', 'anomaly_evidence')
                   if isinstance(explanation.get(k), dict)]
    if not collections:
        return {'items': [], 'explanation_available': False,
                'unavailable_reason': 'Evidence was not recorded for this event.'}
    available = any(c.get('explanation_available', True) for c in collections)
    return {
        'items': sorted([item for c in collections for item in c.get('items', [])],
                        key=lambda item: abs(item['contribution']), reverse=True),
        'explanation_available': available,
        'unavailable_reason': None if available else '; '.join(
            c['unavailable_reason'] for c in collections if c.get('unavailable_reason')),
    }


class EventRecord(BaseModel):
    # Legacy rows are readable, but unavailable values are never reconstructed.
    event_schema_version: str = '1.0.0'
    id: str
    event_id: str
    timestamp: float
    created_at: float
    flow_id: str | None = None
    severity: str
    threat_type: str | None = None
    threat_class: str | None = None
    classification_score: float | None = None
    classification_score_type: str | None = None
    classification_score_class: str | None = None
    anomaly_score: float | None = None
    anomaly_score_type: str | None = None
    detection_source: list[str] = Field(default_factory=list)
    source_mode: Literal['LIVE', 'REPLAY'] | None = None
    capture_interface: str | None = None
    replay_file_identifier: str | None = None
    model_name: str | None = None
    deployment_model_version: str | None = None
    model_manifest_sha256: str | None = None
    model_version: str | None = None
    anomaly_model_version: str | None = None
    feature_schema_version: str | None = None
    explanation_version: str | None = None
    evidence: dict[str, Any] = Field(default_factory=lambda: {
        'items': [], 'explanation_available': False,
        'unavailable_reason': 'Evidence was not recorded for this event.',
    })
    rationale: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    protocol: int | None = None

    model_config = {'extra': 'allow', 'allow_inf_nan': False}

    @model_validator(mode='before')
    @classmethod
    def legacy_aliases(cls, value):
        if isinstance(value, dict):
            value = dict(value)
            value.setdefault('event_id', value.get('id'))
            value.setdefault('threat_class', value.get('threat_type'))
            deployment = value.get('metadata', {}).get('deployment_model', {})
            if isinstance(deployment, dict):
                for target, key in (('model_name', 'model_name'), ('deployment_model_version', 'model_version'), ('model_manifest_sha256', 'manifest_sha256')):
                    value.setdefault(target, deployment.get(key))
            source = value.get('metadata', {}).get('source', {})
            if isinstance(source, dict):
                for key in ('source_mode', 'capture_interface', 'replay_file_identifier'):
                    value.setdefault(key, source.get(key))
        return value

    @model_validator(mode='after')
    def consistent_aliases(self):
        if self.id != self.event_id or self.threat_type != self.threat_class:
            raise ValueError('Event identity/class aliases must agree')
        return self
