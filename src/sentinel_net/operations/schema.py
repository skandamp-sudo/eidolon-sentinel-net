"""Versioned analyst export envelope; nested event fields are allowlisted separately."""

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, allow_inf_nan=False)


class EvidenceReference(StrictModel):
    event_id: str
    signal_type: str
    reference: str


class TimelineItem(EvidenceReference):
    timestamp: float
    clock: Literal["capture_event_time", "processing_time", "event_timestamp_unspecified"]
    description: str
    source: Literal["LIVE", "REPLAY"] | None


class Correlation(StrictModel):
    correlation_id: str
    label: Literal["CORRELATED OBSERVATION", "RECORDED OBSERVATION"]
    contributing_event_ids: list[str] = Field(max_length=32)
    contributing_signal_types: list[str]
    source_count: int
    evidence_count: int
    first_seen: float
    last_seen: float
    time_basis: str
    summary: str


class InvestigationExport(StrictModel):
    export_schema_version: Literal["1.0.0"]
    investigation_id: str
    anchor_event_id: str
    correlation: Correlation
    events: list[dict[str, Any]] = Field(min_length=1, max_length=32)
    evidence_references: list[EvidenceReference] = Field(max_length=256)
    timeline: list[TimelineItem] = Field(max_length=512)
    limitations: list[str]
    bounds: dict[str, int]
    integrity_semantics: str
