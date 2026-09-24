"""Bounded, deterministic projections of already persisted observations.

No cached graph, scoring, inference, attribution or external lookup. Export is
an allowlisted projection, not an archive of arbitrary stored metadata.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from typing import Any

MAX_EVENTS = 32
MAX_RECORD_BYTES = 131072
MAX_EXPORT_BYTES = 1048576
HORIZON_SEC = 300
MAX_REFERENCES = 256
ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}\Z")

# Field names, rather than a blacklist: metadata and raw payloads never pass.
FIELDS = {
    "alignment",
    "alphabetic_ratio",
    "alpn",
    "anomaly_model_version",
    "anomaly_score",
    "anomaly_score_type",
    "answer_count",
    "application_payload",
    "attack_context",
    "behavioral_attack_context",
    "behavioral_evidence",
    "behavioral_evidence_status",
    "canonical",
    "capture_interface",
    "character_entropy",
    "cipher_suites",
    "classification_score",
    "classification_score_class",
    "classification_score_type",
    "client",
    "clock",
    "comparison",
    "compression_methods",
    "confidence_semantics",
    "contribution",
    "created_at",
    "declared_packet_length",
    "deployment_model_version",
    "destination_cid_length",
    "destination_cid_sha256",
    "detector",
    "detector_version",
    "digest",
    "digit_ratio",
    "direction",
    "direction_count",
    "directions",
    "disposition",
    "dns_attack_context",
    "dns_evidence",
    "dns_observation",
    "dns_status",
    "dst_ip",
    "dst_port",
    "duration_sec",
    "ec_point_formats",
    "encoding",
    "encrypted_payload",
    "end",
    "entropy",
    "entropy_scope",
    "event_id",
    "event_schema_version",
    "evidence",
    "evidence_type",
    "explanation_available",
    "explanation_version",
    "extension_ids",
    "family",
    "feature_name",
    "feature_schema_version",
    "fingerprint",
    "flow_id",
    "handshake_type",
    "hello",
    "hello_retry_request",
    "hexadecimal_ratio",
    "id",
    "inter_packet_max_sec",
    "inter_packet_mean_sec",
    "inter_packet_min_sec",
    "interpretation",
    "items",
    "ja4_status",
    "label_count",
    "label_statistics",
    "legacy_version",
    "length",
    "lexical",
    "limits",
    "long_header",
    "longest_label",
    "max_label_entropy",
    "message",
    "message_length",
    "model_manifest_sha256",
    "model_name",
    "model_version",
    "name",
    "observation_window",
    "observed_value",
    "opcode",
    "packet_number",
    "packet_size",
    "packet_size_max",
    "packet_size_mean",
    "packet_size_min",
    "packet_type",
    "parent",
    "parent_semantics",
    "payload_inspected",
    "protocol",
    "qclass",
    "qname_length",
    "qr",
    "qtype",
    "qtype_name",
    "qualification",
    "question_count",
    "questions",
    "quic_evidence",
    "quic_observation",
    "quic_status",
    "rationale",
    "rcode",
    "reason",
    "record_count",
    "reference_threshold",
    "reference_value",
    "repeated_labels",
    "replay_file_identifier",
    "response_record_types",
    "retention",
    "risk",
    "sample_characters",
    "sample_count",
    "samples_capped",
    "scope",
    "selected_cipher_suite",
    "selected_version",
    "semantics",
    "server",
    "severity",
    "signal_type",
    "signature_algorithms",
    "sni",
    "sni_status",
    "source",
    "source_cid_length",
    "source_cid_sha256",
    "source_ip",
    "source_mode",
    "source_port",
    "src_ip",
    "src_port",
    "start",
    "started_at",
    "status",
    "subdomain_depth_proxy",
    "supported_groups",
    "supported_versions",
    "tactic",
    "technique_id",
    "technique_name",
    "threat_class",
    "threat_type",
    "threshold_semantics",
    "timestamp",
    "timing",
    "tls_evidence",
    "tls_observation",
    "tls_status",
    "token_length",
    "total_observed_packets",
    "transaction_id",
    "truncated",
    "unavailable_reason",
    "unique_characters",
    "unit",
    "value",
    "version",
    "version_hex",
    "visibility",
}


class InvalidInvestigation(ValueError):
    """Stored data is malformed or exceeds the documented analyst bounds."""


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def project(value: Any, depth: int = 0) -> Any:
    """Fail closed on excessive structures; strip fields outside export schema."""
    if depth > 10:
        raise InvalidInvestigation("Metadata nesting exceeds bound")
    if isinstance(value, dict):
        if len(value) > 256:
            raise InvalidInvestigation("Metadata fields exceed bound")
        return {k: project(v, depth + 1) for k, v in value.items() if k in FIELDS}
    if isinstance(value, list):
        if len(value) > 128:
            raise InvalidInvestigation("Metadata collection exceeds bound")
        return [project(v, depth + 1) for v in value]
    if isinstance(value, str):
        if len(value) > 4096:
            raise InvalidInvestigation("Metadata string exceeds bound")
        return value
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int) and value.bit_length() <= 64:
        return value
    if isinstance(value, float) and math.isfinite(value):
        return value
    raise InvalidInvestigation("Invalid metadata value")


def number(value: Any) -> bool:
    try:
        return type(value) in (int, float) and math.isfinite(value)
    except OverflowError:
        return False


def validate_event(raw: dict) -> dict:
    if (
        not isinstance(raw, dict)
        or not isinstance(raw.get("id"), str)
        or not ID_PATTERN.fullmatch(raw["id"])
    ):
        raise InvalidInvestigation("Invalid persisted identity")
    if not number(raw.get("timestamp")):
        raise InvalidInvestigation("Missing recorded event time")
    event = project(raw)
    if event.get("source_mode") not in (None, "LIVE", "REPLAY"):
        raise InvalidInvestigation("Invalid traffic source")
    for key in ("evidence", "dns_observation", "tls_observation", "quic_observation"):
        if not isinstance(event.get(key, {}), dict):
            raise InvalidInvestigation("Malformed observation")
    for key in ("behavioral_evidence", "dns_evidence", "tls_evidence", "quic_evidence"):
        if not isinstance(event.get(key, []), list) or any(
            not isinstance(s, dict) for s in event.get(key, [])
        ):
            raise InvalidInvestigation("Malformed evidence")
    for key in ("classification_score", "anomaly_score", "created_at"):
        if event.get(key) is not None and not number(event[key]):
            raise InvalidInvestigation("Malformed numeric result")
    for key in ("flow_id", "src_ip", "dst_ip", "capture_interface", "replay_file_identifier"):
        if event.get(key) is not None and not isinstance(event[key], str):
            raise InvalidInvestigation("Malformed identity")
    if not isinstance(event.get("evidence", {}).get("items", []), list):
        raise InvalidInvestigation("Malformed model evidence")
    if "directions" in event.get("dns_observation", {}):
        raise InvalidInvestigation("Unexpected DNS direction metadata")
    for family in ("tls", "quic"):
        directions = event.get(family + "_observation", {}).get("directions", [])
        if not isinstance(directions, list) or len(directions) > 2:
            raise InvalidInvestigation("Malformed directional metadata")
    if event.get("event_id", event["id"]) != event["id"]:
        raise InvalidInvestigation("Conflicting event identity")
    if (
        "threat_type" in event
        and "threat_class" in event
        and event["threat_type"] != event["threat_class"]
    ):
        raise InvalidInvestigation("Conflicting recorded classification")
    for key, maximum in (("src_port", 65535), ("dst_port", 65535), ("protocol", 255)):
        value = event.get(key)
        if value is not None and (type(value) is not int or not 0 <= value <= maximum):
            raise InvalidInvestigation("Malformed endpoint")
    # Only qualified mappings from known explanation locations; never metadata itself.
    meta = raw.get("metadata", {})
    if not isinstance(meta, dict):
        raise InvalidInvestigation("Malformed metadata")
    explanation = meta.get("explanation", meta)
    if not isinstance(explanation, dict):
        raise InvalidInvestigation("Malformed explanation")
    mappings = explanation.get("attack_mappings", [])
    if not isinstance(mappings, list):
        raise InvalidInvestigation("Malformed ATT&CK context")
    event["attack_context"] = project(mappings)
    return event


def relationship(anchor: dict, other: dict) -> bool:
    keys = ("flow_id", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "source_mode")
    if any(anchor.get(k) is None or other.get(k) != anchor[k] for k in keys):
        return False
    source_key = (
        "replay_file_identifier" if anchor["source_mode"] == "REPLAY" else "capture_interface"
    )
    return (
        bool(anchor.get(source_key))
        and other.get(source_key) == anchor[source_key]
        and number(other.get("timestamp"))
        and abs(other["timestamp"] - anchor["timestamp"]) <= HORIZON_SEC
    )


def build_investigation(anchor: dict, candidates: list[dict], *, truncated: bool = False) -> dict:
    if len(candidates) > MAX_EVENTS:
        raise InvalidInvestigation("Investigation event bound exceeded")
    anchor = validate_event(anchor)
    selected = {anchor["id"]: anchor}
    for raw in candidates:
        event = validate_event(raw)
        if event["id"] != anchor["id"] and relationship(anchor, event):
            selected[event["id"]] = event
    events = sorted(selected.values(), key=lambda e: (e["timestamp"], e["id"]))
    if len(events) > MAX_EVENTS:
        raise InvalidInvestigation("Investigation event bound exceeded")
    refs, timeline, sources = [], [], set()

    def add_ref(event, kind, path):
        if len(refs) >= MAX_REFERENCES:
            raise InvalidInvestigation("Evidence reference bound exceeded")
        refs.append({"event_id": event["id"], "signal_type": kind, "reference": path})
        sources.add(kind)

    def item(event, timestamp, kind, description, clock, reference):
        if number(timestamp):
            timeline.append(
                {
                    "timestamp": timestamp,
                    "clock": clock,
                    "signal_type": kind,
                    "description": description,
                    "source": event.get("source_mode"),
                    "event_id": event["id"],
                    "reference": reference,
                }
            )

    for e in events:
        item(
            e,
            e["timestamp"],
            "recorded_event",
            "Recorded detection event timestamp",
            "event_timestamp_unspecified",
            "timestamp",
        )
        item(
            e,
            e.get("created_at"),
            "record_created",
            "Detection record creation timestamp; not a commit timestamp",
            "processing_time",
            "created_at",
        )
        for key, kind in [
            ("classification_score", "ML classification"),
            ("anomaly_score", "Anomaly score"),
        ]:
            if number(e.get(key)):
                add_ref(e, kind, key)
        if e.get("evidence", {}).get("items"):
            add_ref(e, "Model explanation", "evidence")
        for family in ("behavioral", "dns", "tls", "quic"):
            for i, signal in enumerate(e.get(family + "_evidence", [])):
                path = f"{family}_evidence/{i}"
                add_ref(e, family.upper() + " evidence", path)
                window = signal.get("observation_window", {})
                if not isinstance(window, dict):
                    raise InvalidInvestigation("Malformed observation window")
                if window.get("clock") == "capture_event_time":
                    item(
                        e,
                        window.get("end"),
                        family,
                        f"Recorded {signal.get('signal_type', 'evidence')} window end (not signal generation time)",
                        "capture_event_time",
                        path + "/observation_window/end",
                    )
        for family in ("dns", "tls", "quic"):
            observation = e.get(family + "_observation", {})
            if observation:
                add_ref(e, family.upper() + " metadata", family + "_observation")
            if family == "dns":
                item(
                    e,
                    observation.get("timestamp"),
                    "dns",
                    "Retained DNS observation",
                    "capture_event_time",
                    "dns_observation/timestamp",
                )
            if family == "dns":
                continue
            for i, d in enumerate(observation.get("directions", [])):
                if not isinstance(d, dict):
                    raise InvalidInvestigation("Malformed direction")
                key = "started_at" if family == "tls" else "timestamp"
                item(
                    e,
                    d.get(key),
                    family,
                    "Retained " + family.upper() + " direction observation",
                    "capture_event_time",
                    f"{family}_observation/directions/{i}/{key}",
                )
    timeline.sort(key=lambda t: (t["timestamp"], t["clock"], t["event_id"], t["reference"]))
    limitations = [
        "Multiple evidence sources do not establish statistical independence, attribution or an attack.",
        "Scores, severity and risk are unchanged. No combined attack probability is calculated.",
        "Only exact recorded flow/endpoints/protocol/source identity within ±300 event-timestamp seconds is linked.",
        "Event.timestamp clock is not established for historical rows; capture and processing clocks remain labelled separately.",
        "Missing observations are not synthesized. Window end is not evidence generation time.",
        "This is an allowlisted evidence projection; arbitrary metadata and unselected supporting context are omitted.",
        "Retention can remove authoritative records. This snapshot is not a complete traffic history.",
    ]
    if truncated:
        limitations.append(
            "Candidate query reached its 32-event limit; related evidence may be omitted."
        )
    identifier = hashlib.sha256(
        canonical_bytes(
            {"anchor": anchor["id"], "events": [e["id"] for e in events], "rules": "1.0.0"}
        )
    ).hexdigest()
    return {
        "export_schema_version": "1.0.0",
        "investigation_id": identifier,
        "anchor_event_id": anchor["id"],
        "correlation": {
            "correlation_id": identifier,
            "label": "CORRELATED OBSERVATION" if len(sources) > 1 else "RECORDED OBSERVATION",
            "contributing_event_ids": [e["id"] for e in events],
            "contributing_signal_types": sorted(sources),
            "source_count": len(sources),
            "evidence_count": len(refs),
            "first_seen": events[0]["timestamp"],
            "last_seen": events[-1]["timestamp"],
            "time_basis": "recorded event.timestamp",
            "summary": "Multiple evidence sources are associated with this observation; analyst interpretation is required."
            if len(sources) > 1
            else "Only the recorded evidence shown here is available.",
        },
        "events": events,
        "evidence_references": refs,
        "timeline": timeline,
        "limitations": limitations,
        "bounds": {
            "max_events": MAX_EVENTS,
            "max_references": MAX_REFERENCES,
            "horizon_sec": HORIZON_SEC,
            "max_record_bytes": MAX_RECORD_BYTES,
            "max_export_bytes": MAX_EXPORT_BYTES,
            "max_timeline_items": 512,
        },
        "integrity_semantics": "SHA-256 checks these exact canonical JSON bytes. It is not a digital signature, proof of authorship, external timestamp or legal chain of custody.",
    }


def export_bytes(investigation: dict) -> tuple[bytes, str]:
    from pydantic import ValidationError

    from sentinel_net.operations.schema import InvestigationExport

    try:
        InvestigationExport.model_validate(investigation)
    except ValidationError as exc:
        raise InvalidInvestigation("Invalid export schema") from exc
    content = canonical_bytes(investigation)
    if len(content) > MAX_EXPORT_BYTES:
        raise InvalidInvestigation("Export byte bound exceeded")
    return content, hashlib.sha256(content).hexdigest()
