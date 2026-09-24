"""Analyst projections must never mutate scientific results or infer missing events."""

import copy
import hashlib
import json
from pathlib import Path

import pytest

from sentinel_net.operations.investigation import (
    MAX_EVENTS,
    InvalidInvestigation,
    build_investigation,
    export_bytes,
    project,
)


def event(**changes):
    value = {
        "id": "event-1",
        "flow_id": "flow-1",
        "timestamp": 1000.0,
        "created_at": 2000.0,
        "src_ip": "192.0.2.1",
        "dst_ip": "198.51.100.1",
        "src_port": 20,
        "dst_port": 443,
        "protocol": 6,
        "source_mode": "REPLAY",
        "replay_file_identifier": "recording-1",
        "classification_score": 0.4,
        "anomaly_score": 0.7,
        "severity": "low",
    }
    return {**value, **changes}


def test_positive_exact_flow_sources_and_unchanged_scores():
    a = event()
    original = copy.deepcopy(a)
    result = build_investigation(a, [event(id="event-2", timestamp=1100)])
    assert result["correlation"]["contributing_event_ids"] == ["event-1", "event-2"]
    assert result["correlation"]["source_count"] == 2
    assert result["correlation"]["label"] == "CORRELATED OBSERVATION"
    assert result["events"][0]["classification_score"] == 0.4
    assert result["events"][0]["severity"] == "low" and a == original


@pytest.mark.parametrize(
    "change",
    [
        {"flow_id": "other"},
        {"src_port": 21},
        {"dst_ip": "198.51.100.2"},
        {"protocol": 17},
        {"source_mode": "LIVE"},
        {"replay_file_identifier": "other"},
        {"replay_file_identifier": None},
        {"timestamp": 1300.001},
        {"timestamp": 699.999},
    ],
)
def test_negative_shared_ip_is_insufficient_and_horizon_expires(change):
    r = build_investigation(event(), [event(id="event-2", **change)])
    assert r["correlation"]["contributing_event_ids"] == ["event-1"]


def test_live_requires_interface_and_does_not_join_replay():
    a = event(source_mode="LIVE", capture_interface="en0")
    r = build_investigation(a, [event(id="event-2", source_mode="LIVE", capture_interface="en1")])
    assert len(r["events"]) == 1 and r["timeline"][0]["source"] == "LIVE"


def test_bounds_and_no_persistent_graph():
    with pytest.raises(InvalidInvestigation):
        build_investigation(event(), [event(id=f"e-{i}") for i in range(MAX_EVENTS + 1)])
    assert len(build_investigation(event(), [])["events"]) == 1
    many = [{"signal_type": "context"}] * 128
    with pytest.raises(InvalidInvestigation):
        build_investigation(event(behavioral_evidence=many, dns_evidence=many), [])


def test_timeline_order_missingness_and_clock_labels():
    e = event(created_at=None, dns_observation={"timestamp": 900})
    r = build_investigation(e, [])
    assert [i["timestamp"] for i in r["timeline"]] == [900, 1000]
    assert [i["clock"] for i in r["timeline"]] == [
        "capture_event_time",
        "event_timestamp_unspecified",
    ]
    assert all(i["source"] == "REPLAY" for i in r["timeline"])
    assert not any(i["signal_type"] == "record_created" for i in r["timeline"])


def test_determinism_mutation_and_no_secrets():
    e = event(
        metadata={"api_key": "SECRET", "registry_path": "/private/registry"},
        raw_tls_payload="SECRET",
        tls_observation={"visibility": "BOTH", "raw_payload": "SECRET"},
    )
    a = build_investigation(e, [])
    data, digest = export_bytes(a)
    assert hashlib.sha256(data).hexdigest() == digest
    assert b"SECRET" not in data and b"/private" not in data
    assert export_bytes(build_investigation(dict(reversed(list(e.items()))), [])) == (data, digest)
    assert export_bytes(build_investigation(event(severity="high"), []))[1] != digest


@pytest.mark.parametrize(
    "value",
    [
        float("nan"),
        {"dns_observation": []},
        {"behavioral_evidence": [1]},
        {"metadata": []},
        {"timestamp": "yesterday"},
    ],
)
def test_malformed_metadata(value):
    with pytest.raises(InvalidInvestigation):
        if isinstance(value, dict):
            build_investigation(event(**value), [])
        else:
            project(value)


def test_nested_oversized_metadata():
    x = {}
    root = x
    for _ in range(12):
        x["hello"] = {}
        x = x["hello"]
    with pytest.raises(InvalidInvestigation):
        project(root)
    with pytest.raises(InvalidInvestigation):
        project({"sni": "x" * 4097})


@pytest.mark.parametrize("name", ["f3-event", "f4-event", "f5-tls-event", "f5-quic-event"])
def test_existing_persisted_fixtures(name):
    original = json.loads(Path(f"frontend/src/__tests__/fixtures/{name}.json").read_text())
    result = build_investigation(original, [])
    assert result["events"][0]["classification_score"] == original["classification_score"]
    assert result["events"][0]["anomaly_score"] == original["anomaly_score"]
    assert result["evidence_references"] and result["timeline"]
    assert len(export_bytes(result)[0]) < 1048576


def test_scientific_summary_matches_completed_evaluation():
    summary = json.loads(Path("src/sentinel_net/operations/science.json").read_text())
    path = Path("docs/final-science-metrics.json")
    metrics = json.loads(path.read_text())
    x = metrics["supervised"]["XGBoost"]
    assert summary["report_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert summary["accuracy"] == x["accuracy"] and summary["macro_f1"] == x["f1_macro"]
    assert summary["c2_recall"] == 0 and summary["ddos_recall"] == x["per_class"]["ddos"]["recall"]
    assert summary["benign_to_malicious_fpr"] == 276 / 267851


def test_export_schema_rejects_unrecognized_top_level_and_timeline_overflow():
    from sentinel_net.operations.schema import InvestigationExport

    r = build_investigation(event(), [])
    assert InvestigationExport.model_validate(r).export_schema_version == "1.0.0"
    r["secret"] = "must not be exported"
    with pytest.raises(InvalidInvestigation):
        export_bytes(r)
    r.pop("secret")
    r["timeline"] = [r["timeline"][0]] * 513
    with pytest.raises(InvalidInvestigation):
        export_bytes(r)


def test_compliance_matrix_covers_required_inventory():
    data = json.loads(Path("docs/sih26145-compliance-matrix.json").read_text())
    ids = {r["id"] for r in data["requirements"]}
    assert len(ids) == len(data["requirements"]) == 39
    assert {
        "D1",
        "D2",
        "D3",
        "D4",
        "D5",
        "C1",
        "C2",
        "C3",
        "N1",
        "N2",
        "N3",
        "N4",
        "N5",
        "T1",
        "T2",
        "T3",
        "T4",
        "R1",
        "R2",
        "R3",
        "E1",
        "E2",
        "E3",
        "A1",
        "A2",
        "A3",
        "A4",
        "A5",
        "A6",
        "A7",
        "A8",
        "A9",
        "A10",
        "M1",
        "M2",
        "M3",
        "M4",
        "O1",
        "O2",
    } == ids
    for row in data["requirements"]:
        assert all(
            row.get(k)
            for k in (
                "requirement",
                "implementation",
                "component",
                "verification",
                "demo_path",
                "status",
                "limitation",
            )
        )
    assert next(r for r in data["requirements"] if r["id"] == "A2")["status"] != "COMPLETE"
    assert next(r for r in data["requirements"] if r["id"] == "T3")["status"] == "NOT VERIFIED"


@pytest.mark.parametrize(
    "change",
    [
        {"event_id": "conflict"},
        {"src_port": True},
        {"protocol": 999},
        {"classification_score": "bad"},
    ],
)
def test_rejects_conflicting_or_malformed_identity(change):
    with pytest.raises(InvalidInvestigation):
        build_investigation(event(**change), [])
