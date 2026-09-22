"""The benchmark report must contain real, self-consistent operational fields."""

import copy

import pytest

from scripts.rw5b_environment import STAGES, validate_benchmark


def valid_report():
    sample = {
        "elapsed_sec_including_drain": 2.0,
        "input_packets": 10,
        "processed_packets": 8,
        "input_bytes": 1000,
        "processed_bytes": 800,
        "completed_flows": 2,
        "events": 2,
        "packets_per_sec": 4,
        "flows_per_sec": 1,
        "processing_mbps": 0.0032,
        "latency_ms": {
            s: {"p50": 1, "p95": 2, "p99": 3, "samples": 2, "total_observations": 2} for s in STAGES
        },
        "rss_bytes": {"initial": 100, "sampled_peak": 200, "final": 150},
        "workload_sha256": "a" * 64,
        "source_sha256": {"pipeline.py": "b" * 64},
        "model_identity": {
            "model_name": "qa",
            "model_version": "1",
            "manifest_sha256": "c" * 64,
            "feature_schema_version": "2.0.0",
        },
        "configuration": {"max_events": 500},
        "windows": [{"elapsed_sec": 1}],
    }
    return {"results": [dict(copy.deepcopy(sample), workload=w) for w in "ABCDEF"]}


def test_complete_benchmark_report():
    validate_benchmark(valid_report())


@pytest.mark.parametrize(
    "defect", ["rate", "latency", "rss", "manifest", "source_change", "duration"]
)
def test_invalid_benchmark_report_rejected(defect):
    report = valid_report()
    row = report["results"][0]
    if defect == "rate":
        row["packets_per_sec"] = 10000
    if defect == "latency":
        row["latency_ms"]["inference"]["p99"] = float("nan")
    if defect == "rss":
        row["rss_bytes"]["sampled_peak"] = 1
    if defect == "manifest":
        row["model_identity"]["manifest_sha256"] = ""
    if defect == "source_change":
        row["source_sha256"]["pipeline.py"] = "d" * 64
    if defect == "duration":
        row["elapsed_sec_including_drain"] = -1
    with pytest.raises(ValueError):
        validate_benchmark(report)
