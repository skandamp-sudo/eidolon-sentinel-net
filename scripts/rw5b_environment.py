"""Validate measured benchmark output and bind it to this host's environment.

PYTHONPATH=src .venv/bin/python scripts/rw5b_environment.py \
  --benchmark /tmp/rw5b-final/benchmark.json --output docs/rw5b-environment-manifest.json
"""

import argparse
import hashlib
import importlib.metadata
import json
import math
import os
import platform
import subprocess
from datetime import UTC, datetime
from pathlib import Path

STAGES = (
    "packet_processing",
    "flow_finalization_to_event",
    "inference",
    "evidence_enrichment",
    "persistence",
    "publication",
)


def validate_benchmark(report):
    """Reject incomplete/nonfinite or arithmetically inconsistent measurements."""
    results = report["results"]
    if len(results) != 6 or len({r["workload"] for r in results}) != 6:
        raise ValueError("Six distinct workloads required")
    for r in results:
        duration = r["elapsed_sec_including_drain"]
        if not math.isfinite(duration) or duration <= 0:
            raise ValueError("Invalid monotonic duration")
        for count in (
            "input_packets",
            "processed_packets",
            "input_bytes",
            "processed_bytes",
            "completed_flows",
            "events",
        ):
            if not isinstance(r[count], int) or r[count] < 0:
                raise ValueError("Invalid count")
        if r["processed_packets"] > r["input_packets"] or r["processed_bytes"] > r["input_bytes"]:
            raise ValueError("Processed counts exceed input")
        for rate, count, scale in [
            ("packets_per_sec", "processed_packets", 1),
            ("flows_per_sec", "completed_flows", 1),
            ("processing_mbps", "processed_bytes", 8 / 1e6),
        ]:
            if not math.isclose(r[rate], r[count] * scale / duration, rel_tol=1e-9):
                raise ValueError("Inconsistent throughput")
        for stage in STAGES:
            latency = r["latency_ms"][stage]
            values = [latency[p] for p in ("p50", "p95", "p99")]
            if not all(math.isfinite(v) and v >= 0 for v in values) or values != sorted(values):
                raise ValueError("Invalid latency percentiles")
            if not 1 <= latency["samples"] <= min(4096, latency["total_observations"]):
                raise ValueError("Invalid bounded sample counts")
        mem = r["rss_bytes"]
        if (
            not 0 < mem["initial"] <= mem["sampled_peak"]
            or not 0 < mem["final"] <= mem["sampled_peak"]
        ):
            raise ValueError("Invalid RSS values")
        if len(r["workload_sha256"]) != 64 or not r["source_sha256"]:
            raise ValueError("Missing reproducibility hashes")
        identity = r["model_identity"]
        if (
            not identity["model_name"]
            or not identity["model_version"]
            or len(identity["manifest_sha256"]) != 64
        ):
            raise ValueError("Incomplete model identity")
        if identity["feature_schema_version"] != "2.0.0":
            raise ValueError("Unexpected scientific schema")
        if not r["configuration"] or not r["windows"]:
            raise ValueError("Missing configuration or sustained windows")
    if any(r["source_sha256"] != results[0]["source_sha256"] for r in results[1:]):
        raise ValueError("Measurement source changed between workloads")


def collect_environment(report, benchmark_bytes):
    validate_benchmark(report)
    data = {
        "phase": report.get("phase", "RW-5B"),
        "checked_at": datetime.now(UTC).isoformat(),
        "os": platform.platform(),
        "architecture": platform.machine(),
        "python": platform.python_version(),
        "uid": os.geteuid(),
        "logical_cpus": os.cpu_count(),
        "feature_count": 52,
        "feature_schema_version": "2.0.0",
        "dependencies": {
            p: importlib.metadata.version(p)
            for p in (
                "numpy",
                "scipy",
                "scikit-learn",
                "xgboost",
                "joblib",
                "scapy",
                "aiosqlite",
                "fastapi",
                "uvicorn",
                "websockets",
            )
        },
        "benchmark_sha256": hashlib.sha256(benchmark_bytes).hexdigest(),
        "model_identity": report["results"][0]["model_identity"],
        "workloads": [
            {
                k: r[k]
                for k in (
                    "workload",
                    "workload_sha256",
                    "target_duration_sec",
                    "elapsed_sec_including_drain",
                    "configuration",
                )
            }
            for r in report["results"]
        ],
    }
    data["hardware_read_errors"] = {}
    for key, sysctl in [
        ("cpu", "machdep.cpu.brand_string"),
        ("physical_cores", "hw.physicalcpu"),
        ("ram_bytes", "hw.memsize"),
    ]:
        try:
            value = subprocess.check_output(
                ["/usr/sbin/sysctl", "-n", sysctl], text=True, stderr=subprocess.PIPE
            ).strip()
            data[key] = value if key == "cpu" else int(value)
        except (OSError, ValueError, subprocess.CalledProcessError) as exc:
            data[key] = None
            data["hardware_read_errors"][key] = type(exc).__name__
    return data


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--benchmark", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    raw = args.benchmark.read_bytes()
    result = collect_environment(json.loads(raw), raw)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print("PASS: six complete workloads; environment manifest written")


if __name__ == "__main__":
    main()
