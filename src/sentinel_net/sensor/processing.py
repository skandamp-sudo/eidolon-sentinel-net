"""Shared downstream computation for live capture and recorded replay.

No source-specific inference, enrichment, scoring, or serialization policy.
"""

import time


def infer_completed(completed, extractor, detection, metrics):
    metrics.increment('flows_completed', len(completed))
    if not completed:
        return []
    vectors = extractor.extract_batch(completed)
    metrics.increment('features_generated', len(vectors))
    evidence_before = getattr(detection, "_runtime_evidence_seconds", None)
    started = time.monotonic()
    events = detection.detect_batch(vectors, completed) if vectors else []
    ended = time.monotonic()
    if evidence_before is not None:
        evidence = detection._runtime_evidence_seconds - evidence_before
        metrics.observe_latency("inference", max(0.0, ended-started-evidence))
    # Whole detect_batch, including evidence (separately measured inside _enrich).
    metrics.observe_latency('inference_including_evidence', ended-started)
    return events
