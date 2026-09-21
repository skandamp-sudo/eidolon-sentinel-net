"""Shared downstream computation for live capture and recorded replay.

No source-specific inference, enrichment, scoring, or serialization policy.
"""


def infer_completed(completed, extractor, detection, metrics):
    metrics.increment('flows_completed', len(completed))
    if not completed:
        return []
    vectors = extractor.extract_batch(completed)
    metrics.increment('features_generated', len(vectors))
    return detection.detect_batch(vectors, completed) if vectors else []
