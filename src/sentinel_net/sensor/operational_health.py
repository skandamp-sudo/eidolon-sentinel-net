"""Operational failures are separate from model anomaly/threat classifications."""

ERROR_COUNTERS = (
    "persistence_errors",
    "capture_errors",
    "processing_errors",
    "packets_malformed",
    "packets_dropped",
    "events_dropped",
    "source_errors",
    "output_errors",
    "retention_failures",
    "intelligence_processing_errors",
    "dns_processing_errors",
)


def resource_reasons(metrics, event_bus=None):
    snapshot = metrics.snapshot() if metrics else {}
    reasons = [name for name in ERROR_COUNTERS if snapshot.get(name, 0)]
    if event_bus and event_bus.rejected_subscribers:
        reasons.append("subscriber_capacity")
    return reasons
