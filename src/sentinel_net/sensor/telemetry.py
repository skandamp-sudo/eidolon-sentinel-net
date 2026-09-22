"""Bounded operational timing around the unchanged scientific implementations."""

import time

from sentinel_net.flow.aggregator import FlowAggregator
from sentinel_net.models.types import FlowKey


class TimedFlowAggregator(FlowAggregator):
    def __init__(self, config, metrics):
        super().__init__(config)
        self.metrics = metrics

    def ingest(self, packet):
        super().ingest(packet)
        key = FlowKey(
            packet.src_ip, packet.dst_ip, packet.src_port, packet.dst_port, packet.protocol
        )
        active = self._active.get(key.direction_key)
        if active:
            self.metrics.observe_peak("exact_history_samples_peak", len(active.packet_sizes))

    def _finalize(self, active):
        # Entry into actual canonical finalization, not subsequent queue draining.
        started = time.monotonic()
        self.metrics.observe_peak("exact_history_samples_peak", len(active.packet_sizes))
        flow = super()._finalize(active)
        flow._runtime_finalization_started = started
        return flow


class TimedDetector:
    """Single processing-owner adapter; delegate even replaced detect methods.

    The temporary enrichment hook is local to the runtime detector instance,
    restored on success/failure. Frozen model and scientific code are untouched.
    A detector instance must not be shared across concurrent processing owners.
    """

    def __init__(self, detector, metrics):
        self.detector, self.metrics = detector, metrics
        self._runtime_evidence_seconds = 0.0

    def __getattr__(self, name):
        return getattr(self.detector, name)

    def detect_batch(self, *args, **kwargs):
        original = self.detector._enrich
        had_instance_hook = "_enrich" in vars(self.detector)

        def enrich(event, transformed):
            started = time.monotonic()
            try:
                return original(event, transformed)
            finally:
                elapsed = time.monotonic() - started
                self._runtime_evidence_seconds += elapsed
                self.metrics.observe_latency("evidence_enrichment", elapsed)

        self.detector._enrich = enrich
        try:
            return self.detector.detect_batch(*args, **kwargs)
        finally:
            if had_instance_hook:
                self.detector._enrich = original
            else:
                del self.detector._enrich


def timed_detector(detector, metrics):
    return (
        TimedDetector(detector, metrics)
        if detector is not None and hasattr(detector, "_enrich")
        else detector
    )
