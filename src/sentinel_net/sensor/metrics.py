from __future__ import annotations
from collections import deque
import threading
import time
from dataclasses import dataclass, field

@dataclass
class SensorMetrics:
    """Thread-safe operational counters."""
    packets_observed: int = 0
    packets_parsed: int = 0
    packets_malformed: int = 0
    packets_dropped: int = 0
    packets_processed: int = 0
    bytes_processed: int = 0
    packet_processing_errors: int = 0
    flows_created: int = 0
    flows_active: int = 0
    flows_completed: int = 0
    flows_evicted: int = 0
    features_generated: int = 0
    detections_generated: int = 0
    events_persisted: int = 0
    events_enqueued: int = 0
    events_delivered: int = 0
    events_dropped: int = 0
    persistence_errors: int = 0
    processing_errors: int = 0
    capture_errors: int = 0
    source_errors: int = 0
    output_errors: int = 0
    intelligence_keys: int = 0
    intelligence_buckets_per_key_peak: int = 0
    intelligence_members_per_dimension_peak: int = 0
    intelligence_keys_peak: int = 0
    intelligence_evictions: int = 0
    intelligence_expirations: int = 0
    intelligence_member_overflows: int = 0
    intelligence_session_truncations: int = 0
    intelligence_session_samples_peak: int = 0
    intelligence_late_observations: int = 0
    intelligence_evidence_generated: int = 0
    intelligence_processing_errors: int = 0
    dns_messages_observed: int = 0
    dns_messages_parsed: int = 0
    dns_malformed: int = 0
    dns_truncated: int = 0
    dns_unavailable: int = 0
    dns_state_keys: int = 0
    dns_keys_peak: int = 0
    dns_buckets_per_key_peak: int = 0
    dns_members_per_dimension_peak: int = 0
    dns_member_overflows: int = 0
    dns_late_observations: int = 0
    dns_evictions: int = 0
    dns_expirations: int = 0
    dns_transactions: int = 0
    dns_transactions_peak: int = 0
    dns_observations: int = 0
    dns_observations_peak: int = 0
    dns_evidence_generated: int = 0
    dns_processing_errors: int = 0
    tls_records_observed: int = 0
    tls_client_hello: int = 0
    tls_server_hello: int = 0
    tls_malformed: int = 0
    tls_truncated: int = 0
    tls_unavailable: int = 0
    tls_reassembly_evictions: int = 0
    tls_reassembly_bytes: int = 0
    tls_reassembly_bytes_peak: int = 0
    tls_evidence_generated: int = 0
    quic_packets_observed: int = 0
    quic_long_headers: int = 0
    quic_unknown_versions: int = 0
    quic_malformed: int = 0
    quic_truncated: int = 0
    quic_unavailable: int = 0
    quic_evidence_generated: int = 0
    encrypted_metadata_state: int = 0
    encrypted_metadata_state_peak: int = 0
    encrypted_metadata_samples_per_connection_peak: int = 0
    encrypted_metadata_evictions: int = 0
    encrypted_metadata_expirations: int = 0
    encrypted_metadata_late_observations: int = 0
    encrypted_metadata_processing_errors: int = 0
    kernel_capture_drops: int | None = None
    retention_failures: int = 0
    retention_cycles: int = 0
    retention_events_removed: int = 0
    retention_flows_removed: int = 0
    retention_last_success: float | None = None
    retention_duration_sec: float = 0.0
    database_bytes: int | None = None
    wal_bytes: int | None = None
    flows_active_peak: int = 0
    capture_queue_peak: int = 0
    exact_history_samples_peak: int = 0
    last_error_kind: str = ''
    processing_time_sec: float = 0.0
    capture_queue_depth: int = 0
    detection_queue_depth: int = 0
    start_time: float = 0.0
    stop_time: float = 0.0

    def __post_init__(self):
        self._lock = threading.Lock()
        self._latencies = {}
        self._latency_counts = {}
        if self.start_time == 0.0:
            self.start_time = time.time()

    def increment(self, field: str, amount: int = 1) -> None:
        """Increment a metric by a specific amount."""
        with self._lock:
            if not hasattr(self, field) or field.startswith("_"):
                raise ValueError(f"Unknown metric field: {field}")
            val = getattr(self, field)
            setattr(self, field, val + amount)

    def set_gauge(self, field: str, value: int) -> None:
        """Set a metric to a specific value."""
        with self._lock:
            if hasattr(self, field):
                setattr(self, field, value)

    def observe_latency(self, name: str, seconds: float) -> None:
        with self._lock:
            self._latencies.setdefault(name, deque(maxlen=4096)).append(seconds * 1000)
            self._latency_counts[name] = self._latency_counts.get(name, 0) + 1

    def observe_peak(self, name: str, value: int) -> None:
        with self._lock:
            setattr(self, name, max(getattr(self, name), value))

    def latency_snapshot(self) -> dict:
        with self._lock:
            result = {}
            for name, samples in self._latencies.items():
                ordered = sorted(samples)
                def percentile(q):
                    pos = (len(ordered)-1) * q
                    lo = int(pos)
                    hi = min(lo+1, len(ordered)-1)
                    return ordered[lo] + (ordered[hi]-ordered[lo])*(pos-lo)
                result[name] = dict(p50=percentile(.5), p95=percentile(.95), p99=percentile(.99),
                                    samples=len(ordered), total_observations=self._latency_counts[name],
                                    unit='ms', scope='last_4096_observations')
            return result

    def snapshot(self) -> dict:
        """Return a snapshot of all metrics."""
        with self._lock:
            result = {k: v for k, v in self.__dict__.items() if not k.startswith('_')}
            result['packets_received'] = self.packets_observed
            result['packet_errors'] = self.packets_malformed + self.packet_processing_errors
            result['sensor_uptime'] = self.uptime_sec
            return result

    @property
    def uptime_sec(self) -> float:
        """Calculate the uptime in seconds."""
        return max(0.0, (self.stop_time or time.time()) - self.start_time)
