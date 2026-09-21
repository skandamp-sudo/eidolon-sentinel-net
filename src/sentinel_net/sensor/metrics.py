from __future__ import annotations
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
    last_error_kind: str = ''
    processing_time_sec: float = 0.0
    capture_queue_depth: int = 0
    detection_queue_depth: int = 0
    start_time: float = 0.0
    stop_time: float = 0.0

    def __post_init__(self):
        self._lock = threading.Lock()
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
