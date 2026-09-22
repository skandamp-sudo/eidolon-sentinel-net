"""One capped LRU owner; quantized event-time windows with bounded membership."""

import math
from collections import Counter, OrderedDict
from dataclasses import dataclass, field


@dataclass
class Bucket:
    counts: Counter = field(default_factory=Counter)
    sources: Counter = field(default_factory=Counter)
    destinations: Counter = field(default_factory=Counter)
    ports: Counter = field(default_factory=Counter)
    overflow: int = 0


@dataclass
class KeyState:
    buckets: dict = field(default_factory=dict)
    members: dict = field(
        default_factory=lambda: {n: set() for n in ("sources", "destinations", "ports")}
    )
    sessions: list = field(default_factory=list)
    session_truncated: bool = False

    def expire(self, cutoff, start):
        expired = [b for b in self.buckets if b < cutoff]
        for b in expired:
            del self.buckets[b]
        if expired:
            for name in self.members:
                self.members[name] = set().union(*(getattr(b, name) for b in self.buckets.values()))
        self.sessions[:] = [t for t in self.sessions if t >= start]

    def totals(self):
        result = Bucket()
        for bucket in self.buckets.values():
            result.counts.update(bucket.counts)
            for name in self.members:
                getattr(result, name).update(getattr(bucket, name))
            result.overflow += bucket.overflow
        return result


class BoundedWindow:
    def __init__(self, config, metrics):
        self.config, self.metrics = config, metrics
        self.keys = OrderedDict()
        self.watermark = None
        self.tick = None

    @property
    def cutoff(self):
        return self.tick - self.config.window_sec // self.config.bucket_sec + 1

    @property
    def interval(self):
        return {
            "start": self.cutoff * self.config.bucket_sec,
            "end": (self.tick + 1) * self.config.bucket_sec,
            "duration_sec": self.config.window_sec,
            "clock": "capture_event_time",
            "alignment": "fixed buckets; latest bucket may be partial",
        }

    def advance(self, timestamp):
        if not math.isfinite(timestamp):
            raise ValueError("Nonfinite intelligence event time")
        tick = math.floor(timestamp / self.config.bucket_sec)
        if self.tick is None or tick > self.tick:
            self.tick = tick
            self.watermark = timestamp
            for key, state in list(self.keys.items()):
                state.expire(self.cutoff, self.interval["start"])
                if not state.buckets and not state.sessions:
                    del self.keys[key]
                    self.metrics.increment("intelligence_expirations")
            self.metrics.set_gauge("intelligence_keys", len(self.keys))
        else:
            self.watermark = max(self.watermark, timestamp)
        if tick < self.cutoff:
            self.metrics.increment("intelligence_late_observations")
            return None
        return tick

    def get(self, key, tick):
        if key not in self.keys:
            if len(self.keys) >= self.config.max_keys:
                self.keys.popitem(last=False)
                self.metrics.increment("intelligence_evictions")
            self.keys[key] = KeyState()
        self.keys.move_to_end(key)
        state = self.keys[key]
        bucket = state.buckets.setdefault(tick, Bucket())
        self.metrics.observe_peak("intelligence_buckets_per_key_peak", len(state.buckets))
        self.metrics.set_gauge("intelligence_keys", len(self.keys))
        self.metrics.observe_peak("intelligence_keys_peak", len(self.keys))
        return state, bucket

    def member(self, state, bucket, name, value):
        known = state.members[name]
        if value in known or len(known) < self.config.max_members:
            known.add(value)
            self.metrics.observe_peak("intelligence_members_per_dimension_peak", len(known))
            getattr(bucket, name)[value] += 1
        else:
            bucket.overflow += 1
            self.metrics.increment("intelligence_member_overflows")

    def close(self):
        self.keys.clear()
        self.metrics.set_gauge("intelligence_keys", 0)
