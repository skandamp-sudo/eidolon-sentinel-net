"""Minimal passive packet sources. No flow, feature, model or output logic.

read() returns a packet or an explicit control result, never a fake packet.
Only the processing worker reads/acknowledges; stop() may run concurrently.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import math
from pathlib import Path
import queue
import threading
import time
from typing import Protocol, runtime_checkable
import uuid

from scapy.utils import PcapReader

from sentinel_net.ingestion.parser import extract_raw_packet
from sentinel_net.models.types import ParsedPacket, RawPacket


class SourceMode(str, Enum):
    LIVE = 'LIVE'
    REPLAY = 'REPLAY'


class ReadKind(str, Enum):
    PACKET = 'packet'
    IDLE = 'idle'
    EOF = 'eof'
    CANCELLED = 'cancelled'


class SourceError(RuntimeError):
    """Fatal source opening, reading or capture failure; safe public message."""


@dataclass(frozen=True)
class SourceRead:
    kind: ReadKind
    packet: RawPacket | ParsedPacket | None = None
    idle_watermark: float | None = None


@runtime_checkable
class PassivePacketSource(Protocol):
    mode: SourceMode

    @property
    def provenance(self) -> dict[str, str]: ...
    def start(self) -> None: ...
    def read(self, timeout: float = .1) -> SourceRead: ...
    def acknowledge(self) -> None: ...
    def stop(self) -> None: ...


class LiveCaptureSource:
    """Adapt the RW-2 bounded queue and receive-only capture owner.

    stop() joins capture before cancellation becomes observable. Accepted
    queue entries are still returned, then CANCELLED (live has no natural EOF).
    A missing capture object supports the legacy externally-owned queue API.
    """
    mode = SourceMode.LIVE

    def __init__(self, packets, metrics, *, capture=None, interface='', clock=time.time):
        self.queue = packets
        self.metrics = metrics
        self.capture = capture
        self.interface = interface
        self.clock = clock
        self._started = False
        self._stopped = threading.Event()
        self._stop_lock = threading.Lock()

    @property
    def provenance(self):
        result = {'source_mode': self.mode.value}
        if self.interface:
            result['capture_interface'] = self.interface
        return result

    def start(self):
        if self._started or self._stopped.is_set():
            raise SourceError('Live source is one-shot')
        self._started = True
        if self.capture:
            try:
                self.capture.start()
            except Exception as exc:
                self.metrics.increment('source_errors')
                raise SourceError('Live capture initialization failed') from exc

    def read(self, timeout=.1):
        if not self._started:
            raise SourceError('Live source has not started')
        try:
            packet = self.queue.get(timeout=timeout)
            return SourceRead(ReadKind.PACKET, packet)
        except queue.Empty:
            if self._stopped.is_set():
                return SourceRead(ReadKind.CANCELLED)
            if self.capture and getattr(self.capture, 'failed', False):
                self.metrics.increment('source_errors')
                raise SourceError('Live capture worker failed')
            return SourceRead(ReadKind.IDLE, idle_watermark=self.clock())

    def acknowledge(self):
        self.queue.task_done()
        self.metrics.set_gauge('capture_queue_depth', self.queue.qsize())

    def stop(self):
        with self._stop_lock:
            if self._stopped.is_set():
                return
            if self.capture:
                self.capture.stop()
            self._stopped.set()


class PcapReplaySource:
    """Pull one recorded packet at a time. No producer queue or materialization.

    Optional pacing uses recorded deltas against a monotonic runtime clock.
    A packet already read for pacing is accepted and is yielded even if stop
    interrupts its delay; no subsequent file record is read after cancellation.
    File closure is serialized with reads; stop wakes pacing before joining the reader lock.
    """
    mode = SourceMode.REPLAY

    def __init__(self, path: Path, metrics, *, realtime=False, speed=1.0,
                 reader_factory=PcapReader, clock=time.monotonic):
        self.path = Path(path)
        self.metrics = metrics
        self.realtime = realtime
        self.speed = speed
        self._reader_factory = reader_factory
        self._clock = clock
        self._reader = None
        self._started = False
        self._stop = threading.Event()
        self._pending = None
        self._due = 0.0
        self._previous_capture = None
        self._end = None
        self._identifier = uuid.uuid4().hex
        self._reader_lock = threading.Lock()

    @property
    def provenance(self):
        # An opaque session identifier, not a path, basename, or content claim.
        return {'source_mode': self.mode.value, 'replay_file_identifier': self._identifier}

    def start(self):
        if self._started or self._stop.is_set():
            raise SourceError('Replay source is one-shot')
        self._started = True
        try:
            if not math.isfinite(self.speed) or self.speed <= 0:
                raise ValueError('Replay speed must be finite and positive')
            if self.path.suffix.lower() not in ('.pcap', '.pcapng'):
                raise ValueError('Replay requires a PCAP or PCAPNG file')
            if not self.path.is_file():
                raise ValueError('Replay input is not a readable file')
            self._reader = self._reader_factory(str(self.path))
        except Exception as exc:
            self.metrics.increment('source_errors')
            raise SourceError('Replay source initialization failed') from exc

    def _finish(self, kind):
        if self._reader is not None:
            self._reader.close()
            self._reader = None
        self._end = kind
        return SourceRead(kind)

    def read(self, timeout=.1):
        with self._reader_lock:
            return self._read(timeout)

    def _read(self, timeout):
        if not self._started:
            raise SourceError('Replay source has not started')
        if self._end is not None:
            return SourceRead(self._end)
        if self._pending is None and self._stop.is_set():
            return self._finish(ReadKind.CANCELLED)
        try:
            if self._pending is None:
                try:
                    captured = self._reader.read_packet()
                except EOFError:
                    return self._finish(ReadKind.EOF)
                self.metrics.increment('packets_observed')
                self._pending = extract_raw_packet(captured)
                observed = self._pending.timestamp
                if not math.isfinite(observed):
                    raise ValueError('Invalid capture timestamp')
                delay = 0.0
                if self.realtime and self._previous_capture is not None:
                    delay = max(0.0, observed - self._previous_capture) / self.speed
                self._due = self._clock() + delay
                self._previous_capture = observed
            remaining = self._due - self._clock()
            if remaining > 0 and not self._stop.is_set():
                self._stop.wait(min(timeout, remaining))
                if self._clock() < self._due and not self._stop.is_set():
                    return SourceRead(ReadKind.IDLE)  # no replay wall-clock watermark
            packet, self._pending = self._pending, None
            return SourceRead(ReadKind.PACKET, packet)
        except Exception as exc:
            self.metrics.increment('source_errors')
            self._finish(ReadKind.CANCELLED)
            raise SourceError('Replay source read failed') from exc

    def acknowledge(self):
        pass  # pull-based source has no queued work

    def stop(self):
        self._stop.set()  # wake pacing before acquiring the reader lock
        with self._reader_lock:
            if self._reader is not None:
                self._reader.close()
                self._reader = None
