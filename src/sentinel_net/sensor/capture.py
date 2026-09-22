"""Passive packet capture source.

SECURITY: This module ONLY receives packets using scapy's sniff.
It has NO code path for sending, injecting, modifying, or retransmitting packets.
It does not execute shell commands for filter configuration.
"""
from __future__ import annotations
import logging
import queue
import threading
from dataclasses import dataclass
from typing import Any

from scapy.all import AsyncSniffer
from scapy.interfaces import resolve_iface

from sentinel_net.ingestion.parser import extract_raw_packet
from sentinel_net.models.types import ParsedPacket
from sentinel_net.sensor.metrics import SensorMetrics

logger = logging.getLogger(__name__)


@dataclass
class CaptureConfig:
    interface: str
    bpf_filter: str = ""
    snap_length: int = 65535
    promiscuous_mode: bool = False
    buffer_size: int = 2 * 1024 * 1024


class PassiveCaptureSource:
    """Observation-only packet capture.
    
    SECURITY: This class ONLY receives packets. It has NO code path
    for sending, injecting, modifying, or retransmitting packets.
    """
    
    def __init__(self, config: CaptureConfig, packet_queue: queue.Queue, metrics: SensorMetrics):
        self._config = config
        self._queue = packet_queue
        self._metrics = metrics
        self._running = threading.Event()
        self._thread: threading.Thread | None = None
        self._error: str | None = None
    
    @staticmethod
    def validate_interface(interface: str) -> None:
        if not interface or interface.strip() != interface or any(ord(c) < 32 for c in interface):
            raise ValueError("A valid capture interface is required")
        iface = resolve_iface(interface)
        if not iface.is_valid():
            raise ValueError("Capture interface is unavailable")

    @property
    def failed(self) -> bool:
        sniffer = getattr(self, '_sniffer', None)
        failed = self._running.is_set() and sniffer is not None and not sniffer.running
        if failed and self._error is None:
            self._error = 'Capture worker stopped unexpectedly'
            self._metrics.increment('capture_errors')
        return bool(self._error)

    def start(self) -> None:
        """Open the receive-only socket synchronously, then verify worker readiness."""
        self._validate_filter(self._config.bpf_filter)
        self.validate_interface(self._config.interface)
        if self._running.is_set():
            raise RuntimeError('Capture is already running')
        self._socket = None
        self._sniffer = None
        ready = threading.Event()
        try:
            iface = resolve_iface(self._config.interface)
            self._socket = iface.l2listen()(
                iface=iface, filter=self._config.bpf_filter or None,
                promisc=self._config.promiscuous_mode)
            self._running.set()
            self._sniffer = AsyncSniffer(opened_socket=self._socket, store=False,
                                         prn=self._on_packet, started_callback=ready.set)
            self._sniffer.start()
            if not ready.wait(5) or not self._sniffer.running:
                raise RuntimeError('Capture worker did not become ready')
        except Exception:
            self._error = 'Capture initialization failed (check interface, filter and permissions)'
            self._metrics.increment('capture_errors')
            self.stop()
            raise RuntimeError(self._error) from None

    def refresh_statistics(self) -> None:
        """Read actual native BPF drop counters when this backend exposes them."""
        sock = getattr(self, '_socket', None)
        if sock is None:
            return
        drops = None
        if type(sock).__module__ == 'scapy.arch.bpf.supersocket' and hasattr(sock, 'get_stats'):
            try:
                _, value = sock.get_stats()
                if isinstance(value, int) and value >= 0:
                    drops = value
            except Exception:
                pass  # unavailable, never a synthetic zero
        self._metrics.set_gauge('kernel_capture_drops', drops)

    def stop(self) -> None:
        """Wake Scapy's control socket even with zero traffic; join before draining."""
        self._running.clear()
        sniffer = getattr(self, '_sniffer', None)
        if sniffer is not None:
            if sniffer.running and hasattr(sniffer, 'stop_cb'):
                sniffer.stop(join=False)
            if sniffer.thread is not None:
                sniffer.thread.join(timeout=5)
                if sniffer.thread.is_alive():
                    raise TimeoutError('Capture worker did not stop')
        sock = getattr(self, '_socket', None)
        if sock is not None:
            self.refresh_statistics()
            sock.close()
            self._socket = None

    def _on_packet(self, raw_pkt: Any) -> None:
        """Callback for incoming packets."""
        if not self._running.is_set():
            return
            
        self._metrics.increment("packets_observed")
        try:
            rp = extract_raw_packet(raw_pkt)
            rp.interface = self._config.interface
        except Exception:
            self._metrics.increment("packets_malformed")
            return
        
        try:
            self._queue.put_nowait(rp)
            self._metrics.set_gauge("capture_queue_depth", self._queue.qsize())
            self._metrics.observe_peak("capture_queue_peak", self._queue.qsize())
        except queue.Full:
            self._metrics.increment("packets_dropped")
    
    @staticmethod
    def _validate_filter(bpf_filter: str) -> None:
        """Validate BPF filter to prevent shell injection.
        
        SECURITY: Rejects shell metacharacters (; | ` $( ) > < & !)
        Only allows safe BPF syntax characters.
        """
        invalid_chars = [";", "|", "`", "$", "(", ")", ">", "<", "&", "!"]
        for c in invalid_chars:
            if c in bpf_filter:
                raise ValueError(f"Invalid character in BPF filter: {c}")


class MockCaptureSource:
    """Mock capture source for testing that provides pre-built ParsedPackets.

    Puts ParsedPacket objects directly into the queue (bypassing raw capture).
    The consuming pipeline should detect this and skip the parse step.
    """

    def __init__(self, packets: list[ParsedPacket], packet_queue: queue.Queue, metrics: SensorMetrics):
        self._packets = packets
        self._queue = packet_queue
        self._metrics = metrics
        self._running = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        """Start the mock capture loop."""
        self._running.set()
        self._thread = threading.Thread(target=self._capture_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop the mock capture loop."""
        self._running.clear()
        if self._thread:
            self._thread.join(timeout=2.0)

    def _capture_loop(self) -> None:
        """Push mock packets to the queue."""
        for pkt in self._packets:
            if not self._running.is_set():
                break

            self._metrics.increment("packets_observed")
            try:
                self._queue.put_nowait(pkt)
                self._metrics.set_gauge("capture_queue_depth", self._queue.qsize())
            except queue.Full:
                self._metrics.increment("packets_dropped")
