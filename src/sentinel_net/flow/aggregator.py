"""
Flow aggregation engine for EIDOLON // SENTINEL-NET.

Groups ParsedPacket objects into ObservedFlow records by matching packets
to conversations using canonical 5-tuple keys. Tracks forward/reverse
direction based on the initiator (first packet sender).

SECURITY: This module performs NO network I/O. It is a pure in-memory
data aggregation engine that processes ParsedPacket objects.
It does NOT transmit, modify, inject, or probe any network traffic.
"""

import logging
import time
from dataclasses import dataclass, field

from sentinel_net.models.types import (
    TCP_ACK,
    TCP_FIN,
    TCP_PSH,
    TCP_RST,
    TCP_SYN,
    FlowKey,
    ObservedFlow,
    ParsedPacket,
)

logger = logging.getLogger(__name__)


@dataclass
class FlowAggregatorConfig:
    """Configuration for the flow aggregation engine.

    Attributes:
        idle_timeout_sec: Seconds of inactivity before a flow is expired.
        max_active_flows: Upper bound on active flows to prevent unbounded memory.
            When exceeded, the oldest idle flow is evicted.
        store_packets: If True, retain ParsedPacket references in the flow.
            Set to False to reduce memory usage (packet details are still
            counted in statistics).
    """

    idle_timeout_sec: float = 120.0
    max_active_flows: int = 100_000
    store_packets: bool = False
    fin_grace_sec: float = 1.0

    def __post_init__(self) -> None:
        if self.idle_timeout_sec <= 0 or self.max_active_flows <= 0 or self.fin_grace_sec < 0:
            raise ValueError('Flow limits must be positive; FIN grace must be nonnegative')


@dataclass
class _ActiveFlow:
    """Internal mutable state for an in-progress flow.

    Not exported — callers receive finalized ObservedFlow objects.
    """

    # Canonical conversation key (sorted endpoints)
    conversation_key: str

    # The initiator's FlowKey (first packet determines forward direction)
    initiator_key: FlowKey

    # Timing
    first_seen: float = 0.0
    last_seen: float = 0.0

    # Forward direction (initiator → responder)
    fwd_packet_count: int = 0
    fwd_bytes: int = 0
    fwd_payload_bytes: int = 0
    fwd_timestamps: list[float] = field(default_factory=list)

    # Reverse direction (responder → initiator)
    rev_packet_count: int = 0
    rev_bytes: int = 0
    rev_payload_bytes: int = 0
    rev_timestamps: list[float] = field(default_factory=list)

    # TCP flags (counted from bitmask)
    syn_count: int = 0
    syn_ack_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    psh_count: int = 0

    # Packet sizes for statistics
    packet_sizes: list[int] = field(default_factory=list)

    # Stored packets (only if config.store_packets is True)
    packets: list[ParsedPacket] = field(default_factory=list)

    # Completion detection
    fin_seen: bool = False
    fin_timestamp: float | None = None
    rst_seen: bool = False

    def is_forward(self, pkt: ParsedPacket) -> bool:
        """Determine if a packet is in the forward (initiator→responder) direction."""
        return (
            pkt.src_ip == self.initiator_key.src_ip
            and pkt.dst_ip == self.initiator_key.dst_ip
            and pkt.src_port == self.initiator_key.src_port
            and pkt.dst_port == self.initiator_key.dst_port
        )


class FlowAggregator:
    """Aggregates ParsedPacket objects into ObservedFlow records.

    Packets are mapped to conversations using a canonical 5-tuple key
    (sorted endpoints + protocol). The first packet to create a flow
    defines the 'forward' direction.

    Flows are expired after a configurable idle timeout or when TCP
    FIN/RST is observed. Completed flows are exposed via flush methods
    in deterministic timestamp order.

    SECURITY: This class performs NO network I/O. No packets are sent,
    modified, or injected. No hosts are probed or scanned.
    """

    def __init__(self, config: FlowAggregatorConfig | None = None) -> None:
        self._config = config or FlowAggregatorConfig()
        self._active: dict[str, _ActiveFlow] = {}
        self._completed: list[ObservedFlow] = []
        self._total_packets_processed: int = 0
        self._total_flows_created: int = 0
        self._total_flows_expired: int = 0
        self._total_flows_evicted: int = 0

    @property
    def active_flow_count(self) -> int:
        """Number of currently active (non-expired) flows."""
        return len(self._active)

    @property
    def completed_flow_count(self) -> int:
        """Number of flows in the completed queue awaiting retrieval."""
        return len(self._completed)

    @property
    def total_packets_processed(self) -> int:
        """Total packets ingested since creation."""
        return self._total_packets_processed

    @property
    def total_flows_created(self) -> int:
        """Total flows created since creation."""
        return self._total_flows_created

    @property
    def total_flows_expired(self) -> int:
        """Total flows expired since creation."""
        return self._total_flows_expired

    @property
    def total_flows_evicted(self) -> int:
        return self._total_flows_evicted

    def ingest(self, packet: ParsedPacket) -> None:
        """Ingest a single ParsedPacket into the aggregator.

        Maps the packet to an existing flow or creates a new one.
        Updates flow statistics. Optionally retains the ParsedPacket
        reference (controlled by config.store_packets).

        Args:
            packet: A parsed network packet to aggregate.
        """
        self._total_packets_processed += 1

        # Build the flow key from this packet
        pkt_key = FlowKey(
            src_ip=packet.src_ip,
            dst_ip=packet.dst_ip,
            src_port=packet.src_port,
            dst_port=packet.dst_port,
            protocol=packet.protocol,
        )
        conversation_key = pkt_key.direction_key

        # Expire a reused tuple before adding its new packet. Global expiry is
        # driven by the caller's capture-time/wall-clock watermark.
        previous = self._active.get(conversation_key)
        if previous is not None and self._is_expired(previous, packet.timestamp):
            self._completed.append(self._finalize(self._active.pop(conversation_key)))
            self._total_flows_expired += 1

        if conversation_key in self._active:
            flow = self._active[conversation_key]
        else:
            # Evict oldest flow if at capacity
            if len(self._active) >= self._config.max_active_flows:
                self._evict_oldest()

            flow = _ActiveFlow(
                conversation_key=conversation_key,
                initiator_key=pkt_key,
                first_seen=packet.timestamp,
                last_seen=packet.timestamp,
            )
            self._active[conversation_key] = flow
            self._total_flows_created += 1

        # Update timing
        flow.last_seen = max(flow.last_seen, packet.timestamp)
        if packet.timestamp < flow.first_seen:
            flow.first_seen = packet.timestamp

        # Determine direction
        is_fwd = flow.is_forward(packet)

        # Update directional counters
        pkt_size = packet.ip_total_length
        if is_fwd:
            flow.fwd_packet_count += 1
            flow.fwd_bytes += pkt_size
            flow.fwd_payload_bytes += packet.payload_size
            flow.fwd_timestamps.append(packet.timestamp)
        else:
            flow.rev_packet_count += 1
            flow.rev_bytes += pkt_size
            flow.rev_payload_bytes += packet.payload_size
            flow.rev_timestamps.append(packet.timestamp)

        # Record packet size for statistics
        flow.packet_sizes.append(pkt_size)

        # Update TCP flags
        if packet.tcp_flags is not None:
            flags = packet.tcp_flags
            has_syn = bool(flags & TCP_SYN)
            has_ack = bool(flags & TCP_ACK)

            if has_syn and has_ack:
                flow.syn_ack_count += 1
            elif has_syn:
                flow.syn_count += 1

            if has_ack:
                flow.ack_count += 1
            if flags & TCP_FIN:
                flow.fin_count += 1
                flow.fin_seen = True
                if flow.fin_timestamp is None:
                    flow.fin_timestamp = packet.timestamp
            if flags & TCP_RST:
                flow.rst_count += 1
                flow.rst_seen = True
            if flags & TCP_PSH:
                flow.psh_count += 1

        # Store packet reference if configured
        if self._config.store_packets:
            # Drop raw bytes reference to limit memory
            packet.raw_packet = None
            flow.packets.append(packet)

        # RST ends the observed segment immediately, including the RST packet.
        # FIN starts a fixed grace window to retain teardown ACKs; it is not
        # prolonged by further traffic. No unseen TCP state is inferred.
        if flow.rst_seen or (flow.fin_seen and self._config.fin_grace_sec == 0):
            self._completed.append(self._finalize(self._active.pop(conversation_key)))
            self._total_flows_expired += 1

    def _is_expired(self, flow: _ActiveFlow, current_time: float) -> bool:
        return (
            current_time - flow.last_seen >= self._config.idle_timeout_sec
            or (flow.fin_timestamp is not None
                and current_time - flow.fin_timestamp >= self._config.fin_grace_sec)
        )

    def expire_idle(self, current_time: float | None = None) -> int:
        """Expire flows that have been idle beyond the timeout.

        Args:
            current_time: Reference time for idle check. Defaults to
                the current wall-clock time.

        Returns:
            Number of flows expired.
        """
        if current_time is None:
            current_time = time.time()

        expired_keys: list[str] = []

        for key, flow in self._active.items():
            if self._is_expired(flow, current_time):
                expired_keys.append(key)

        for key in expired_keys:
            flow = self._active.pop(key)
            self._completed.append(self._finalize(flow))
            self._total_flows_expired += 1

        if expired_keys:
            logger.debug(f"Expired {len(expired_keys)} idle flows")

        return len(expired_keys)

    def flush_completed(self) -> list[ObservedFlow]:
        """Retrieve and clear all completed flows.

        Returns flows in deterministic order (sorted by start_time,
        then by conversation key for ties).

        Returns:
            List of completed ObservedFlow objects.
        """
        result = sorted(
            self._completed,
            key=lambda f: (f.start_time, f.flow_key.direction_key),
        )
        self._completed.clear()
        return result

    def flush_all(self) -> list[ObservedFlow]:
        """Finalize and return ALL flows (active + completed).

        Use at end-of-PCAP to ensure no flows are lost. Returns flows
        in deterministic order (sorted by start_time).

        Returns:
            List of all ObservedFlow objects.
        """
        # Finalize all active flows
        for flow in self._active.values():
            self._completed.append(self._finalize(flow))
            self._total_flows_expired += 1

        self._active.clear()

        return self.flush_completed()

    def _evict_oldest(self) -> None:
        """Evict the flow with the oldest last_seen timestamp."""
        if not self._active:
            return

        oldest_key = min(self._active, key=lambda k: self._active[k].last_seen)
        flow = self._active.pop(oldest_key)
        self._completed.append(self._finalize(flow))
        self._total_flows_expired += 1
        self._total_flows_evicted += 1
        logger.debug(f"Evicted oldest flow: {oldest_key}")

    def _compute_iats(self, timestamps: list[float]) -> list[float]:
        """Compute inter-arrival times from sorted timestamps."""
        if len(timestamps) < 2:
            return []
        sorted_ts = sorted(timestamps)
        return [sorted_ts[i + 1] - sorted_ts[i] for i in range(len(sorted_ts) - 1)]

    def _finalize(self, active: _ActiveFlow) -> ObservedFlow:
        """Convert an _ActiveFlow into a finalized ObservedFlow."""
        duration = active.last_seen - active.first_seen
        total_pkts = active.fwd_packet_count + active.rev_packet_count
        total_bytes = active.fwd_bytes + active.rev_bytes
        total_payload = active.fwd_payload_bytes + active.rev_payload_bytes

        # Determine direction label
        if active.rev_packet_count == 0:
            direction = "forward"
        elif active.fwd_packet_count == 0:
            direction = "reverse"
        else:
            direction = "bidirectional"

        # Build TCP flag counts dict (backward-compat with Phase 1)
        tcp_flag_counts = {
            "SYN": active.syn_count,
            "SYN_ACK": active.syn_ack_count,
            "ACK": active.ack_count,
            "FIN": active.fin_count,
            "RST": active.rst_count,
            "PSH": active.psh_count,
        }

        return ObservedFlow(
            flow_key=active.initiator_key,
            direction=direction,
            start_time=active.first_seen,
            end_time=active.last_seen,
            duration_sec=duration,
            packet_count=total_pkts,
            byte_count=total_bytes,
            payload_byte_count=total_payload,
            packets=active.packets,
            tcp_flag_counts=tcp_flag_counts,
            is_complete=active.fin_seen or active.rst_seen,
            # Phase 2 fields
            forward_packet_count=active.fwd_packet_count,
            reverse_packet_count=active.rev_packet_count,
            forward_bytes=active.fwd_bytes,
            reverse_bytes=active.rev_bytes,
            forward_payload_bytes=active.fwd_payload_bytes,
            reverse_payload_bytes=active.rev_payload_bytes,
            syn_count=active.syn_count,
            syn_ack_count=active.syn_ack_count,
            ack_count=active.ack_count,
            fin_count=active.fin_count,
            rst_count=active.rst_count,
            psh_count=active.psh_count,
            forward_iats=self._compute_iats(active.fwd_timestamps),
            reverse_iats=self._compute_iats(active.rev_timestamps),
            packet_sizes=active.packet_sizes,
            initiator_ip=active.initiator_key.src_ip,
            initiator_port=active.initiator_key.src_port,
        )
