"""
End-to-end offline PCAP processing pipeline for EIDOLON // SENTINEL-NET.

Chains: PCAP File → Packet Parser → Flow Aggregator → Feature Extractor → FeatureVector

This pipeline works completely offline. It reads PCAP files from disk,
parses packets, aggregates them into flows, and extracts statistical features.

SECURITY: The pipeline is structurally passive. It performs NO network I/O,
NO packet transmission, NO active probing, and NO traffic decryption.
"""

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path

from sentinel_net.features.extractor import FeatureExtractor
from sentinel_net.flow.aggregator import FlowAggregator, FlowAggregatorConfig
from sentinel_net.ingestion.replay import PcapReplay, PcapReplayConfig
from sentinel_net.models.types import FeatureVector, ObservedFlow

logger = logging.getLogger(__name__)


@dataclass
class PipelineResult:
    """Result of processing a PCAP file through the full pipeline.

    Attributes:
        flows: Finalized ObservedFlow records.
        feature_vectors: Extracted FeatureVector records (1:1 with flows).
        total_packets: Total packets read from the PCAP.
        parsed_packets: Packets successfully parsed (IP only).
        skipped_packets: Packets skipped (non-IP, malformed).
        total_flows: Number of flows produced.
        processing_time_sec: Wall-clock time for the entire pipeline.
    """

    flows: list[ObservedFlow] = field(default_factory=list)
    feature_vectors: list[FeatureVector] = field(default_factory=list)
    total_packets: int = 0
    parsed_packets: int = 0
    skipped_packets: int = 0
    total_flows: int = 0
    processing_time_sec: float = 0.0


@dataclass
class PipelineConfig:
    """Configuration for the PCAP processing pipeline.

    Attributes:
        idle_timeout_sec: Flow idle timeout in seconds.
        max_active_flows: Maximum concurrent active flows.
        store_packets: Whether to retain ParsedPacket refs in flows.
        realtime: Whether to replay at original timing (False for batch).
    """

    idle_timeout_sec: float = 120.0
    max_active_flows: int = 100_000
    store_packets: bool = False
    realtime: bool = False


class PcapPipeline:
    """Offline PCAP → FeatureVector processing pipeline.

    Usage::

        pipeline = PcapPipeline()
        result = pipeline.process(Path("capture.pcap"))
        for fv in result.feature_vectors:
            arr = fv.to_numpy_array()  # ready for ML
    """

    def __init__(self, config: PipelineConfig | None = None) -> None:
        self._config = config or PipelineConfig()

    def process(self, pcap_path: Path) -> PipelineResult:
        """Process a PCAP file through the complete pipeline (synchronous).

        Args:
            pcap_path: Path to the PCAP file.

        Returns:
            PipelineResult with flows, feature vectors, and statistics.
        """
        start_time = time.monotonic()

        # 1. Replay PCAP
        replay_config = PcapReplayConfig(
            pcap_path=pcap_path,
            realtime=self._config.realtime,
        )
        replay = PcapReplay(replay_config)
        packets = replay.replay_sync()

        # 2. Aggregate into flows
        agg_config = FlowAggregatorConfig(
            idle_timeout_sec=self._config.idle_timeout_sec,
            max_active_flows=self._config.max_active_flows,
            store_packets=self._config.store_packets,
        )
        aggregator = FlowAggregator(agg_config)

        watermark = float("-inf")
        for pkt in packets:
            watermark = max(watermark, pkt.timestamp)
            aggregator.expire_idle(watermark)
            aggregator.ingest(pkt)

        # Flush all flows (end of PCAP)
        flows = aggregator.flush_all()

        # 3. Extract features
        extractor = FeatureExtractor()
        feature_vectors = extractor.extract_batch(flows)

        elapsed = time.monotonic() - start_time

        result = PipelineResult(
            flows=flows,
            feature_vectors=feature_vectors,
            total_packets=replay.packet_count,
            parsed_packets=replay.parsed_count,
            skipped_packets=replay.skipped_count,
            total_flows=len(flows),
            processing_time_sec=elapsed,
        )

        logger.info(
            f"Pipeline complete: {result.total_packets} packets → "
            f"{result.parsed_packets} parsed → {result.total_flows} flows → "
            f"{len(feature_vectors)} feature vectors in {elapsed:.3f}s"
        )

        return result

    def process_packets(
        self,
        packets: list,
        aggregator: FlowAggregator | None = None,
    ) -> PipelineResult:
        """Process pre-parsed packets (for testing or streaming use).

        Args:
            packets: List of ParsedPacket objects.
            aggregator: Optional pre-configured aggregator.

        Returns:
            PipelineResult with flows and feature vectors.
        """
        start_time = time.monotonic()

        if aggregator is None:
            agg_config = FlowAggregatorConfig(
                idle_timeout_sec=self._config.idle_timeout_sec,
                max_active_flows=self._config.max_active_flows,
                store_packets=self._config.store_packets,
            )
            aggregator = FlowAggregator(agg_config)

        watermark = float("-inf")
        for pkt in packets:
            watermark = max(watermark, pkt.timestamp)
            aggregator.expire_idle(watermark)
            aggregator.ingest(pkt)

        flows = aggregator.flush_all()

        extractor = FeatureExtractor()
        feature_vectors = extractor.extract_batch(flows)

        elapsed = time.monotonic() - start_time

        return PipelineResult(
            flows=flows,
            feature_vectors=feature_vectors,
            total_packets=len(packets),
            parsed_packets=len(packets),
            skipped_packets=0,
            total_flows=len(flows),
            processing_time_sec=elapsed,
        )
