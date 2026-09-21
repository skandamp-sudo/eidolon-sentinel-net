"""One packet-processing owner for every passive source."""
from __future__ import annotations

import asyncio
import logging
import threading
import time

from sentinel_net.features.extractor import FeatureExtractor
from sentinel_net.flow.aggregator import FlowAggregator, FlowAggregatorConfig
from sentinel_net.ingestion.parser import parse_packet
from sentinel_net.models.types import ParsedPacket
from sentinel_net.sensor.event_output import persist_and_publish
from sentinel_net.sensor.processing import infer_completed
from sentinel_net.sensor.sources import LiveCaptureSource, PassivePacketSource, ReadKind, SourceMode

logger = logging.getLogger(__name__)


class PacketProcessingPipeline:
    """Source → parser → aggregation → features → inference/evidence → durable output.

    Processing is serialized on one worker. SQLite writes run on its owning
    asyncio loop; callers on that loop must await wait()/astop(), never join it.
    Source control results carry no ML policy and are never network packets.
    """

    def __init__(self, config, source: PassivePacketSource, event_bus, metrics,
                 detection_pipeline=None, *, db=None, event_loop=None):
        self.source = source
        self._capture_queue = getattr(source, 'queue', None)  # compatibility gauge
        self._event_bus = event_bus
        self._metrics = metrics
        agg_config = getattr(config, 'flow_aggregator_config', None)
        if agg_config is None:
            agg_config = FlowAggregatorConfig(
                idle_timeout_sec=config.flow_idle_timeout_sec,
                max_active_flows=config.max_active_flows)
        self._aggregator = FlowAggregator(agg_config)
        self._extractor = FeatureExtractor()
        self._detection = detection_pipeline
        self._db = db
        self._event_loop = event_loop
        self._thread = None
        self._running = threading.Event()
        self._error = None
        self._fatal = False
        self.completion = None

    @property
    def failed(self):
        return self._fatal

    @property
    def alive(self):
        return self._thread is not None and self._thread.is_alive()

    def start(self):
        if self._thread is not None:
            raise RuntimeError('Processing owner is one-shot')
        if self._detection is None or self._db is None or self._event_loop is None:
            raise ValueError('Detection, database and owning event loop are required')
        if not self._event_loop.is_running() or not self._db.is_connected:
            raise ValueError('Database and owning event loop must be ready')
        try:
            self.source.start()
        except Exception:
            self._metrics.set_gauge('last_error_kind', 'SOURCE_ERROR')
            raise
        self._running.set()
        self._thread = threading.Thread(target=self._run_guarded, daemon=True)
        try:
            self._thread.start()
        except Exception:
            self._running.clear()
            self.source.stop()
            raise

    async def wait(self):
        """Wait for finite EOF or explicit source cancellation; preserve failure cause."""
        if self._thread is not None:
            await asyncio.to_thread(self._thread.join)
        if self._error:
            raise self._error

    async def astop(self):
        await asyncio.to_thread(self.stop)

    def stop(self):
        try:
            current_loop = asyncio.get_running_loop()
        except RuntimeError:
            current_loop = None
        if current_loop is not None and current_loop is self._event_loop:
            raise RuntimeError('Use await astop() from the database event loop')
        self.source.stop()
        self._running.clear()
        if self._thread:
            self._thread.join(timeout=30.0)
            if self._thread.is_alive():
                raise TimeoutError('Processing has not finished draining')
        if self._error:
            label = 'Live' if self.source.mode == SourceMode.LIVE else 'Replay'
            raise RuntimeError(f'{label} processing failed; inspect error counters/logs') from self._error

    def _run_guarded(self):
        try:
            self._processing_loop()
        except Exception as exc:
            self._error = exc
            self._fatal = True
            self._metrics.increment('processing_errors')
            self._metrics.set_gauge('last_error_kind', 'PROCESSING_ERROR')
            logger.exception('Processing worker stopped unexpectedly')
        finally:
            # Finalize accepted work exactly once on EOF, cancellation or failure.
            started = time.monotonic()
            try:
                self._process_completed_flows(self._aggregator.flush_all())
                self._update_gauges()
            except Exception as exc:
                self._error = exc
                self._fatal = True
                self._metrics.increment('processing_errors')
            finally:
                self._metrics.increment('processing_time_sec', time.monotonic()-started)
                try:
                    self.source.stop()
                except Exception as exc:
                    self._error = exc
                    self._fatal = True
                    self._metrics.increment('source_errors')
                    self._metrics.set_gauge('last_error_kind', 'SOURCE_ERROR')
                self._running.clear()

    def _processing_loop(self):
        watermark = float('-inf')
        while True:
            source_errors = self._metrics.source_errors
            try:
                item = self.source.read(timeout=.1)
            except Exception as exc:
                self._error = exc
                self._fatal = True
                self.completion = 'source_error'
                if self._metrics.source_errors == source_errors:
                    self._metrics.increment('source_errors')
                self._metrics.set_gauge('last_error_kind', 'SOURCE_ERROR')
                logger.exception('Passive source failed')
                break
            if item.kind in (ReadKind.EOF, ReadKind.CANCELLED):
                self.completion = item.kind.value
                break
            started = time.monotonic()
            try:
                if item.kind == ReadKind.IDLE:
                    if item.idle_watermark is not None:
                        # Preserve RW-2 semantics: idle wall time expires existing
                        # flows but never rewrites the capture-time watermark.
                        self._aggregator.expire_idle(item.idle_watermark)
                else:
                    try:
                        packet = item.packet
                        parsed = packet if isinstance(packet, ParsedPacket) else parse_packet(packet)
                        if parsed is None:
                            self._metrics.increment('packets_malformed')
                        else:
                            self._metrics.increment('packets_parsed')
                            watermark = max(watermark, parsed.timestamp)
                            self._aggregator.expire_idle(watermark)
                            self._aggregator.ingest(parsed)
                            self._metrics.increment('packets_processed')
                    except Exception as exc:
                        self._error = exc
                        self._metrics.increment('processing_errors')
                        self._metrics.increment('packet_processing_errors')
                        self._metrics.set_gauge('last_error_kind', 'PROCESSING_ERROR')
                        logger.exception('Packet processing failed')
                        # A broken replay parser must not report successful EOF.
                        if self.source.mode == SourceMode.REPLAY:
                            self.source.stop()
                    finally:
                        self.source.acknowledge()
                self._process_completed_flows()
                self._update_gauges()
            finally:
                # Runtime elapsed time only; never wall time minus historical PCAP time.
                self._metrics.increment('processing_time_sec', time.monotonic()-started)

    def _update_gauges(self):
        if self._capture_queue is not None:
            self._metrics.set_gauge('capture_queue_depth', self._capture_queue.qsize())
        self._metrics.set_gauge('flows_created', self._aggregator.total_flows_created)
        self._metrics.set_gauge('flows_active', self._aggregator.active_flow_count)
        self._metrics.set_gauge('flows_evicted', self._aggregator.total_flows_evicted)

    def _process_completed_flows(self, completed=None):
        if completed is None:
            completed = self._aggregator.flush_completed()
        for flow in completed:
            try:
                events = infer_completed([flow], self._extractor, self._detection, self._metrics)
            except Exception as exc:
                self._error = exc
                self._metrics.increment('processing_errors')
                self._metrics.set_gauge('last_error_kind', 'PROCESSING_ERROR')
                logger.exception('Flow inference failed')
                continue
            for event in events:
                event.metadata['source'] = dict(self.source.provenance)
                identity = getattr(self._detection, 'deployment_identity', None)
                if identity:
                    event.metadata['deployment_model'] = dict(identity)
                try:
                    asyncio.run_coroutine_threadsafe(
                        persist_and_publish(event, self._db, self._event_bus, self._metrics),
                        self._event_loop).result()
                except Exception as exc:
                    self._error = exc
                    logger.exception('Durable event output failed')


class LiveSensorPipeline(PacketProcessingPipeline):
    """Compatibility constructor for RW-1 callers with an externally owned queue.

    No independent processing logic. Stop the external producer before astop().
    New service callers use PacketProcessingPipeline with an explicit source.
    """
    def __init__(self, config, capture_queue, event_bus, metrics,
                 detection_pipeline=None, *, db=None, event_loop=None):
        super().__init__(config, LiveCaptureSource(capture_queue, metrics,
            interface=getattr(config, 'capture_interface', '')), event_bus, metrics,
            detection_pipeline, db=db, event_loop=event_loop)
