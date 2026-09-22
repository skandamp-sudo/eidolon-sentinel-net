"""Single owner of continuous passive sensor resources and shutdown ordering."""
from __future__ import annotations

import asyncio
import logging
import math
import queue
import time

from sentinel_net.sensor.capture import CaptureConfig, PassiveCaptureSource
from sentinel_net.sensor.event_bus import EventBus
from sentinel_net.sensor.lifecycle import SensorLifecycle, SensorState
from sentinel_net.sensor.metrics import SensorMetrics
from sentinel_net.sensor.retention import RetentionWorker
from sentinel_net.sensor.operational_health import resource_reasons
from sentinel_net.sensor.pipeline import PacketProcessingPipeline
from sentinel_net.sensor.sources import LiveCaptureSource
from sentinel_net.sensor.runtime_model import load_runtime_model, ModelLoadError
from sentinel_net.storage.database import Database

logger = logging.getLogger(__name__)


class SensorService:
    """One-shot runtime. Recreate the owner to restart after failure/shutdown.

    Dependencies can be replaced by deterministic test sources. API lifecycle
    and CLI shutdown both delegate here; neither owns a second database/bus.
    """

    def __init__(self, config, *, capture_factory=PassiveCaptureSource,
                 interface_validator=PassiveCaptureSource.validate_interface,
                 model_loader=None, database_factory=Database):
        self.config = config
        self.lifecycle = SensorLifecycle()
        self.metrics = SensorMetrics()
        self.metrics.stop_time = self.metrics.start_time  # not started yet
        self.db = None
        self.event_bus = None
        self.pipeline = None
        self.capture = None
        self.source = None
        self._capture_factory = capture_factory
        self._interface_validator = interface_validator
        self.model_identity = None
        self._model_loader = model_loader or (lambda identity: load_runtime_model(identity, registry=config.model_registry))
        self._database_factory = database_factory
        self._monitor = None
        self.retention = None
        self._lock = asyncio.Lock()
        self._quiesced = False
        self._closed = False
        self._failed = False
        self._started = False
        self._failure_reason = ''
        self._reasons = set()

    def _validate(self):
        c = self.config
        for value in (c.capture_queue_size, c.event_queue_size, c.max_active_flows):
            if value <= 0:
                raise ValueError('Sensor queue and flow limits must be positive')
        if not math.isfinite(c.flow_idle_timeout_sec) or c.flow_idle_timeout_sec <= 0:
            raise ValueError('Flow idle timeout must be finite and positive')
        if not 1 <= c.api_port <= 65535:
            raise ValueError('API port must be between 1 and 65535')
        PassiveCaptureSource._validate_filter(c.capture_filter)
        self._interface_validator(c.capture_interface)

    async def start(self):
        async with self._lock:
            if self.lifecycle.state != SensorState.STOPPED or self._closed:
                raise RuntimeError('SensorService is one-shot and already started or closed')
            self.lifecycle.transition(SensorState.STARTING)
            stage = 'configuration'
            try:
                self._validate()
                stage = 'model loading'
                detection = await asyncio.to_thread(self._model_loader, self.config.sensor_model)
                self.model_identity = getattr(detection, 'deployment_identity', None)
                stage = 'database initialization'
                self.db = self._database_factory(self.config.database_path)
                await self.db.initialize()
                self.event_bus = EventBus(self.config.event_queue_size, self.config.max_subscribers)
                self.retention = RetentionWorker(self.db, self.config, self.metrics)
                self.retention.start()
                packets = queue.Queue(maxsize=self.config.capture_queue_size)
                self.capture = self._capture_factory(CaptureConfig(
                    interface=self.config.capture_interface,
                    bpf_filter=self.config.capture_filter,
                    promiscuous_mode=self.config.promiscuous_mode), packets, self.metrics)
                self.source = LiveCaptureSource(packets, self.metrics, capture=self.capture,
                                                interface=self.config.capture_interface)
                self.pipeline = PacketProcessingPipeline(
                    self.config, self.source, self.event_bus, self.metrics, detection,
                    db=self.db, event_loop=asyncio.get_running_loop())
                stage = 'capture initialization'
                await asyncio.to_thread(self.pipeline.start)
                self.metrics.start_time = time.time()
                self.metrics.stop_time = 0
                self._started = True
                self.lifecycle.transition(SensorState.RUNNING)
                self._monitor = asyncio.create_task(self._watch(), name='sensor-health')
                logger.info('LIVE PASSIVE SENSOR | interface=%s | database=%s | schema=2.0.0 / 52 | state=running',
                            self.config.capture_interface, self.config.database_path)
            except BaseException as exc:
                self._fail(exc.code if isinstance(exc, ModelLoadError) else stage.replace(' ', '_') + '_failed')
                await self._close()
                if isinstance(exc, ModelLoadError):
                    raise
                raise RuntimeError(f'Sensor startup failed during {stage}; check local configuration and resources') from None

    def _fail(self, reason):
        self._failed = True
        self._failure_reason = reason
        self._reasons.add(reason)
        if self.lifecycle.state != SensorState.FAILED:
            self.lifecycle.transition(SensorState.FAILED, error=reason)
        self.lifecycle.request_shutdown()

    def refresh_health(self):
        """Safe reason codes only; never exception strings, paths or credentials."""
        if self.lifecycle.state not in (SensorState.RUNNING, SensorState.DEGRADED):
            return
        capture_failed = getattr(self.capture, 'failed', False)
        if capture_failed or self.pipeline.failed:
            if capture_failed:
                self.metrics.set_gauge('last_error_kind', 'SOURCE_ERROR')
            self._fail('capture_worker_failed' if capture_failed else 'processing_worker_failed')
            return
        m = self.metrics.snapshot()
        self._reasons.update(resource_reasons(self.metrics, self.event_bus))
        if m['capture_queue_depth'] >= self.config.capture_queue_size * .8:
            self._reasons.add('capture_queue_pressure')
        # Degradation is latched for this run so intermittent loss stays visible.
        if self._reasons and self.lifecycle.state == SensorState.RUNNING:
            self.lifecycle.transition(SensorState.DEGRADED)

    def health(self):
        self.refresh_health()
        return {'state': self.lifecycle.state.value, 'mode': 'live_passive_sensor',
                'reasons': sorted(self._reasons)}

    async def _watch(self):
        while not self._quiesced:
            if hasattr(self.capture, 'refresh_statistics'):
                self.capture.refresh_statistics()
            self.refresh_health()
            if self._failed:
                return
            await asyncio.sleep(.1)

    async def quiesce(self):
        """Stop/drain producers while REST/WS remain alive to deliver final output."""
        async with self._lock:
            await self._quiesce()

    async def _quiesce(self):
        if self._quiesced:
            return
        if self._monitor:
            self._monitor.cancel()
            await asyncio.gather(self._monitor, return_exceptions=True)
        if self.lifecycle.state not in (SensorState.STOPPED, SensorState.STOPPING):
            self.lifecycle.transition(SensorState.STOPPING)
        if self.source:
            try:
                await asyncio.to_thread(self.source.stop)
            except Exception:
                self.metrics.increment('capture_errors')
                self._fail('capture_shutdown_failed')
                # Do not drain a queue or close storage while a producer survives.
                raise
        if self.pipeline:
            try:
                await self.pipeline.astop()
            except Exception:
                self._fail('processing_shutdown_failed')
                if self.pipeline.alive:
                    raise  # Never close storage underneath a surviving worker.
        if self.event_bus:
            deadline = asyncio.get_running_loop().time() + 1.5
            while self.event_bus.pending_count and asyncio.get_running_loop().time() < deadline:
                await asyncio.sleep(.02)
        self.metrics.stop_time = time.time() if self._started else self.metrics.start_time
        self._quiesced = True

    async def stop(self):
        async with self._lock:
            await self._close()

    async def _close(self):
        if self._closed:
            return
        await self._quiesce()
        if self.event_bus:
            self.metrics.increment('events_dropped', self.event_bus.shutdown())
        if self.retention:
            await self.retention.stop()
        if self.db:
            try:
                await self.db.close()
            except Exception:
                self._fail('database_close_failed')
                raise
        self._closed = True
        if self._failed:
            if self.lifecycle.state != SensorState.FAILED:
                self.lifecycle.transition(SensorState.FAILED, error=self._failure_reason)
        elif self.lifecycle.state == SensorState.STOPPING:
            self.lifecycle.transition(SensorState.STOPPED)
