"""
PCAP replay-to-dashboard bridge for EIDOLON // SENTINEL-NET demo.

Feeds a PCAP file through the REAL production pipeline:
  PCAP → Parser → Flow Aggregator → Feature Extractor → ML Inference →
  Database Persist → EventBus → WebSocket → Dashboard

SECURITY: Structurally passive. Reads files from disk only.
No network I/O, no packet transmission, no active probing.

LABELING: Sensor state is set to REPLAYING (not RUNNING) to honestly
distinguish recorded traffic replay from live network capture.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from pathlib import Path


from sentinel_net.sensor.runtime_model import load_runtime_model
from sentinel_net.sensor.sources import PcapReplaySource
from sentinel_net.sensor.pipeline import PacketProcessingPipeline
from types import SimpleNamespace
from sentinel_net.sensor.event_bus import EventBus
from sentinel_net.sensor.lifecycle import SensorLifecycle, SensorState
from sentinel_net.sensor.metrics import SensorMetrics
from sentinel_net.storage.database import Database
from sentinel_net.sensor.event_output import persist_and_publish as _persist_and_publish

logger = logging.getLogger(__name__)



@dataclass
class DemoReplayConfig:
    """Configuration for a demo PCAP replay session."""

    pcap_path: Path
    model: str
    model_registry: Path = Path("models/registry")
    realtime: bool = True
    speed: float = 1.0
    flow_idle_timeout: float = 120.0
    max_active_flows: int = 100_000


async def load_detection_pipeline(config):
    """Resolve only the explicitly requested approved local bundle."""
    return await asyncio.to_thread(load_runtime_model, config.model, registry=config.model_registry)


async def run_replay(config, db, event_bus, lifecycle, metrics, *, detection=None) -> dict:
    """Replay is a finite source of the same worker used by the live service."""
    starting = metrics.snapshot()
    lifecycle.transition(SensorState.STARTING)
    pipeline = None
    watch = None
    source = None
    cancelled = False
    started = time.monotonic()

    async def watch_shutdown():
        while True:
            if lifecycle.shutdown_requested:
                await asyncio.to_thread(source.stop)
                return
            await asyncio.sleep(.05)

    try:
        if detection is None:
            detection = await load_detection_pipeline(config)
        source = PcapReplaySource(config.pcap_path, metrics,
                                  realtime=config.realtime, speed=config.speed)
        runtime = SimpleNamespace(flow_idle_timeout_sec=config.flow_idle_timeout,
                                  max_active_flows=config.max_active_flows)
        pipeline = PacketProcessingPipeline(runtime, source, event_bus, metrics, detection,
                                            db=db, event_loop=asyncio.get_running_loop())
        await asyncio.to_thread(pipeline.start)
        lifecycle.transition(SensorState.REPLAYING)
        metrics.start_time, metrics.stop_time = time.time(), 0
        watch = asyncio.create_task(watch_shutdown())
        try:
            await pipeline.wait()
        except asyncio.CancelledError:
            # asyncio cancellation requests input stop, not worker abandonment.
            cancelled = True
            await asyncio.to_thread(source.stop)
            await pipeline.wait()
        if pipeline.completion == 'cancelled' or cancelled:
            lifecycle.transition(SensorState.STOPPING)
            lifecycle.transition(SensorState.STOPPED)
        else:
            lifecycle.transition(SensorState.REPLAY_COMPLETE)
    except BaseException as exc:
        if pipeline and pipeline.alive:
            await asyncio.to_thread(source.stop)
            try:
                await pipeline.wait()
            except Exception:
                logger.exception('Replay drain completed with errors')
        if metrics.processing_errors == starting['processing_errors'] and not metrics.source_errors:
            metrics.increment('processing_errors')
        lifecycle.transition(SensorState.ERROR, error=type(exc).__name__)
        raise
    finally:
        if source:
            await asyncio.to_thread(source.stop)
        if watch:
            watch.cancel()
            await asyncio.gather(watch, return_exceptions=True)
        metrics.stop_time = time.time()

    if cancelled:
        raise asyncio.CancelledError
    snapshot = metrics.snapshot()
    return {
        'pcap_file': str(config.pcap_path),  # local CLI summary only, not event/API provenance
        'total_packets': snapshot['packets_observed'] - starting['packets_observed'],
        'parsed_packets': snapshot['packets_parsed'] - starting['packets_parsed'],
        'skipped_packets': snapshot['packets_malformed'] - starting['packets_malformed'],
        'total_flows': snapshot['flows_completed'] - starting['flows_completed'],
        'total_detections': snapshot['detections_generated'] - starting['detections_generated'],
        'events_persisted': snapshot['events_persisted'] - starting['events_persisted'],
        'elapsed_sec': round(time.monotonic() - started, 2),
        'mode': 'REPLAY', 'completion': pipeline.completion,
    }
