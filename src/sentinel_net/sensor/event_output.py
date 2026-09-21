"""Shared durable event output for existing live and replay callers (RW-1)."""
import logging

logger = logging.getLogger(__name__)


async def persist_and_publish(event, db, event_bus, metrics):
    metrics.increment('detections_generated')
    try:
        await db.store_event(event)
    except Exception:
        metrics.increment('persistence_errors')
        metrics.set_gauge('last_error_kind', 'PERSISTENCE_ERROR')
        metrics.increment('processing_errors')
        logger.exception('Event persistence failed: %s', event.id)
        raise
    metrics.increment('events_persisted')
    # All outputs use the same domain serializer, including the durable snapshot.
    try:
        result = event_bus.publish_result(event.to_dict())
    except Exception:
        metrics.increment('output_errors')
        metrics.increment('processing_errors')
        metrics.set_gauge('last_error_kind', 'OUTPUT_ERROR')
        raise
    metrics.increment('events_enqueued', result.enqueued)
    metrics.increment('events_dropped', result.dropped)
