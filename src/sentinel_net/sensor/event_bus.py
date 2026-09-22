from __future__ import annotations
import queue
import threading
from typing import NamedTuple


class PublishResult(NamedTuple):
    enqueued: int
    dropped: int

class EventBus:
    """Lightweight in-process pub/sub with bounded buffer.
    
    SECURITY: No external connections required (No Redis/Kafka).
    Bounded queues prevent memory exhaustion.
    """
    def __init__(self, max_queue_size: int = 1000, max_subscribers: int = 32):
        if max_queue_size <= 0 or max_subscribers <= 0:
            raise ValueError('Event bus limits must be positive')
        self.max_subscribers = max_subscribers
        self.subscriber_peak = 0
        self.queue_peak = 0
        self.rejected_subscribers = 0
        self.max_queue_size = max_queue_size
        self._subscribers: dict[str, queue.Queue] = {}
        self._lock = threading.Lock()
        self._shutdown = False
        self._dropped_events = 0
    
    def subscribe(self, subscriber_id: str) -> queue.Queue:
        """Subscribe to events and return the bounded queue."""
        with self._lock:
            if self._shutdown:
                raise RuntimeError('Event bus is closed')
            if subscriber_id not in self._subscribers:
                if len(self._subscribers) >= self.max_subscribers:
                    self.rejected_subscribers += 1
                    raise RuntimeError('Subscriber capacity reached')
                self._subscribers[subscriber_id] = queue.Queue(maxsize=self.max_queue_size)
                self.subscriber_peak = max(self.subscriber_peak, len(self._subscribers))
            return self._subscribers[subscriber_id]
    
    def unsubscribe(self, subscriber_id: str) -> int:
        """Unsubscribe from events."""
        with self._lock:
            pending = self._subscribers.pop(subscriber_id, None)
            dropped = pending.qsize() if pending is not None else 0
            self._dropped_events += dropped
            return dropped
    
    def publish(self, event: dict) -> int:
        """Publish an event to all subscriber queues.
        
        Returns:
            Number of subscribers that received the event.
        """
        return self.publish_result(event).enqueued

    def publish_result(self, event: dict) -> PublishResult:
        """Atomic per-publication accounting; zero subscribers is not data loss."""
        delivered = 0
        dropped = 0
        with self._lock:
            if self._shutdown:
                return PublishResult(0, 0)
            for sub_id, q in self._subscribers.items():
                try:
                    q.put_nowait(event)
                    delivered += 1
                    self.queue_peak = max(self.queue_peak, q.qsize())
                except queue.Full:
                    self._dropped_events += 1
                    dropped += 1
        return PublishResult(delivered, dropped)
    
    def shutdown(self) -> int:
        """Signal all subscribers and clear queues."""
        with self._lock:
            self._shutdown = True
            dropped = 0
            for q in self._subscribers.values():
                while not q.empty():
                    try:
                        q.get_nowait()
                        dropped += 1
                    except queue.Empty:
                        break
            self._subscribers.clear()
            self._dropped_events += dropped
            return dropped
    
    @property
    def pending_count(self) -> int:
        with self._lock:
            return sum(q.qsize() for q in self._subscribers.values())

    @property
    def subscriber_count(self) -> int:
        """Number of active subscribers."""
        with self._lock:
            return len(self._subscribers)
    
    @property
    def dropped_events(self) -> int:
        """Total number of events dropped due to full queues."""
        with self._lock:
            return self._dropped_events
