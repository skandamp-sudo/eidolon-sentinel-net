"""Tests for EventBus in-process pub/sub."""

from __future__ import annotations

import queue
import threading
import time

import pytest

from sentinel_net.sensor.event_bus import EventBus


class TestEventBus:
    def test_subscribe_creates_queue(self):
        bus = EventBus(max_queue_size=10)
        q = bus.subscribe("sub1")
        assert isinstance(q, queue.Queue)
        assert bus.subscriber_count == 1
        bus.shutdown()

    def test_publish_delivers_to_subscribers(self):
        bus = EventBus(max_queue_size=10)
        q1 = bus.subscribe("sub1")
        q2 = bus.subscribe("sub2")
        bus.publish({"type": "test", "data": "hello"})
        assert q1.get_nowait()["data"] == "hello"
        assert q2.get_nowait()["data"] == "hello"
        bus.shutdown()

    def test_unsubscribe_removes(self):
        bus = EventBus(max_queue_size=10)
        bus.subscribe("sub1")
        bus.unsubscribe("sub1")
        assert bus.subscriber_count == 0
        bus.shutdown()

    def test_unsubscribe_nonexistent_is_safe(self):
        bus = EventBus(max_queue_size=10)
        bus.unsubscribe("nonexistent")  # Should not raise
        bus.shutdown()

    def test_bounded_queue_drops(self):
        bus = EventBus(max_queue_size=2)
        q = bus.subscribe("sub1")
        bus.publish({"n": 1})
        bus.publish({"n": 2})
        bus.publish({"n": 3})  # Should be dropped for full queue
        assert q.qsize() == 2
        assert bus.dropped_events >= 1
        bus.shutdown()

    def test_publish_after_shutdown(self):
        bus = EventBus(max_queue_size=10)
        bus.subscribe("sub1")
        bus.shutdown()
        delivered = bus.publish({"type": "test"})
        assert delivered == 0

    def test_publish_no_subscribers(self):
        bus = EventBus(max_queue_size=10)
        delivered = bus.publish({"type": "test"})
        assert delivered == 0
        bus.shutdown()

    def test_multiple_subscribers_independent(self):
        bus = EventBus(max_queue_size=5)
        q1 = bus.subscribe("fast")
        q2 = bus.subscribe("slow")
        # Fill q2
        for i in range(5):
            bus.publish({"n": i})
        # q2 is full, q1 is full — next publish drops for both
        bus.publish({"n": 99})
        assert q1.qsize() == 5
        assert q2.qsize() == 5
        bus.shutdown()

    def test_thread_safety(self):
        bus = EventBus(max_queue_size=100)
        q = bus.subscribe("sub1")

        def producer():
            for i in range(50):
                bus.publish({"n": i})

        threads = [threading.Thread(target=producer) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert q.qsize() == 100  # Bounded at 100
        bus.shutdown()

    def test_subscriber_count(self):
        bus = EventBus(max_queue_size=10)
        bus.subscribe("a")
        bus.subscribe("b")
        bus.subscribe("c")
        assert bus.subscriber_count == 3
        bus.unsubscribe("b")
        assert bus.subscriber_count == 2
        bus.shutdown()
