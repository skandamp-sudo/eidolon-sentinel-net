"""Tests for event retention and bounded storage."""

from __future__ import annotations

import time

import pytest

from sentinel_net.models.types import (
    DetectionEvent,
    FlowKey,
    ObservedFlow,
)
from sentinel_net.storage.database import Database


def _make_event(event_id: str, ts: float) -> DetectionEvent:
    fk = FlowKey(src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=1, dst_port=80, protocol=6)
    flow = ObservedFlow(
        flow_key=fk, direction="forward", start_time=ts,
        end_time=ts + 1, duration_sec=1.0, packet_count=1,
        byte_count=100, payload_byte_count=50,
    )
    return DetectionEvent(
        id=event_id, timestamp=ts, flow_key=fk, observed_flow=flow,
        severity="info", rationale="test", metadata={},
    )


class TestRetention:
    @pytest.mark.asyncio
    async def test_cleanup_by_max_count(self, tmp_path):
        db = Database(tmp_path / "test.db")
        await db.initialize()

        # Store 10 events
        base = time.time()
        for i in range(10):
            await db.store_event(_make_event(f"evt-{i}", base + i))

        count_before = await db.get_event_count()
        assert count_before == 10

        # Retain only 5
        deleted = await db.cleanup_old_events(max_count=5, max_age_sec=None)
        assert deleted == 5

        count_after = await db.get_event_count()
        assert count_after == 5
        await db.close()

    @pytest.mark.asyncio
    async def test_cleanup_by_age(self, tmp_path):
        db = Database(tmp_path / "test.db")
        await db.initialize()

        now = time.time()
        # 5 old events (1 hour ago)
        for i in range(5):
            await db.store_event(_make_event(f"old-{i}", now - 3600 + i))

        # 5 recent events
        for i in range(5):
            await db.store_event(_make_event(f"new-{i}", now + i))

        deleted = await db.cleanup_old_events(max_count=None, max_age_sec=1800)  # 30 min
        assert deleted == 5

        count_after = await db.get_event_count()
        assert count_after == 5
        await db.close()

    @pytest.mark.asyncio
    async def test_cleanup_no_action_when_within_limits(self, tmp_path):
        db = Database(tmp_path / "test.db")
        await db.initialize()

        base = time.time()
        for i in range(3):
            await db.store_event(_make_event(f"evt-{i}", base + i))

        deleted = await db.cleanup_old_events(max_count=10, max_age_sec=3600)
        assert deleted == 0
        await db.close()

    @pytest.mark.asyncio
    async def test_combined_cleanup(self, tmp_path):
        db = Database(tmp_path / "test.db")
        await db.initialize()

        now = time.time()
        # 3 old + 7 recent
        for i in range(3):
            await db.store_event(_make_event(f"old-{i}", now - 7200 + i))
        for i in range(7):
            await db.store_event(_make_event(f"new-{i}", now + i))

        # Age cleanup first (removes old 3), then count cleanup (keep 5 of remaining 7)
        deleted = await db.cleanup_old_events(max_count=5, max_age_sec=3600)
        assert deleted >= 3
        await db.close()

    @pytest.mark.asyncio
    async def test_bounded_storage(self, tmp_path):
        """Retention prevents unbounded growth."""
        db = Database(tmp_path / "test.db")
        await db.initialize()

        base = time.time()
        for i in range(100):
            await db.store_event(_make_event(f"evt-{i}", base + i))

        assert await db.get_event_count() == 100

        deleted = await db.cleanup_old_events(max_count=20, max_age_sec=None)
        assert deleted == 80
        assert await db.get_event_count() == 20
        await db.close()
