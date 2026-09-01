"""Tests for SQLite database storage."""

import time
import uuid

import pytest

from sentinel_net.models.types import DetectionEvent, FlowKey, ObservedFlow
from sentinel_net.storage.database import Database

pytestmark = pytest.mark.asyncio


async def test_initialize_creates_tables(tmp_db_path):
    """Test that initialization creates the required tables."""
    db = Database(tmp_db_path)
    await db.initialize()

    assert db.is_connected

    async with db._conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ) as cursor:
        tables = [row[0] for row in await cursor.fetchall()]
        assert "flows" in tables
        assert "events" in tables

    await db.close()


async def test_health_check(db):
    """Test health check returns True on initialized DB."""
    assert await db.health_check() is True


async def test_health_check_uninitialized():
    """Test health check returns False when not initialized."""
    from pathlib import Path
    db = Database(Path("/tmp/nonexistent_test.db"))
    assert await db.health_check() is False


def _make_flow() -> ObservedFlow:
    """Helper to create a test ObservedFlow."""
    key = FlowKey(
        src_ip="192.168.1.1",
        dst_ip="10.0.0.1",
        src_port=12345,
        dst_port=80,
        protocol=6,
    )
    return ObservedFlow(
        flow_key=key,
        direction="forward",
        start_time=1000.0,
        end_time=1001.0,
        duration_sec=1.0,
        packet_count=10,
        byte_count=1500,
        payload_byte_count=1000,
    )


def _make_event(flow: ObservedFlow | None = None) -> DetectionEvent:
    """Helper to create a test DetectionEvent."""
    if flow is None:
        flow = _make_flow()
    return DetectionEvent(
        id=str(uuid.uuid4()),
        timestamp=time.time(),
        flow_key=flow.flow_key,
        observed_flow=flow,
        severity="high",
        rationale="Test detection event",
        metadata={"test_key": "test_value"},
    )


async def test_store_flow(db):
    """Test storing an ObservedFlow."""
    flow = _make_flow()
    flow_id = await db.store_flow(flow)

    assert flow_id is not None
    assert len(flow_id) == 36  # UUID format


async def test_store_and_get_event(db):
    """Test storing and retrieving a DetectionEvent."""
    event = _make_event()
    event_id = await db.store_event(event)

    assert event_id == event.id

    events = await db.get_events()
    assert len(events) == 1
    assert events[0]["id"] == event.id
    assert events[0]["severity"] == "high"
    assert events[0]["rationale"] == "Test detection event"


async def test_event_count(db):
    """Test counting events."""
    for _ in range(3):
        await db.store_event(_make_event())

    count = await db.get_event_count()
    assert count == 3


async def test_get_events_with_since_filter(db):
    """Test filtering events by timestamp."""
    early = _make_event()
    early.timestamp = 1000.0
    await db.store_event(early)

    late = _make_event()
    late.timestamp = 2000.0
    await db.store_event(late)

    events = await db.get_events(since=1500.0)
    assert len(events) == 1
    assert events[0]["timestamp"] == 2000.0
