"""SQLite database manager for EIDOLON // SENTINEL-NET.

Provides async access to a SQLite database for storing flows and detection events.
Uses aiosqlite with WAL mode for concurrent read performance.
"""

import json
import logging
import time
from pathlib import Path
from uuid import uuid4

import aiosqlite

from sentinel_net.models.types import DetectionEvent, ObservedFlow

logger = logging.getLogger(__name__)


class Database:
    """SQLite database manager handling asynchronous connections and queries."""

    def __init__(self, db_path: Path) -> None:
        """Initialize the database manager.

        Args:
            db_path: Path to the SQLite database file.
        """
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: aiosqlite.Connection | None = None

    @property
    def is_connected(self) -> bool:
        """Check if the database connection is active."""
        return self._conn is not None

    async def initialize(self) -> None:
        """Create connection, enable WAL mode, and create tables if they don't exist."""
        logger.info(f"Initializing SQLite database at {self.db_path}")
        self._conn = await aiosqlite.connect(self.db_path)
        await self._conn.execute("PRAGMA journal_mode=WAL")
        await self._conn.execute("PRAGMA synchronous=NORMAL")

        await self._conn.execute("""
            CREATE TABLE IF NOT EXISTS flows (
                id TEXT PRIMARY KEY,
                flow_key TEXT NOT NULL,
                src_ip TEXT NOT NULL,
                dst_ip TEXT NOT NULL,
                src_port INTEGER,
                dst_port INTEGER,
                protocol INTEGER NOT NULL,
                direction TEXT NOT NULL,
                start_time REAL NOT NULL,
                end_time REAL NOT NULL,
                duration_sec REAL NOT NULL,
                packet_count INTEGER NOT NULL,
                byte_count INTEGER NOT NULL,
                payload_byte_count INTEGER NOT NULL,
                created_at REAL NOT NULL
            )
        """)

        await self._conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY,
                timestamp REAL NOT NULL,
                flow_id TEXT,
                severity TEXT NOT NULL DEFAULT 'info',
                rationale TEXT DEFAULT '',
                metadata TEXT DEFAULT '{}',
                created_at REAL NOT NULL,
                FOREIGN KEY(flow_id) REFERENCES flows(id)
            )
        """)
        await self._conn.commit()
        logger.info("Database tables ready.")

    async def close(self) -> None:
        """Close the database connection."""
        if self._conn:
            await self._conn.close()
            self._conn = None
            logger.info("Database connection closed.")

    async def store_flow(self, flow: ObservedFlow) -> str:
        """Serialize and insert an ObservedFlow.

        Args:
            flow: The ObservedFlow to store.

        Returns:
            The generated UUID for the stored flow.
        """
        if not self._conn:
            raise RuntimeError("Database not initialized")

        flow_id = str(uuid4())
        created_at = time.time()

        await self._conn.execute("""
            INSERT INTO flows (
                id, flow_key, src_ip, dst_ip, src_port, dst_port, protocol,
                direction, start_time, end_time, duration_sec, packet_count,
                byte_count, payload_byte_count, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            flow_id,
            flow.flow_key.unidirectional_key,
            flow.flow_key.src_ip,
            flow.flow_key.dst_ip,
            flow.flow_key.src_port,
            flow.flow_key.dst_port,
            flow.flow_key.protocol,
            flow.direction,
            flow.start_time,
            flow.end_time,
            flow.duration_sec,
            flow.packet_count,
            flow.byte_count,
            flow.payload_byte_count,
            created_at,
        ))
        await self._conn.commit()
        return flow_id

    async def store_event(self, event: DetectionEvent) -> str:
        """Serialize and insert a DetectionEvent.

        Args:
            event: The DetectionEvent to store.

        Returns:
            The event ID.
        """
        if not self._conn:
            raise RuntimeError("Database not initialized")

        created_at = time.time()
        meta_json = json.dumps(event.metadata) if event.metadata else "{}"

        # Store the flow first if present, get flow_id
        flow_id: str | None = None
        if event.observed_flow:
            flow_id = await self.store_flow(event.observed_flow)

        await self._conn.execute("""
            INSERT INTO events (
                id, timestamp, flow_id, severity, rationale, metadata, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            event.id,
            event.timestamp,
            flow_id,
            event.severity,
            event.rationale,
            meta_json,
            created_at,
        ))
        await self._conn.commit()
        return event.id

    async def get_events(
        self, limit: int = 50, offset: int = 0, since: float | None = None
    ) -> list[dict]:
        """Query events with optional filtering.

        Args:
            limit: Maximum number of events to return.
            offset: Number of events to skip.
            since: Optional epoch timestamp to filter events from.

        Returns:
            List of event dictionaries.
        """
        if not self._conn:
            raise RuntimeError("Database not initialized")

        query = "SELECT * FROM events"
        params: list = []

        if since is not None:
            query += " WHERE timestamp >= ?"
            params.append(since)

        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        async with self._conn.execute(query, tuple(params)) as cursor:
            columns = [col[0] for col in cursor.description]
            rows = await cursor.fetchall()
            return [dict(zip(columns, row)) for row in rows]

    async def get_event_count(self) -> int:
        """Count total events in the database."""
        if not self._conn:
            raise RuntimeError("Database not initialized")

        async with self._conn.execute("SELECT COUNT(*) FROM events") as cursor:
            row = await cursor.fetchone()
            return row[0] if row else 0

    async def health_check(self) -> bool:
        """Verify the database is accessible.

        Returns:
            True if a simple query succeeds, False otherwise.
        """
        if not self._conn:
            return False
        try:
            async with self._conn.execute("SELECT 1") as cursor:
                await cursor.fetchone()
                return True
        except Exception:
            return False
