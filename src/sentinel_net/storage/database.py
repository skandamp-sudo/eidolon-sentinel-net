"""SQLite database manager for EIDOLON // SENTINEL-NET.

Provides async access to a SQLite database for storing flows and detection events.
Uses aiosqlite with WAL mode for concurrent read performance.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from pathlib import Path

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
        self._write_lock = asyncio.Lock()

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
                threat_type TEXT DEFAULT 'unknown',
                anomaly_score REAL,
                model_version TEXT,
                feature_schema_version TEXT,
                explanation_version TEXT,
                rationale TEXT DEFAULT '',
                metadata TEXT DEFAULT '{}',
                created_at REAL NOT NULL,
                FOREIGN KEY(flow_id) REFERENCES flows(id)
            )
        """)
        
        # Additive migration: retain legacy columns/indexes, persist the complete
        # public record for new events so REST and WS cannot diverge.
        async with self._conn.execute("PRAGMA table_info(events)") as cursor:
            columns = {row[1] for row in await cursor.fetchall()}
        if 'event_json' not in columns:
            await self._conn.execute("ALTER TABLE events ADD COLUMN event_json TEXT")

        async with self._conn.execute("PRAGMA table_info(flows)") as cursor:
            flow_columns = {row[1] for row in await cursor.fetchall()}
        if 'retention_eligible' not in flow_columns:
            await self._conn.execute("ALTER TABLE flows ADD COLUMN retention_eligible INTEGER NOT NULL DEFAULT 0")
        await self._conn.execute("CREATE INDEX IF NOT EXISTS idx_flows_retention ON flows(retention_eligible)")

        # Add indexes if not exists
        await self._conn.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)")
        await self._conn.execute("CREATE INDEX IF NOT EXISTS idx_events_threat_type ON events(threat_type)")
        await self._conn.execute("CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity)")
        await self._conn.execute("CREATE INDEX IF NOT EXISTS idx_events_flow_id ON events(flow_id)")
        await self._conn.execute("CREATE INDEX IF NOT EXISTS idx_flows_start_time ON flows(start_time)")
        
        await self._conn.commit()
        logger.info("Database tables ready.")

    async def close(self) -> None:
        """Close the database connection."""
        if self._conn:
            await self._conn.close()
            self._conn = None
            logger.info("Database connection closed.")

    async def store_flow(self, flow: ObservedFlow) -> str:
        async with self._write_lock:
            try:
                flow_id = await self._insert_flow(flow)
                await self._conn.commit()
                return flow_id
            except BaseException:
                if self._conn:
                    await self._conn.rollback()
                raise

    async def _insert_flow(self, flow: ObservedFlow) -> str:
        """Serialize and insert an ObservedFlow.

        Args:
            flow: The ObservedFlow to store.

        Returns:
            The generated UUID for the stored flow.
        """
        if not self._conn:
            raise RuntimeError("Database not initialized")

        flow_id = flow.id
        created_at = time.time()

        await self._conn.execute("""
            INSERT OR IGNORE INTO flows (
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
        return flow_id

    async def store_event(self, event: DetectionEvent, explanation_data: dict | None = None) -> str:
        """Atomically persist flow and public event record before publication."""
        if not self._conn:
            raise RuntimeError("Database not initialized")
        if explanation_data:
            event.metadata.update(explanation_data)
        record = event.to_dict()
        encoded = json.dumps(record, allow_nan=False)
        async with self._write_lock:
            try:
                if event.observed_flow:
                    await self._insert_flow(event.observed_flow)
                    await self._conn.execute("UPDATE flows SET retention_eligible=1 WHERE id=?", (event.observed_flow.id,))
                await self._conn.execute("""
                    INSERT INTO events (
                        id, timestamp, flow_id, severity, threat_type, anomaly_score,
                        model_version, feature_schema_version, explanation_version,
                        rationale, metadata, created_at, event_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    record['id'], record['timestamp'], record['flow_id'], record['severity'],
                    record['threat_type'], record['anomaly_score'], record['model_version'],
                    record['feature_schema_version'], record['explanation_version'],
                    record['rationale'], json.dumps(record['metadata'], allow_nan=False),
                    record['created_at'], encoded,
                ))
                await self._conn.commit()
            except BaseException:
                await self._conn.rollback()
                raise
        return event.id

    @staticmethod
    def _event_record(row: dict) -> dict:
        from sentinel_net.models.event_record import EventRecord, metadata_evidence
        encoded = row.pop('event_json', None)
        if encoded:
            return EventRecord.model_validate_json(encoded).model_dump(mode='json')
        # Historical rows have no saved confidence/evidence. Preserve missingness.
        if isinstance(row.get('metadata'), str):
            try:
                row['metadata'] = json.loads(row['metadata'])
            except json.JSONDecodeError:
                row['metadata'] = {}
        row['evidence'] = metadata_evidence(row.get('metadata') or {})
        return EventRecord.model_validate(row).model_dump(mode='json')

    async def get_event_by_id(self, event_id: str) -> dict | None:
        """Retrieve a single event by ID."""
        if not self._conn:
            raise RuntimeError("Database not initialized")
            
        async with self._conn.execute("SELECT e.*, f.src_ip, f.dst_ip, f.src_port, f.dst_port, f.protocol FROM events e LEFT JOIN flows f ON e.flow_id = f.id WHERE e.id = ?", (event_id,)) as cursor:
            row = await cursor.fetchone()
            if not row:
                return None
            columns = [col[0] for col in cursor.description]
            return self._event_record(dict(zip(columns, row)))

    async def get_flow_by_id(self, flow_id: str) -> dict | None:
        """Retrieve a single flow by ID."""
        if not self._conn:
            raise RuntimeError("Database not initialized")
            
        async with self._conn.execute("SELECT * FROM flows WHERE id = ?", (flow_id,)) as cursor:
            row = await cursor.fetchone()
            if not row:
                return None
            columns = [col[0] for col in cursor.description]
            return dict(zip(columns, row))

    async def get_flows(self, limit: int = 50, offset: int = 0, since: float | None = None) -> list[dict]:
        """Query flows with optional filtering."""
        if not self._conn:
            raise RuntimeError("Database not initialized")
            
        query = "SELECT * FROM flows"
        params: list = []
        
        if since is not None:
            query += " WHERE start_time >= ?"
            params.append(since)
            
        query += " ORDER BY start_time DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        
        async with self._conn.execute(query, tuple(params)) as cursor:
            columns = [col[0] for col in cursor.description]
            rows = await cursor.fetchall()
            return [dict(zip(columns, row)) for row in rows]

    async def get_flow_count(self, since: float | None = None) -> int:
        """Count filtered flows in the database."""
        if not self._conn:
            raise RuntimeError("Database not initialized")

        query = "SELECT COUNT(*) FROM flows WHERE 1=1"
        params: list = []
        
        if since is not None:
            query += " AND start_time >= ?"
            params.append(since)

        async with self._conn.execute(query, tuple(params)) as cursor:
            row = await cursor.fetchone()
            return row[0] if row else 0

    async def get_events(
        self, 
        limit: int = 50, 
        offset: int = 0, 
        since: float | None = None,
        threat_type: str | None = None,
        severity: str | None = None,
        flow_id: str | None = None
    ) -> list[dict]:
        """Query events with extended filtering.

        Args:
            limit: Maximum number of events to return.
            offset: Number of events to skip.
            since: Optional epoch timestamp to filter events from.
            threat_type: Optional threat type filter.
            severity: Optional severity filter.
            flow_id: Optional flow ID filter.

        Returns:
            List of event dictionaries.
        """
        if not self._conn:
            raise RuntimeError("Database not initialized")

        query = """
            SELECT e.*, 
                   f.src_ip, f.dst_ip, f.src_port, f.dst_port, f.protocol
            FROM events e
            LEFT JOIN flows f ON e.flow_id = f.id
            WHERE 1=1
        """
        params: list = []

        if since is not None:
            query += " AND e.timestamp >= ?"
            params.append(since)
            
        if threat_type is not None:
            query += " AND e.threat_type = ?"
            params.append(threat_type)
            
        if severity is not None:
            query += " AND e.severity = ?"
            params.append(severity)
            
        if flow_id is not None:
            query += " AND e.flow_id = ?"
            params.append(flow_id)

        query += " ORDER BY e.timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        async with self._conn.execute(query, tuple(params)) as cursor:
            columns = [col[0] for col in cursor.description]
            rows = await cursor.fetchall()
            return [self._event_record(dict(zip(columns, row))) for row in rows]

    async def get_event_count(self, threat_type: str | None = None, severity: str | None = None, since: float | None = None, flow_id: str | None = None) -> int:
        """Count filtered events in the database."""
        if not self._conn:
            raise RuntimeError("Database not initialized")

        query = "SELECT COUNT(*) FROM events WHERE 1=1"
        params: list = []
        
        if since is not None:
            query += " AND timestamp >= ?"
            params.append(since)
            
        if threat_type is not None:
            query += " AND threat_type = ?"
            params.append(threat_type)
            
        if severity is not None:
            query += " AND severity = ?"
            params.append(severity)
            
        if flow_id is not None:
            query += " AND flow_id = ?"
            params.append(flow_id)

        async with self._conn.execute(query, tuple(params)) as cursor:
            row = await cursor.fetchone()
            return row[0] if row else 0
            
    async def get_stats(self) -> dict:
        """Aggregate stats (count by threat_type, count by severity)."""
        if not self._conn:
            raise RuntimeError("Database not initialized")
            
        stats = {
            "threat_types": {},
            "severities": {},
            "total_events": 0
        }
        
        async with self._conn.execute("SELECT threat_type, COUNT(*) FROM events GROUP BY threat_type") as cursor:
            rows = await cursor.fetchall()
            for row in rows:
                stats["threat_types"][row[0]] = row[1]
                stats["total_events"] += row[1]
                
        async with self._conn.execute("SELECT severity, COUNT(*) FROM events GROUP BY severity") as cursor:
            rows = await cursor.fetchall()
            for row in rows:
                stats["severities"][row[0]] = row[1]
                
        return stats
        
    async def cleanup_old_events(self, max_count: int | None, max_age_sec: float | None) -> int:
        async with self._write_lock:
            try:
                return await self._cleanup_old_events(max_count, max_age_sec)
            except BaseException:
                if self._conn:
                    await self._conn.rollback()
                raise

    async def _cleanup_old_events(self, max_count: int | None, max_age_sec: float | None) -> int:
        """Retention cleanup, returns deleted count."""
        if not self._conn:
            raise RuntimeError("Database not initialized")
            
        deleted_count = 0
        now = time.time()
        
        if max_age_sec is not None:
            threshold = now - max_age_sec
            async with self._conn.execute("DELETE FROM events WHERE timestamp < ?", (threshold,)) as cursor:
                deleted_count += cursor.rowcount
                
        if max_count is not None:
            async with self._conn.execute("SELECT COUNT(*) FROM events") as cursor:
                row = await cursor.fetchone()
                total = row[0] if row else 0
                
            if total > max_count:
                to_delete = total - max_count
                async with self._conn.execute(
                    "DELETE FROM events WHERE id IN (SELECT id FROM events ORDER BY timestamp ASC LIMIT ?)", 
                    (to_delete,)
                ) as cursor:
                    deleted_count += cursor.rowcount
                    
        await self._conn.commit()
        return deleted_count

    def storage_sizes(self) -> dict:
        """Allocated file sizes; DELETE does not imply filesystem shrink."""
        result = {}
        for key, path in [('database_bytes', self.db_path), ('wal_bytes', Path(str(self.db_path) + '-wal'))]:
            try:
                result[key] = path.stat().st_size
            except FileNotFoundError:
                result[key] = 0
            except OSError:
                result[key] = None
        return result

    async def cleanup_batch(self, *, max_count: int, cutoff: float, row_limit: int) -> dict:
        """Bound deleted rows across both tables in one transaction.

        Only flows proven complete by a committed event are eligible. Standalone
        store_flow records and active in-memory flows are never garbage-collected.
        The writer lock serializes eligibility, references, and cleanup.
        """
        if row_limit <= 0 or max_count < 0:
            raise ValueError('Invalid retention bounds')
        async with self._write_lock:
            if not self._conn:
                raise RuntimeError('Database not initialized')
            try:
                # Acquire the SQLite writer reservation before reads, including
                # against other connections/processes. Busy timeout stays finite.
                await self._conn.execute('BEGIN IMMEDIATE')
                async with self._conn.execute('SELECT COUNT(*) FROM events') as cur:
                    excess = max(0, (await cur.fetchone())[0] - max_count)
                async with self._conn.execute(
                    'SELECT id, flow_id, timestamp FROM events ORDER BY timestamp, id LIMIT ?',
                    (max(1, row_limit // 2),)) as cur:
                    rows = await cur.fetchall()
                victims = [(eid, fid) for i, (eid, fid, ts) in enumerate(rows) if i < excess or ts < cutoff]
                for eid, fid in victims:
                    # Also safely migrate eligibility for historical referenced flows.
                    await self._conn.execute('UPDATE flows SET retention_eligible=1 WHERE id=?', (fid,))
                    await self._conn.execute('DELETE FROM events WHERE id=?', (eid,))
                remaining = row_limit - len(victims)
                async with self._conn.execute(
                    'DELETE FROM flows WHERE id IN (SELECT f.id FROM flows f WHERE retention_eligible=1 '
                    'AND NOT EXISTS (SELECT 1 FROM events e WHERE e.flow_id=f.id) LIMIT ?)',
                    (remaining,)) as cur:
                    flows = cur.rowcount
                await self._conn.commit()
                return {'events': len(victims), 'flows': flows}
            except BaseException:
                await self._conn.rollback()
                raise

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
