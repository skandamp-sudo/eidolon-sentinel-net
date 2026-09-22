"""Lifecycle-owned bounded retention, independent of scientific inference."""

import asyncio
import logging
import time

logger = logging.getLogger(__name__)


class RetentionWorker:
    def __init__(self, db, config, metrics):
        self.db, self.config, self.metrics = db, config, metrics
        self.task = None

    def start(self):
        if self.task is not None:
            raise RuntimeError("Retention worker already started")
        self.task = asyncio.create_task(self._run(), name="sqlite-retention")

    async def stop(self):
        if self.task:
            self.task.cancel()
            await asyncio.gather(self.task, return_exceptions=True)

    async def cycle(self):
        started = time.monotonic()
        cutoff = time.time() - self.config.retention_hours * 3600
        remaining = self.config.cleanup_cycle_rows
        try:
            while remaining:
                limit = min(remaining, self.config.cleanup_batch_rows)
                removed = await self.db.cleanup_batch(
                    max_count=self.config.max_events, cutoff=cutoff, row_limit=limit
                )
                for kind, count in removed.items():
                    self.metrics.increment(f"retention_{kind}_removed", count)
                total = sum(removed.values())
                remaining -= total
                await asyncio.sleep(0)  # let persistence and API requests run
                if total == 0:
                    break
            self.metrics.increment("retention_cycles")
            self.metrics.set_gauge("retention_last_success", time.time())
        except asyncio.CancelledError:
            raise
        except Exception:
            self.metrics.increment("retention_failures")
            self.metrics.set_gauge("last_error_kind", "RETENTION_ERROR")
            logger.exception("SQLite retention failed; next attempt at configured interval")
        finally:
            self.metrics.set_gauge("retention_duration_sec", time.monotonic() - started)
            for name, value in self.db.storage_sizes().items():
                self.metrics.set_gauge(name, value)

    async def _run(self):
        while True:
            await self.cycle()
            await asyncio.sleep(self.config.cleanup_interval_sec)
