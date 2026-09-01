"""Shared test fixtures for EIDOLON // SENTINEL-NET."""

from pathlib import Path

import pytest

from sentinel_net.storage.database import Database


@pytest.fixture
def tmp_db_path(tmp_path: Path) -> Path:
    """Fixture providing a temporary database path."""
    return tmp_path / "test.db"


@pytest.fixture
async def db(tmp_db_path: Path):
    """Fixture providing an initialized Database instance."""
    database = Database(tmp_db_path)
    await database.initialize()
    yield database
    await database.close()
