"""FastAPI application factory for EIDOLON // SENTINEL-NET."""

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from sentinel_net.config import get_config, setup_logging
from sentinel_net.storage.database import Database
from sentinel_net.api.routes import health


logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage the lifecycle of the FastAPI application."""
    config = get_config()
    setup_logging(config.log_level)
    
    db = Database(config.database_path)
    await db.initialize()
    app.state.db = db
    
    logger.info("Database initialized.")
    yield
    
    logger.info("Closing database connection.")
    await db.close()


def create_app() -> FastAPI:
    """Create and configure the FastAPI application.
    
    Returns:
        The configured FastAPI instance.
    """
    app = FastAPI(
        title="EIDOLON // SENTINEL-NET API",
        version="0.1.0",
        lifespan=lifespan
    )
    
    # Add CORS middleware for dev
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Include routers
    app.include_router(health.router)
    
    return app


app = create_app()
