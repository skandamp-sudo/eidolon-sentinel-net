"""
Configuration management for SENTINEL-NET.

All settings are loaded from environment variables with SENTINEL_ prefix
or from a .env file. Secrets (api_key) are never logged.
"""

from __future__ import annotations

import logging
from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from sentinel_net.intelligence.config import IntelligenceConfig
from sentinel_net.dns.config import DNSConfig


class SentinelConfig(BaseSettings):
    """Application configuration settings."""

    # ── General ──
    env: str = "development"
    log_level: str = "INFO"

    # ── Database ──
    database_path: Path = Path("data/sentinel_net.db")

    # ── API ──
    api_host: str = "127.0.0.1"
    api_port: int = 8000
    api_key: str = "changeme-dev"
    cors_origins: str = ""  # Comma-separated origins; empty = dev mode (*)

    # ── PCAP ──
    pcap_dir: Path = Path("data/pcaps")

    # ── Live Capture ──
    capture_interface: str = ""  # Empty = no live capture
    sensor_model: str | None = None  # Approved model-name/version identity
    model_registry: Path = Path("models/registry")
    capture_filter: str = ""  # BPF filter string
    snap_length: int = 65535
    promiscuous_mode: bool = False
    capture_buffer_size: int = 2 * 1024 * 1024  # 2 MB

    # ── Sensor Pipeline ──
    capture_queue_size: int = 10_000
    detection_queue_size: int = 5_000
    event_queue_size: int = 1_000
    flow_idle_timeout_sec: float = 120.0
    max_active_flows: int = 100_000

    max_subscribers: int = Field(default=32, gt=0)
    ws_send_timeout_sec: float = Field(default=5.0, gt=0, allow_inf_nan=False)

    intelligence: IntelligenceConfig = Field(default_factory=IntelligenceConfig)
    dns: DNSConfig = Field(default_factory=DNSConfig)

    # ── Retention ──
    max_events: int = Field(default=100_000, ge=0)
    retention_hours: float = Field(default=168.0, gt=0, allow_inf_nan=False)  # 7 days
    cleanup_interval_sec: float = Field(default=300.0, gt=0, allow_inf_nan=False)  # 5 minutes

    cleanup_batch_rows: int = Field(default=500, gt=0, le=10000)
    cleanup_cycle_rows: int = Field(default=5000, gt=0, le=100000)

    # ── WebSocket ──
    ws_queue_size: int = 100
    ws_auth_timeout_sec: float = 10.0
    ws_heartbeat_interval_sec: float = 30.0
    ws_query_param_auth: bool = False  # Disabled by default for security

    model_config = SettingsConfigDict(
        env_prefix="SENTINEL_",
        env_nested_delimiter="__",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    @property
    def cors_origin_list(self) -> list[str]:
        """Parse comma-separated CORS origins."""
        if not self.cors_origins:
            return ["*"] if self.env == "development" else []
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


@lru_cache()
def get_config() -> SentinelConfig:
    """Retrieve the singleton configuration instance."""
    return SentinelConfig()


def setup_logging(level: str) -> None:
    """Configure standard library logging.

    Args:
        level: Logging level as a string (e.g., 'INFO', 'DEBUG').
    """
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        level=numeric_level,
        format="%(asctime)s | %(levelname)8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
