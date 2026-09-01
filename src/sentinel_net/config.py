"""
Configuration management for SENTINEL-NET.
"""

import logging
from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class SentinelConfig(BaseSettings):
    """
    Application configuration settings.
    """
    env: str = 'development'
    database_path: Path = Path('data/sentinel_net.db')
    api_host: str = '127.0.0.1'
    api_port: int = 8000
    api_key: str = 'changeme-dev'
    log_level: str = 'INFO'
    pcap_dir: Path = Path('data/pcaps')

    model_config = SettingsConfigDict(
        env_prefix='SENTINEL_',
        env_file='.env',
        env_file_encoding='utf-8',
        extra='ignore'
    )


@lru_cache()
def get_config() -> SentinelConfig:
    """
    Retrieve the singleton configuration instance.
    """
    return SentinelConfig()


def setup_logging(level: str) -> None:
    """
    Configure standard library logging.
    
    Args:
        level: Logging level as a string (e.g., 'INFO', 'DEBUG').
    """
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        level=numeric_level,
        format="%(asctime)s | %(levelname)8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
