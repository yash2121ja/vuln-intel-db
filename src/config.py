"""Configuration for VulnIntel DB service."""

from functools import lru_cache
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    APP_NAME: str = "VulnIntel DB"
    APP_VERSION: str = "1.0.0"

    DATABASE_URL: str = "postgresql+asyncpg://vulndb:vulndb_pass@localhost:5434/vuln_intel"
    REDIS_URL: str = "redis://localhost:6381/0"
    CELERY_BROKER_URL: str = "redis://localhost:6381/1"

    # API keys for higher rate limits
    NVD_API_KEY: str = ""
    GITHUB_TOKEN: str = ""

    # Sync intervals (minutes)
    SYNC_INTERVAL_NVD: int = 360          # 6 hours
    SYNC_INTERVAL_DEBIAN: int = 180       # 3 hours
    SYNC_INTERVAL_ALPINE: int = 180       # 3 hours
    SYNC_INTERVAL_REDHAT: int = 360       # 6 hours
    SYNC_INTERVAL_UBUNTU: int = 360       # 6 hours
    SYNC_INTERVAL_GHSA: int = 120         # 2 hours
    SYNC_INTERVAL_OSV: int = 360          # 6 hours
    SYNC_INTERVAL_EPSS: int = 1440        # 24 hours
    SYNC_INTERVAL_KEV: int = 360          # 6 hours
    SYNC_INTERVAL_EXPLOITDB: int = 1440   # 24 hours

    # Cache TTL
    QUERY_CACHE_TTL: int = 300  # 5 min

    class Config:
        env_file = ".env"
        case_sensitive = True


@lru_cache()
def get_settings() -> Settings:
    return Settings()
