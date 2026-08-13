import os
from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict

# Base dir for resolving relative cert paths
_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

class Settings(BaseSettings):
    ENVIRONMENT: str = "development"

    # Database Config
    DATABASE_URL: str = "postgresql+asyncpg://postgres:root@localhost:5432/zerotrust_edr"

    # Redis Config
    REDIS_URL: str = "redis://localhost:6379/0"

    # JWT Auth Config (M1)
    JWT_SECRET_KEY_PATH: Optional[str] = None
    JWT_PUBLIC_KEY_PATH: Optional[str] = None
    JWT_ALGORITHM: str = "RS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    FORCE_DB_CHECK: bool = False

    # Rate Limiting (M1)
    LOGIN_RATE_LIMIT: str = "10/minute"

    # Certificate Authority (M3) — paths to the local dev CA
    CA_CERT_PATH: str = os.path.join(_BASE_DIR, "certificates", "ca.crt")
    CA_KEY_PATH: str = os.path.join(_BASE_DIR, "certificates", "ca.key")
    AGENT_CERT_VALID_DAYS: int = 365

    # Heartbeat (M4)
    HEARTBEAT_INTERVAL_SECONDS: int = 30
    OFFLINE_THRESHOLD_SECONDS: int = 90
    MONITOR_CHECK_INTERVAL_SECONDS: int = 15

    # Risk Decay Config (M7)
    DECAY_GRACE_HOURS: int = 24
    DECAY_AMOUNT: int = 5
    DECAY_INTERVAL_MINUTES: int = 60

    # Threat Intel Sync (M9)
    THREAT_INTEL_SYNC_INTERVAL_HOURS: int = 6

    model_config = SettingsConfigDict(
        env_file=os.path.join(_BASE_DIR, ".env"),
        env_file_encoding="utf-8",
        extra="ignore"
    )

settings = Settings()
