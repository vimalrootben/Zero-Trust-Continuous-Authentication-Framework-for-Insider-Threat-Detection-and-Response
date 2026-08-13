"""
AgentConfig — Single source of runtime configuration for the Windows EDR agent.

All values are loaded from environment variables or an agent_config.env file.
No URLs, cert paths, or intervals are hardcoded anywhere else in the agent.

Usage:
    from agent.config.config import agent_config
    print(agent_config.manager_url)
"""
import os
from typing import Optional
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class AgentConfig(BaseSettings):
    """Runtime configuration for the Zero Trust EDR agent."""

    # Manager connectivity
    manager_url: str = Field(
        "https://localhost:8443",
        description="Base HTTPS URL of the manager API (mTLS).",
    )
    manager_ws_url: str = Field(
        "wss://localhost:8443",
        description="WebSocket URL for real-time command channel.",
    )

    # TLS / mTLS certificate paths
    cert_path: str = Field(
        "agent_certs/agent.crt",
        description="Path to the agent's signed client certificate (PEM).",
    )
    key_path: str = Field(
        "agent_certs/agent.key",
        description="Path to the agent's private key (PEM). Never leaves this host.",
    )
    ca_cert_path: str = Field(
        "agent_certs/ca.crt",
        description="Path to the manager CA certificate for server verification.",
    )

    # Local SQLite persistence (offline queue, agent state)
    local_db_path: str = Field(
        "agent_data/agent_local.db",
        description="Path to the local SQLite database for offline telemetry queuing.",
    )

    # Timings (configurable without restart for safe hot-reload values)
    heartbeat_interval_seconds: int = Field(30, ge=5, le=300)
    telemetry_batch_interval_seconds: int = Field(15, ge=5, le=120)
    telemetry_batch_size: int = Field(50, ge=1, le=500)
    offline_queue_max_size: int = Field(100_000, ge=1000)
    offline_flush_batch_size: int = Field(100, ge=10, le=1000)

    # Logging
    log_level: str = Field("INFO", description="Python logging level.")
    # Self‑protection toggles (Phase 10) – enable the subsystem and individual guards
    enable_self_protection: bool = Field(True, description="Enable self‑protection subsystem")
    enable_service_guard: bool = Field(True, description="Enable service guard")
    enable_file_integrity_guard: bool = Field(True, description="Enable file integrity guard")
    enable_tamper_logger: bool = Field(True, description="Enable tamper logger")

    # Agent identity (written to local storage after successful registration)
    agent_id: Optional[str] = Field(
        None,
        description="Persisted agent UUID after first successful registration.",
    )

    model_config = SettingsConfigDict(
        env_file="agent_config.env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    def __init__(self, **values):
        yaml_values = self._load_yaml_config()
        # Explicit values override yaml, yaml overrides defaults
        combined = {**yaml_values, **values}
        super().__init__(**combined)

    @staticmethod
    def _load_yaml_config() -> dict:
        yaml_path = "config.yaml"
        if not os.path.exists(yaml_path):
            return {}
        try:
            import yaml
            with open(yaml_path, "r", encoding="utf-8") as f:
                content = yaml.safe_load(f)
                return content if isinstance(content, dict) else {}
        except Exception:
            return {}

    def reload(self) -> "AgentConfig":
        """
        Hot-reload configuration from file sources (agent_config.env / config.yaml).
        Returns a fresh instance — callers that cache config should
        replace their reference with the returned object.
        """
        return AgentConfig()


# Singleton — import this from the rest of the agent
agent_config = AgentConfig()
