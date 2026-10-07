"""Application configuration loaded from environment variables."""

from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """CyberSec MCP server settings — loaded from .env or environment."""

    # Logging
    log_level: str = "INFO"

    # Audit
    audit_db_path: str = "audit.db"

    # Docker
    docker_socket: str = "unix:///var/run/docker.sock"

    # Sandbox
    max_concurrent_sandboxes: int = 3
    default_timeout: int = 120

    # Policy
    policy_config_path: str = "config/policies.yaml"

    # Allowed targets
    allowed_networks: str = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8"
    allowed_domains: str = "*.lab.local,*.test,localhost"

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8", "extra": "ignore"}

    @property
    def network_list(self) -> list[str]:
        return [n.strip() for n in self.allowed_networks.split(",") if n.strip()]

    @property
    def domain_list(self) -> list[str]:
        return [d.strip() for d in self.allowed_domains.split(",") if d.strip()]

    @property
    def policy_path(self) -> Path:
        return Path(self.policy_config_path)


# Singleton
settings = Settings()


def get_settings() -> Settings:
    """Return the global Settings singleton."""
    return settings
