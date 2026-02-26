"""Application configuration via pydantic-settings."""

from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Neo4j
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "sentinel_dev"

    # AWS
    aws_default_region: str = "us-east-1"
    aws_regions: str = "us-east-1"
    aws_assume_role_arn: str = ""

    # API
    api_port: int = 8000
    enable_raw_cypher: bool = False

    # Phase 2: Agent
    anthropic_api_key: str = ""
    agent_model: str = "claude-opus-4-6"
    agent_max_tokens: int = 4096
    agent_enable_thinking: bool = False
    agent_thinking_budget_tokens: int = 8000

    # Security
    api_key: str = ""  # If set, all requests must include X-API-Key header
    rate_limit_enabled: bool = False  # Set true in production; keep false for tests

    # Persistence
    sentinel_db_path: str = "./sentinel.db"

    # Phase 3: CloudTrail polling (opt-in)
    enable_cloudtrail_polling: bool = False
    aws_account_id: str = ""  # required when enable_cloudtrail_polling=True
    cloudtrail_poll_interval: int = 60  # seconds between polls

    @property
    def regions_list(self) -> list[str]:
        return [r.strip() for r in self.aws_regions.split(",") if r.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
