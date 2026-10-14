"""Application settings, read from ``CTI_*`` environment variables.

Every variable is documented in ``.env.example`` and DEPLOYMENT_GUIDE.md §3.
"""

from __future__ import annotations

from enum import StrEnum
from functools import lru_cache
from pathlib import Path
from typing import Annotated

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

# backend/app/core/config.py -> repository root
REPO_ROOT = Path(__file__).resolve().parents[3]

PLACEHOLDER_SECRETS = frozenset({"", "change-me", "changeme", "secret", "password"})


class Environment(StrEnum):
    DEVELOPMENT = "development"
    TEST = "test"
    PRODUCTION = "production"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="CTI_",
        env_file=(REPO_ROOT / ".env",),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    env: Environment = Environment.DEVELOPMENT
    log_level: str = "INFO"
    database_url: SecretStr = SecretStr("postgresql+psycopg://cti:change-me@localhost:5432/cti")
    secret_key: SecretStr = SecretStr("change-me")
    session_ttl_minutes: int = Field(default=480, ge=5, le=7 * 24 * 60)
    session_idle_minutes: int = Field(default=60, ge=1, le=24 * 60)
    cors_origins: Annotated[list[str], NoDecode] = ["http://localhost:5173"]
    upload_dir: Path = Path(".local/uploads")
    artifact_dir: Path = Path(".local/artifacts")
    max_upload_mb: int = Field(default=50, ge=1, le=1024)
    import_root: Path = Path("data")
    max_reject_ratio: float = Field(default=0.2, gt=0, le=1)
    ingest_chunk_size: int = Field(default=5000, ge=1, le=100_000)
    max_query_days: int = Field(default=400, ge=1)
    max_agg_days: int = Field(default=400, ge=1)
    max_concurrent_jobs: int = Field(default=2, ge=1, le=16)
    job_heartbeat_seconds: int = Field(default=15, ge=1)
    job_timeout_seconds: int = Field(default=600, ge=10)
    worker_poll_seconds: float = Field(default=2.0, gt=0)

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _split_origins(cls, value: object) -> object:
        if isinstance(value, str):
            return [origin.strip() for origin in value.split(",") if origin.strip()]
        return value

    @field_validator("upload_dir", "artifact_dir", "import_root")
    @classmethod
    def _resolve_dir(cls, value: Path) -> Path:
        # Relative paths are resolved against the repository root so that the API, worker,
        # CLI, and tests agree regardless of the current working directory.
        return value if value.is_absolute() else (REPO_ROOT / value).resolve()

    @field_validator("log_level")
    @classmethod
    def _upper_level(cls, value: str) -> str:
        level = value.upper()
        if level not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ValueError(f"invalid log level {value!r}")
        return level

    @model_validator(mode="after")
    def _production_requirements(self) -> Settings:
        if self.env is not Environment.PRODUCTION:
            return self
        problems: list[str] = []
        secret = self.secret_key.get_secret_value()
        if secret.lower() in PLACEHOLDER_SECRETS or len(secret.encode()) < 32:
            problems.append("CTI_SECRET_KEY must be a non-placeholder value of at least 32 bytes")
        if any(f":{p}@" in self.database_url.get_secret_value() for p in PLACEHOLDER_SECRETS):
            problems.append("CTI_DATABASE_URL contains a placeholder password")
        if "*" in self.cors_origins:
            problems.append("CTI_CORS_ORIGINS must not contain '*'")
        if problems:
            raise ValueError("; ".join(problems))
        return self

    @property
    def is_production(self) -> bool:
        return self.env is Environment.PRODUCTION


@lru_cache
def get_settings() -> Settings:
    return Settings()
