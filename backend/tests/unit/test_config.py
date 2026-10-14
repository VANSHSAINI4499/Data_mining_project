from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from app.core.config import REPO_ROOT, Environment, Settings

pytestmark = pytest.mark.unit

STRONG_KEY = "k" * 48
GOOD_URL = "postgresql+psycopg://cti:s3cure-Password@db:5432/cti"


def test_production_rejects_placeholder_secret_key() -> None:
    with pytest.raises(ValidationError, match="CTI_SECRET_KEY"):
        Settings(env=Environment.PRODUCTION, secret_key="change-me", database_url=GOOD_URL)


def test_production_rejects_short_secret_key() -> None:
    with pytest.raises(ValidationError, match="at least 32 bytes"):
        Settings(
            env=Environment.PRODUCTION,
            secret_key="short-but-not-placeholder",
            database_url=GOOD_URL,
        )


def test_production_rejects_placeholder_database_password() -> None:
    with pytest.raises(ValidationError, match="placeholder password"):
        Settings(
            env=Environment.PRODUCTION,
            secret_key=STRONG_KEY,
            database_url="postgresql+psycopg://cti:change-me@db:5432/cti",
        )


def test_production_rejects_wildcard_cors() -> None:
    with pytest.raises(ValidationError, match="CORS"):
        Settings(
            env=Environment.PRODUCTION,
            secret_key=STRONG_KEY,
            database_url=GOOD_URL,
            cors_origins="*",
        )


def test_production_accepts_strong_configuration() -> None:
    settings = Settings(env=Environment.PRODUCTION, secret_key=STRONG_KEY, database_url=GOOD_URL)
    assert settings.is_production


def test_development_allows_placeholders() -> None:
    assert Settings(env=Environment.DEVELOPMENT, secret_key="change-me").secret_key


def test_cors_origins_are_split_from_comma_separated_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CTI_CORS_ORIGINS", "http://a.test, http://b.test")
    assert Settings().cors_origins == ["http://a.test", "http://b.test"]


def test_relative_directories_resolve_against_repo_root() -> None:
    settings = Settings(upload_dir=Path("x/uploads"))
    assert settings.upload_dir == (REPO_ROOT / "x/uploads").resolve()


def test_invalid_log_level_rejected() -> None:
    with pytest.raises(ValidationError):
        Settings(log_level="LOUD")


def test_secrets_are_not_shown_in_repr() -> None:
    settings = Settings(secret_key=STRONG_KEY, database_url=GOOD_URL)
    assert STRONG_KEY not in repr(settings)
    assert "s3cure-Password" not in repr(settings)
