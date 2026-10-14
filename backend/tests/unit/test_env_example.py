"""AC-1.5: every setting is configurable via a documented CTI_* variable in .env.example."""

from __future__ import annotations

import re

import pytest

from app.core.config import REPO_ROOT, Settings

pytestmark = pytest.mark.unit


def _example_keys() -> set[str]:
    text = (REPO_ROOT / ".env.example").read_text(encoding="utf-8")
    return set(re.findall(r"^([A-Z][A-Z0-9_]*)=", text, flags=re.M))


def test_every_setting_is_documented_in_env_example() -> None:
    expected = {f"CTI_{name.upper()}" for name in Settings.model_fields}
    assert expected - _example_keys() == set()


def test_env_example_contains_only_placeholder_secrets() -> None:
    text = (REPO_ROOT / ".env.example").read_text(encoding="utf-8")
    for key in ("POSTGRES_PASSWORD", "CTI_SECRET_KEY"):
        assert re.search(rf"^{key}=change-me$", text, flags=re.M), key
