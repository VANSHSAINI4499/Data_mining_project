"""The destructive test fixtures must refuse non-test databases."""

from __future__ import annotations

import pytest

from tests.conftest import UnsafeTestDatabaseError, assert_safe_test_database

pytestmark = pytest.mark.unit

URL = "postgresql+psycopg://cti:pw@localhost:5432/{}"


def test_accepts_dedicated_test_database() -> None:
    assert_safe_test_database(URL.format("cti_test"), URL.format("cti"))


@pytest.mark.parametrize("name", ["cti", "production", "warehouse"])
def test_rejects_database_without_test_in_name(name: str) -> None:
    with pytest.raises(UnsafeTestDatabaseError, match="must contain 'test'"):
        assert_safe_test_database(URL.format(name), None)


def test_rejects_test_url_equal_to_app_url() -> None:
    with pytest.raises(UnsafeTestDatabaseError, match="same database"):
        assert_safe_test_database(URL.format("cti_test"), URL.format("cti_test"))
