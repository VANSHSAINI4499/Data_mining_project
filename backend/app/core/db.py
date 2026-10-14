"""Database engine and session management.

Sessions are created without an open transaction; services define transaction
boundaries with ``with session.begin():`` (ARCHITECTURE.md §5, rule 4).
"""

from __future__ import annotations

from collections.abc import Iterator
from functools import lru_cache
from typing import Annotated

from fastapi import Depends
from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings

# Every session works in UTC regardless of the server's default timezone, so timestamps are
# read back in UTC (API_SPECIFICATION.md §1) and date arithmetic in SQL is UTC-based.
SESSION_OPTIONS = {"options": "-c timezone=UTC"}


def make_engine(url: str) -> Engine:
    return create_engine(
        url, pool_pre_ping=True, pool_size=5, max_overflow=5, connect_args=SESSION_OPTIONS
    )


@lru_cache
def get_engine() -> Engine:
    return make_engine(get_settings().database_url.get_secret_value())


@lru_cache
def get_session_factory() -> sessionmaker[Session]:
    return sessionmaker(bind=get_engine(), expire_on_commit=False, autobegin=True)


def get_session() -> Iterator[Session]:
    session = get_session_factory()()
    try:
        yield session
    finally:
        session.close()


# The API layer depends on this alias instead of importing SQLAlchemy directly.
DbSession = Annotated[Session, Depends(get_session)]
