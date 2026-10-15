"""Adapter registry. Importing this package registers every adapter."""

from app.ingestion.adapters import canonical, datasets, logs, web  # noqa: F401  (registration)
from app.ingestion.adapters.base import ADAPTERS, Adapter


def get_adapter_class(name: str) -> type[Adapter] | None:
    return ADAPTERS.get(name)


__all__ = ["ADAPTERS", "Adapter", "get_adapter_class"]
