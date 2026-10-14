"""Typed domain errors. The API layer maps them to RFC 9457 problem responses."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class FieldError:
    field: str
    code: str
    message: str


class DomainError(Exception):
    """Base class for errors raised by services and domain modules."""

    status: int = 400
    slug: str = "bad-request"
    title: str = "Bad request"

    def __init__(
        self,
        detail: str,
        *,
        errors: list[FieldError] | None = None,
        extra: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(detail)
        self.detail = detail
        self.errors = errors or []
        self.extra = extra or {}


class NotFoundError(DomainError):
    status, slug, title = 404, "not-found", "Resource not found"


class ConflictError(DomainError):
    status, slug, title = 409, "conflict", "Conflict"


class ValidationFailedError(DomainError):
    status, slug, title = 422, "validation-error", "Request validation failed"


class AuthenticationError(DomainError):
    status, slug, title = 401, "unauthenticated", "Authentication required"


class PermissionDeniedError(DomainError):
    status, slug, title = 403, "forbidden", "Permission denied"


class CsrfError(DomainError):
    status, slug, title = 403, "csrf-failed", "CSRF token missing or invalid"


class NotReadyError(DomainError):
    status, slug, title = 503, "not-ready", "Service not ready"
