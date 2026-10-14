"""RFC 9457 problem responses (API_SPECIFICATION.md §4)."""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.errors import DomainError, FieldError
from app.core.logging import request_id_var

PROBLEM_BASE = "https://cti-warehouse.local/problems/"
PROBLEM_MEDIA_TYPE = "application/problem+json"

_HTTP_SLUGS = {
    400: ("bad-request", "Bad request"),
    401: ("unauthenticated", "Authentication required"),
    403: ("forbidden", "Permission denied"),
    404: ("not-found", "Resource not found"),
    405: ("method-not-allowed", "Method not allowed"),
    409: ("conflict", "Conflict"),
    411: ("length-required", "Content-Length required"),
    413: ("payload-too-large", "Payload too large"),
    415: ("unsupported-media-type", "Unsupported media type"),
    422: ("validation-error", "Request validation failed"),
    429: ("rate-limited", "Too many requests"),
    500: ("internal-error", "Internal server error"),
    503: ("not-ready", "Service not ready"),
}
_LOCATION_PREFIXES = {"body", "query", "path", "header", "cookie"}


def problem_response(
    *,
    status: int,
    slug: str,
    title: str,
    detail: str,
    instance: str,
    errors: list[FieldError] | None = None,
    extra: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    body: dict[str, Any] = {
        "type": PROBLEM_BASE + slug,
        "title": title,
        "status": status,
        "detail": detail,
        "instance": instance,
        "request_id": request_id_var.get(),
    }
    if errors:
        body["errors"] = [{"field": e.field, "code": e.code, "message": e.message} for e in errors]
    if extra:
        body.update({k: v for k, v in extra.items() if k not in body})
    return JSONResponse(body, status_code=status, media_type=PROBLEM_MEDIA_TYPE, headers=headers)


def internal_error_response(instance: str) -> JSONResponse:
    slug, title = _HTTP_SLUGS[500]
    return problem_response(
        status=500,
        slug=slug,
        title=title,
        instance=instance,
        detail="An unexpected error occurred. Quote the request_id when reporting it.",
    )


def _field_errors(exc: RequestValidationError) -> list[FieldError]:
    result: list[FieldError] = []
    for err in exc.errors():
        loc = [str(part) for part in err.get("loc", ())]
        if loc and loc[0] in _LOCATION_PREFIXES:
            loc = loc[1:]
        result.append(
            FieldError(
                ".".join(loc) or "request",
                str(err.get("type", "invalid")),
                str(err.get("msg", "invalid value")),
            )
        )
    return result


def install_problem_handlers(app: FastAPI) -> None:
    @app.exception_handler(DomainError)
    async def _domain(request: Request, exc: DomainError) -> JSONResponse:
        return problem_response(
            status=exc.status,
            slug=exc.slug,
            title=exc.title,
            detail=exc.detail,
            instance=request.url.path,
            errors=exc.errors,
            extra=exc.extra,
        )

    @app.exception_handler(RequestValidationError)
    async def _validation(request: Request, exc: RequestValidationError) -> JSONResponse:
        errors = _field_errors(exc)
        slug, title = _HTTP_SLUGS[422]
        return problem_response(
            status=422,
            slug=slug,
            title=title,
            instance=request.url.path,
            errors=errors,
            detail=f"{len(errors)} field(s) are invalid",
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        slug, title = _HTTP_SLUGS.get(exc.status_code, ("http-error", "HTTP error"))
        detail = exc.detail if isinstance(exc.detail, str) else title
        return problem_response(
            status=exc.status_code,
            slug=slug,
            title=title,
            detail=detail,
            instance=request.url.path,
            headers=dict(exc.headers or {}),
        )
