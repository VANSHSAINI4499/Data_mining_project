"""FastAPI application factory. Run with ``uvicorn app.main:app``."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import __version__
from app.api.deps import SESSION_COOKIE
from app.api.middleware import (
    RateLimitMiddleware,
    RequestContextMiddleware,
    SecurityHeadersMiddleware,
    UploadLimitMiddleware,
)
from app.api.problems import install_problem_handlers
from app.api.v1.router import API_PREFIX, api_router
from app.core.config import Settings, get_settings
from app.core.logging import configure_logging
from app.core.ratelimit import RateLimiter


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level)

    docs_enabled = not settings.is_production
    app = FastAPI(
        title="CTI Warehouse API",
        version=__version__,
        openapi_url=f"{API_PREFIX}/openapi.json" if docs_enabled else None,
        docs_url=f"{API_PREFIX}/docs" if docs_enabled else None,
        redoc_url=None,
        swagger_ui_oauth2_redirect_url=None,
    )
    install_problem_handlers(app)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        allow_headers=["Content-Type", "X-CSRF-Token", "X-Request-ID"],
        expose_headers=["X-Request-ID", "Retry-After"],
    )
    app.add_middleware(UploadLimitMiddleware, max_bytes=settings.max_upload_mb * 1024 * 1024)
    # One limiter per application instance (single API process in the MVP).
    app.state.rate_limiter = RateLimiter()
    app.add_middleware(
        RateLimitMiddleware, limiter=app.state.rate_limiter, cookie_name=SESSION_COOKIE
    )
    app.add_middleware(
        SecurityHeadersMiddleware, docs_path=f"{API_PREFIX}/docs" if docs_enabled else None
    )
    # Added last so it is outermost: every response, including CORS and 500s, gets an ID.
    app.add_middleware(RequestContextMiddleware)
    app.include_router(api_router)
    return app


app = create_app()
