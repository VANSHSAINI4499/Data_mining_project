"""Request context: request IDs, client IP, access logs, and last-resort 500 handling."""

from __future__ import annotations

import hashlib
import ipaddress
import logging
import re
import time
import uuid
from http.cookies import CookieError, SimpleCookie

from starlette.datastructures import Headers, MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.api.problems import internal_error_response, problem_response
from app.core.logging import client_ip_var, request_id_var, user_id_var
from app.core.ratelimit import LIMITS, RateLimiter, retry_after_header

log = logging.getLogger("app.access")

REQUEST_ID_HEADER = "X-Request-ID"
_VALID_REQUEST_ID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


def client_ip(scope: Scope) -> str | None:
    """The peer address if it is a valid IP; ``None`` otherwise (sockets, test clients)."""
    client = scope.get("client")
    if not client:
        return None
    try:
        return str(ipaddress.ip_address(client[0]))
    except ValueError:
        return None


UPLOAD_PATH_SUFFIXES = ("/ingestion/uploads", "/assets/import")
MULTIPART_OVERHEAD = 1024 * 1024  # form fields and boundaries around the file part


class _BodyTooLargeError(Exception):
    pass


class UploadLimitMiddleware:
    """Enforce the upload limit *before* the multipart body is parsed (SECURITY §4).

    Requires a Content-Length on upload endpoints and stops reading if the body exceeds it.
    """

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes + MULTIPART_OVERHEAD

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if (
            scope["type"] != "http"
            or scope.get("method") != "POST"
            or not str(scope.get("path", "")).endswith(UPLOAD_PATH_SUFFIXES)
        ):
            await self.app(scope, receive, send)
            return
        path = str(scope.get("path", ""))
        length = Headers(scope=scope).get("content-length")
        if length is None or not length.isdigit():
            await _problem(
                scope,
                receive,
                send,
                411,
                "length-required",
                "Content-Length required",
                "uploads must declare Content-Length",
            )
            return
        if int(length) > self.max_bytes:
            await _problem(
                scope,
                receive,
                send,
                413,
                "payload-too-large",
                "Payload too large",
                f"upload body exceeds the limit of {self.max_bytes} bytes",
            )
            return
        received = 0
        started = False

        async def counting_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    raise _BodyTooLargeError
            return message

        async def tracking_send(message: Message) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, counting_receive, tracking_send)
        except _BodyTooLargeError:
            if not started:
                await _problem(
                    scope,
                    receive,
                    send,
                    413,
                    "payload-too-large",
                    "Payload too large",
                    f"body exceeded {self.max_bytes} bytes",
                    path,
                )


async def _problem(
    scope: Scope,
    receive: Receive,
    send: Send,
    status: int,
    slug: str,
    title: str,
    detail: str,
    instance: str | None = None,
) -> None:
    from app.api.problems import problem_response

    response = problem_response(
        status=status,
        slug=slug,
        title=title,
        detail=detail,
        instance=instance or str(scope.get("path", "")),
    )
    await response(scope, receive, send)


class RequestContextMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        incoming = Headers(scope=scope).get(REQUEST_ID_HEADER, "")
        request_id = incoming if _VALID_REQUEST_ID.match(incoming) else str(uuid.uuid4())
        tokens = (
            request_id_var.set(request_id),
            client_ip_var.set(client_ip(scope)),
            user_id_var.set(None),
        )
        state = {"status": 500, "started": False}
        start = time.perf_counter()

        async def send_with_id(message: Message) -> None:
            if message["type"] == "http.response.start":
                state["status"] = message["status"]
                state["started"] = True
                MutableHeaders(scope=message)[REQUEST_ID_HEADER] = request_id
            await send(message)

        try:
            await self.app(scope, receive, send_with_id)
        except Exception:
            log.exception("unhandled error", extra={"path": scope.get("path")})
            if state["started"]:
                raise
            await internal_error_response(scope.get("path", ""))(scope, receive, send_with_id)
        finally:
            log.info(
                "request",
                extra={
                    "method": scope.get("method"),
                    "path": scope.get("path"),
                    "status": state["status"],
                    "duration_ms": round((time.perf_counter() - start) * 1000, 1),
                },
            )
            for var, token in zip(
                (request_id_var, client_ip_var, user_id_var), tokens, strict=True
            ):
                var.reset(token)


SECURITY_HEADERS = [
    (b"x-content-type-options", b"nosniff"),
    (b"referrer-policy", b"no-referrer"),
    (b"x-frame-options", b"DENY"),
    # The API only returns JSON; nothing it serves may load sub-resources or be framed.
    (b"content-security-policy", b"default-src 'none'; frame-ancestors 'none'"),
    (b"cross-origin-resource-policy", b"same-origin"),
]
DOCS_CSP = (
    b"default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; "
    b"style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    b"img-src 'self' data: https://fastapi.tiangolo.com; frame-ancestors 'none'"
)


class SecurityHeadersMiddleware:
    """Add security headers to every HTTP response (SECURITY_REQUIREMENTS.md §13)."""

    def __init__(self, app: ASGIApp, docs_path: str | None = None) -> None:
        self.app = app
        self.docs_path = docs_path

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        # Swagger UI (development only) needs its CDN assets.
        is_docs = self.docs_path is not None and scope.get("path") == self.docs_path

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for name, value in SECURITY_HEADERS:
                    use_docs_csp = is_docs and name == b"content-security-policy"
                    headers.setdefault(
                        name.decode(), (DOCS_CSP if use_docs_csp else value).decode()
                    )
            await send(message)

        await self.app(scope, receive, send_with_headers)


JOB_PATH_SUFFIXES = (
    "/training-runs",
    "/scoring-runs",
    "/match-runs",
    "/correlation/runs",
    "/retry",
    "/sync",
    "/threat-intel/imports",
)
UNLIMITED_PATHS = ("/api/v1/health", "/api/v1/health/ready", "/api/v1/auth/login")


def rate_category(method: str, path: str) -> str:
    if method == "POST" and path.endswith(UPLOAD_PATH_SUFFIXES):
        return "upload"
    if method == "POST" and path.endswith(JOB_PATH_SUFFIXES):
        return "job"
    return "default"


class RateLimitMiddleware:
    """Per-session (or per-IP when anonymous) limits; 429 with ``Retry-After`` when exceeded.

    Login is limited separately per IP and username inside the login endpoint.
    """

    def __init__(self, app: ASGIApp, limiter: RateLimiter, cookie_name: str) -> None:
        self.app = app
        self.limiter = limiter
        self.cookie_name = cookie_name

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        path = str(scope.get("path", ""))
        if scope["type"] != "http" or not path.startswith("/api/") or path in UNLIMITED_PATHS:
            await self.app(scope, receive, send)
            return
        cookie = SimpleCookie()
        try:
            cookie.load(Headers(scope=scope).get("cookie", ""))
        except CookieError:  # malformed cookies are treated as anonymous
            cookie = SimpleCookie()
        token = cookie.get(self.cookie_name)
        who = (
            "s:" + hashlib.sha256(token.value.encode()).hexdigest()[:32]
            if token is not None
            else f"ip:{client_ip(scope)}"
        )
        category = rate_category(str(scope.get("method", "")), path)
        wait = self.limiter.hit(f"{category}:{who}", LIMITS[category])
        if category != "default" and wait is None:
            wait = self.limiter.hit(f"default:{who}", LIMITS["default"])
        if wait is None:
            await self.app(scope, receive, send)
            return
        response = problem_response(
            status=429,
            slug="rate-limited",
            title="Too many requests",
            detail=f"rate limit for {category} requests exceeded; retry later",
            instance=path,
            headers={"Retry-After": retry_after_header(wait)},
        )
        await response(scope, receive, send)
