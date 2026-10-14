"""Request context: request IDs, client IP, access logs, and last-resort 500 handling."""

from __future__ import annotations

import ipaddress
import logging
import re
import time
import uuid

from starlette.datastructures import Headers, MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.api.problems import internal_error_response
from app.core.logging import client_ip_var, request_id_var, user_id_var

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
