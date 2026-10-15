"""TAXII 2.1 collection polling (THREAT_INTELLIGENCE.md §8, §10). No database access here.

Only admin-configured ``https`` API roots are contacted, with TLS verification always on.
Retries: transport errors and HTTP 5xx up to ``MAX_ATTEMPTS`` with back-off; HTTP 429 honours
``Retry-After`` (capped at one hour); other 4xx fail immediately.
"""

from __future__ import annotations

import json
import random
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import httpx

ACCEPT = "application/taxii+json;version=2.1"
TIMEOUT_S = 30.0
MAX_RESPONSE_BYTES = 50 * 1024 * 1024
MAX_ATTEMPTS = 3
BACKOFF_S = (30.0, 120.0, 600.0)
MAX_RETRY_AFTER_S = 3600.0


class TaxiiError(Exception):
    def __init__(self, message: str, *, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


@dataclass
class PollResult:
    objects: list[dict[str, Any]] = field(default_factory=list)
    pages: int = 0
    cursor: str | None = None  # value for the next run's added_after
    more_available: bool = False
    retries: int = 0


def _retry_after(response: httpx.Response, attempt: int) -> float:
    value = response.headers.get("Retry-After", "")
    if value.isdigit():
        return min(float(value), MAX_RETRY_AFTER_S)
    return BACKOFF_S[min(attempt, len(BACKOFF_S) - 1)]


def _read_capped(response: httpx.Response) -> bytes:
    declared = response.headers.get("Content-Length")
    if declared and declared.isdigit() and int(declared) > MAX_RESPONSE_BYTES:
        raise TaxiiError("TAXII response exceeds the 50 MB limit")
    body = bytearray()
    for chunk in response.iter_bytes():
        body.extend(chunk)
        if len(body) > MAX_RESPONSE_BYTES:
            raise TaxiiError("TAXII response exceeds the 50 MB limit")
    return bytes(body)


def _get(
    client: httpx.Client,
    url: str,
    params: dict[str, str],
    headers: dict[str, str],
    sleep: Callable[[float], None],
    result: PollResult,
) -> tuple[dict[str, Any], httpx.Headers]:
    for attempt in range(MAX_ATTEMPTS):
        try:
            with client.stream("GET", url, params=params, headers=headers) as response:
                if response.status_code == 429 or response.status_code >= 500:
                    if attempt == MAX_ATTEMPTS - 1:
                        raise TaxiiError(
                            f"TAXII server returned {response.status_code} after "
                            f"{MAX_ATTEMPTS} attempts",
                            status=response.status_code,
                        )
                    wait = (
                        _retry_after(response, attempt)
                        if response.status_code == 429
                        else BACKOFF_S[attempt] * (1 + random.random() * 0.1)  # noqa: S311 - jitter
                    )
                    result.retries += 1
                    sleep(wait)
                    continue
                if response.status_code >= 400:
                    raise TaxiiError(
                        f"TAXII server returned {response.status_code}", status=response.status_code
                    )
                body = _read_capped(response)
                try:
                    data = json.loads(body.decode("utf-8"))
                except (ValueError, UnicodeDecodeError) as exc:
                    raise TaxiiError("TAXII response is not JSON") from exc
                if not isinstance(data, dict):
                    raise TaxiiError("TAXII envelope must be a JSON object")
                return data, response.headers
        except httpx.TransportError as exc:
            if attempt == MAX_ATTEMPTS - 1:
                raise TaxiiError(f"TAXII request failed: {type(exc).__name__}") from exc
            result.retries += 1
            sleep(BACKOFF_S[attempt])
    raise TaxiiError("unreachable")  # pragma: no cover


def poll(
    *,
    api_root: str,
    collection_id: str,
    added_after: str | None,
    token: str | None,
    max_pages: int = 20,
    transport: httpx.BaseTransport | None = None,
    sleep: Callable[[float], None] | None = None,
) -> PollResult:
    if not api_root.startswith("https://"):
        raise TaxiiError("TAXII API root must use https")
    if not collection_id or "/" in collection_id:
        raise TaxiiError("invalid collection id")
    sleeper = sleep or time.sleep
    url = f"{api_root.rstrip('/')}/collections/{collection_id}/objects/"
    headers = {"Accept": ACCEPT}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    result = PollResult(cursor=added_after)
    params: dict[str, str] = {}
    if added_after:
        params["added_after"] = added_after
    with httpx.Client(
        transport=transport, timeout=TIMEOUT_S, verify=True, follow_redirects=False
    ) as client:
        while result.pages < max_pages:
            data, response_headers = _get(client, url, params, headers, sleeper, result)
            result.pages += 1
            objects = data.get("objects") or []
            if not isinstance(objects, list):
                raise TaxiiError("TAXII envelope 'objects' must be a list")
            result.objects += [o for o in objects if isinstance(o, dict)]
            last_added = response_headers.get("X-TAXII-Date-Added-Last")
            if last_added:
                result.cursor = last_added
            if not data.get("more"):
                result.more_available = False
                break
            result.more_available = True
            if data.get("next"):
                params = {"next": str(data["next"])}
                if added_after:
                    params["added_after"] = added_after
            elif last_added:
                params = {"added_after": last_added}
            else:
                break
    return result
