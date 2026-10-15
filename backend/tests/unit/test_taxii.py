"""TAXII 2.1 polling against a local stub transport (AC-8.4). No network access."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from app.ti import taxii

ROOT = "https://taxii.example.test/api1"


def _indicator(n: int) -> dict[str, Any]:
    return {
        "type": "indicator",
        "id": f"indicator--{n:04d}",
        "pattern_type": "stix",
        "pattern": f"[ipv4-addr:value = '203.0.113.{n}']",
        "valid_from": "2026-01-01T00:00:00Z",
    }


class Stub:
    """Serves pages of a TAXII collection and records requests."""

    def __init__(self, responses: list[httpx.Response]) -> None:
        self.responses = responses
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self.responses.pop(0)


def envelope(
    objects: list[dict[str, Any]], more: bool, next_: str | None = None, last: str | None = None
) -> httpx.Response:
    body: dict[str, Any] = {"objects": objects, "more": more}
    if next_:
        body["next"] = next_
    headers = {"Content-Type": taxii.ACCEPT}
    if last:
        headers["X-TAXII-Date-Added-Last"] = last
    return httpx.Response(200, content=json.dumps(body).encode(), headers=headers)


def run(stub: Stub, sleeps: list[float], **kwargs: Any) -> taxii.PollResult:
    return taxii.poll(
        api_root=ROOT,
        collection_id="col-1",
        transport=httpx.MockTransport(stub),
        sleep=sleeps.append,
        **kwargs,
    )


def test_paginates_with_next_and_returns_cursor() -> None:
    stub = Stub(
        [
            envelope([_indicator(1), _indicator(2)], True, "page2", "2026-01-02T00:00:00Z"),
            envelope([_indicator(3)], False, None, "2026-01-03T00:00:00Z"),
        ]
    )
    sleeps: list[float] = []
    result = run(stub, sleeps, added_after="2026-01-01T00:00:00Z", token="secret-token")
    assert [o["id"] for o in result.objects] == [
        "indicator--0001",
        "indicator--0002",
        "indicator--0003",
    ]
    assert result.pages == 2 and result.cursor == "2026-01-03T00:00:00Z"
    assert result.more_available is False and sleeps == []
    first, second = stub.requests
    assert first.url.path == "/api1/collections/col-1/objects/"
    assert first.url.params["added_after"] == "2026-01-01T00:00:00Z"
    assert second.url.params["next"] == "page2"
    assert first.headers["Accept"] == taxii.ACCEPT
    assert first.headers["Authorization"] == "Bearer secret-token"


def test_max_pages_stops_and_reports_more() -> None:
    stub = Stub([envelope([_indicator(i)], True, f"p{i}") for i in range(5)])
    result = run(stub, [], added_after=None, token=None, max_pages=2)
    assert result.pages == 2 and result.more_available is True
    assert "Authorization" not in stub.requests[0].headers


def test_retries_5xx_and_honours_retry_after_on_429() -> None:
    stub = Stub(
        [
            httpx.Response(503),
            httpx.Response(429, headers={"Retry-After": "7"}),
            envelope([_indicator(1)], False),
        ]
    )
    sleeps: list[float] = []
    result = run(stub, sleeps, added_after=None, token=None)
    assert result.retries == 2 and len(result.objects) == 1
    assert 30 <= sleeps[0] <= 33  # back-off with jitter
    assert sleeps[1] == 7


def test_retry_after_is_capped_at_one_hour() -> None:
    stub = Stub([httpx.Response(429, headers={"Retry-After": "99999"}), envelope([], False)])
    sleeps: list[float] = []
    run(stub, sleeps, added_after=None, token=None)
    assert sleeps == [taxii.MAX_RETRY_AFTER_S]


def test_gives_up_after_three_attempts() -> None:
    stub = Stub([httpx.Response(500)] * 3)
    with pytest.raises(taxii.TaxiiError, match="after 3 attempts"):
        run(stub, [], added_after=None, token=None)


def test_client_errors_are_not_retried() -> None:
    stub = Stub([httpx.Response(401)])
    with pytest.raises(taxii.TaxiiError) as exc:
        run(stub, [], added_after=None, token=None)
    assert exc.value.status == 401 and len(stub.requests) == 1


def test_transport_errors_are_retried() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            raise httpx.ConnectError("refused", request=request)
        return envelope([], False)

    sleeps: list[float] = []
    result = taxii.poll(
        api_root=ROOT,
        collection_id="c",
        added_after=None,
        token=None,
        transport=httpx.MockTransport(handler),
        sleep=sleeps.append,
    )
    assert result.retries == 1 and len(sleeps) == 1


def test_rejects_oversized_and_invalid_responses_and_plain_http() -> None:
    big = httpx.Response(
        200, headers={"Content-Length": str(taxii.MAX_RESPONSE_BYTES + 1)}, content=b"{}"
    )
    with pytest.raises(taxii.TaxiiError, match="50 MB"):
        run(Stub([big]), [], added_after=None, token=None)
    with pytest.raises(taxii.TaxiiError, match="not JSON"):
        run(Stub([httpx.Response(200, content=b"<html>")]), [], added_after=None, token=None)
    with pytest.raises(taxii.TaxiiError, match="https"):
        taxii.poll(api_root="http://insecure.test", collection_id="c", added_after=None, token=None)
