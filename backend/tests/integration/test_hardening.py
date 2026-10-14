"""HTTP hardening: rate limits, security headers, CORS, production mode (AC-7.1, AC-7.2)."""

from __future__ import annotations

from collections.abc import Callable

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from app.core.config import Settings, get_settings
from app.core.ratelimit import LIMITS, RateLimiter
from app.core.security import Role
from tests.conftest import LoggedIn

pytestmark = pytest.mark.integration

LOGIN = "/api/v1/auth/login"


def test_security_headers_on_success_and_error(client: TestClient) -> None:
    for resp in (client.get("/api/v1/health"), client.get("/api/v1/events")):
        assert resp.headers["X-Content-Type-Options"] == "nosniff"
        assert resp.headers["Referrer-Policy"] == "no-referrer"
        assert resp.headers["X-Frame-Options"] == "DENY"
        assert "default-src 'none'" in resp.headers["Content-Security-Policy"]
        assert resp.headers["X-Request-ID"]


def test_login_rate_limit_per_ip_and_username(client: TestClient) -> None:
    for _ in range(LIMITS["login"]):
        resp = client.post(LOGIN, json={"username": "nobody", "password": "wrong-password"})
        assert resp.status_code == 401
    limited = client.post(LOGIN, json={"username": "nobody", "password": "wrong-password"})
    assert limited.status_code == 429
    assert int(limited.headers["Retry-After"]) >= 1
    assert limited.json()["title"] == "Too many requests"
    # Another username from the same address is not affected.
    other = client.post(LOGIN, json={"username": "somebody", "password": "wrong-password"})
    assert other.status_code == 401


def test_job_endpoint_rate_limit(
    login: Callable[..., LoggedIn], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(LIMITS, "job", 3)
    analyst = login("ana", Role.ANALYST)
    body = {"from": "2026-01-01T00:00:00Z", "to": "2026-01-02T00:00:00Z"}
    codes = [
        analyst.client.post(
            "/api/v1/correlation/runs", json=body, headers=analyst.headers()
        ).status_code
        for _ in range(4)
    ]
    assert codes == [202, 202, 202, 429]
    # Ordinary reads still work.
    assert analyst.client.get("/api/v1/alerts").status_code == 200


def test_default_limit_applies_to_anonymous_requests(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(LIMITS, "default", 2)
    codes = [client.get("/api/v1/events").status_code for _ in range(3)]
    assert codes == [401, 401, 429]
    assert client.get("/api/v1/health").status_code == 200  # health is never limited


def test_token_bucket_refills() -> None:
    now = [0.0]
    limiter = RateLimiter(clock=lambda: now[0])
    assert [limiter.hit("k", 60) is None for _ in range(60)] == [True] * 60
    wait = limiter.hit("k", 60)
    assert wait is not None and 0 < wait <= 1.0
    now[0] += 1.0
    assert limiter.hit("k", 60) is None


def test_cors_only_for_configured_origins(client: TestClient) -> None:
    allowed = get_settings().cors_origins[0]
    ok = client.options(
        "/api/v1/events",
        headers={"Origin": allowed, "Access-Control-Request-Method": "GET"},
    )
    assert ok.headers.get("access-control-allow-origin") == allowed
    assert ok.headers.get("access-control-allow-credentials") == "true"
    bad = client.options(
        "/api/v1/events",
        headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"},
    )
    assert "access-control-allow-origin" not in bad.headers


def test_production_mode_hides_api_docs() -> None:
    from app.main import create_app

    settings = Settings(
        env="production",
        secret_key=SecretStr("x" * 48),
        database_url=SecretStr("postgresql+psycopg://cti:a-real-password@localhost:5432/cti"),
    )
    with TestClient(create_app(settings)) as prod:
        assert prod.get("/api/v1/docs").status_code == 404
        assert prod.get("/api/v1/openapi.json").status_code == 404
    with TestClient(create_app(get_settings())) as dev:
        docs = dev.get("/api/v1/docs")
        assert docs.status_code == 200
        assert "cdn.jsdelivr.net" in docs.headers["Content-Security-Policy"]


def test_audit_records_are_admin_only_and_filterable(login: Callable[..., LoggedIn]) -> None:
    viewer = login("val", Role.VIEWER)
    assert viewer.client.get("/api/v1/audit-records").status_code == 403
    admin = login("root", Role.ADMIN)
    first = admin.client.get("/api/v1/audit-records", params={"limit": 2})
    assert first.status_code == 200, first.text
    page = first.json()
    assert len(page["items"]) == 2 and page["next_cursor"]
    assert page["items"][0]["audit_id"] > page["items"][1]["audit_id"]
    rest_resp = admin.client.get(
        "/api/v1/audit-records", params={"limit": 2, "cursor": page["next_cursor"]}
    )
    assert rest_resp.status_code == 200, rest_resp.text
    rest = rest_resp.json()
    assert rest["items"][0]["audit_id"] < page["items"][1]["audit_id"]
    logins = admin.client.get("/api/v1/audit-records", params={"action": "auth.login"}).json()
    assert logins["items"] and {i["action"] for i in logins["items"]} == {"auth.login"}
    assert {i["actor"] for i in logins["items"]} >= {"root", "val"}
    family = admin.client.get("/api/v1/audit-records", params={"action": "auth."}).json()
    assert all(i["action"].startswith("auth.") for i in family["items"])
    assert "auth.login" in family["known_actions"]
    # Read-only: no mutating methods exist on the collection.
    assert admin.client.delete("/api/v1/audit-records", headers=admin.headers()).status_code == 405
    bad = admin.client.get("/api/v1/audit-records", params={"cursor": "not-a-cursor"})
    assert bad.status_code == 422
