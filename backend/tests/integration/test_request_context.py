from __future__ import annotations

import uuid

import pytest
from fastapi import APIRouter
from fastapi.testclient import TestClient

pytestmark = pytest.mark.integration


def test_request_id_generated_when_absent(client: TestClient) -> None:
    resp = client.get("/api/v1/health")
    uuid.UUID(resp.headers["X-Request-ID"])


def test_valid_request_id_is_echoed(client: TestClient) -> None:
    resp = client.get("/api/v1/health", headers={"X-Request-ID": "trace-abc.123"})
    assert resp.headers["X-Request-ID"] == "trace-abc.123"


def test_invalid_request_id_is_replaced(client: TestClient) -> None:
    resp = client.get("/api/v1/health", headers={"X-Request-ID": "bad id <script>"})
    assert resp.headers["X-Request-ID"] != "bad id <script>"
    uuid.UUID(resp.headers["X-Request-ID"])


def test_unknown_route_is_problem_json(client: TestClient) -> None:
    resp = client.get("/api/v1/does-not-exist")
    assert resp.status_code == 404
    assert resp.headers["content-type"].startswith("application/problem+json")
    body = resp.json()
    assert body["type"].endswith("/not-found")
    assert body["request_id"] == resp.headers["X-Request-ID"]


def test_unhandled_error_returns_500_problem_without_internals() -> None:
    from app.main import create_app

    app = create_app()
    boom = APIRouter()

    @boom.get("/api/v1/_test/boom")
    def _boom() -> None:
        raise RuntimeError("secret internal detail password=hunter2")

    app.include_router(boom)
    with TestClient(app, raise_server_exceptions=False) as test_client:
        resp = test_client.get("/api/v1/_test/boom")
    assert resp.status_code == 500
    body = resp.json()
    assert body["type"].endswith("/internal-error")
    assert body["request_id"] == resp.headers["X-Request-ID"]
    assert "hunter2" not in resp.text and "RuntimeError" not in resp.text
