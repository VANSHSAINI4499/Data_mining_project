"""API tests for Phase 2 endpoints (AC-2.3, AC-2.6, AC-2.7)."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings
from app.core.security import Role
from app.jobs.registry import HANDLERS
from app.jobs.worker import Worker
from tests.conftest import LoggedIn

pytestmark = pytest.mark.integration

FLOWS = [
    {
        "event_type": "network_flow",
        "event_time": f"2026-01-05T{10 + i % 3:02d}:00:{i:02d}Z",
        "src_ip": f"192.0.2.{10 + i % 2}",
        "dst_ip": "198.51.100.7",
        "dst_port": 22 if i % 2 else 443,
        "protocol": "tcp",
        "bytes_out": 100,
        "bytes_in": 50,
        "label_raw": "BRUTE_FORCE" if i % 2 else "BENIGN",
    }
    for i in range(6)
] + [
    {
        "event_type": "auth",
        "event_time": "2026-01-05T11:30:00Z",
        "user_name": "Alice",
        "auth_result": "failure",
        "src_ip": "203.0.113.5",
    }
]


def _jsonl(rows: list[dict[str, Any]]) -> bytes:
    return ("\n".join(json.dumps(r) for r in rows) + "\n").encode()


def _source_id(client: TestClient, key: str = "synthetic") -> int:
    sources = client.get("/api/v1/sources").json()
    return int(next(s["source_id"] for s in sources if s["source_key"] == key))


def _upload(session: LoggedIn, content: bytes, name: str = "events.jsonl", **form: Any) -> Any:
    data = {"source_id": str(_source_id(session.client)), **{k: str(v) for k, v in form.items()}}
    return session.client.post(
        "/api/v1/ingestion/uploads",
        headers=session.headers(),
        files={"file": (name, content, "application/octet-stream")},
        data=data,
    )


def _run_worker(factory: sessionmaker[Session]) -> None:
    worker = Worker(factory, get_settings(), HANDLERS)
    while worker.run_once():
        pass


@pytest.fixture
def analyst(login: Callable[..., LoggedIn], seeded: Session) -> LoggedIn:
    return login("ana", Role.ANALYST)


def test_upload_processed_by_worker_end_to_end(
    analyst: LoggedIn, session_factory: sessionmaker[Session]
) -> None:
    resp = _upload(analyst, _jsonl(FLOWS))
    assert resp.status_code == 202, resp.text
    body = resp.json()
    assert body["status"] == "pending" and body["job_id"]
    _run_worker(session_factory)

    batch = analyst.client.get(f"/api/v1/ingestion/batches/{body['batch_id']}").json()
    assert batch["status"] == "completed"
    assert (batch["records_total"], batch["records_loaded"]) == (7, 7)
    assert "stored_path" not in batch and "metadata" in batch
    job = analyst.client.get(f"/api/v1/jobs/{body['job_id']}").json()
    assert job["status"] == "succeeded" and job["result"]["records_loaded"] == 7

    dq = analyst.client.get(f"/api/v1/data-quality/batches/{body['batch_id']}").json()
    assert {c["check_name"]: c["status"] for c in dq}["counter_reconciliation"] == "pass"

    again = _upload(analyst, _jsonl(FLOWS), name="renamed.jsonl")
    assert again.status_code == 200
    assert again.json()["status"] == "duplicate"
    assert again.json()["duplicate_of"] == body["batch_id"]


def test_upload_validation_and_limits(analyst: LoggedIn, monkeypatch: pytest.MonkeyPatch) -> None:
    assert _upload(analyst, b"PK\x03\x04", name="a.zip").status_code == 415
    assert _upload(analyst, b"\x00\x01binary", name="a.jsonl").status_code == 415
    assert _upload(analyst, b"x", name="a.jsonl", adapter="nope").status_code == 422
    assert _upload(analyst, b"x", name="a.jsonl", timezone="Mars/Base").status_code == 422
    assert _upload(analyst, b"", name="a.jsonl").status_code == 422
    monkeypatch.setattr(get_settings(), "max_upload_mb", 1)
    big = b'{"a": 1}\n' * 150_000  # ~1.3 MB > 1 MB limit, under the multipart overhead allowance
    resp = _upload(analyst, big)
    assert resp.status_code == 413
    assert resp.headers["content-type"].startswith("application/problem+json")


def test_upload_middleware_rejects_oversized_or_unsized_bodies(
    analyst: LoggedIn, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.main import create_app

    monkeypatch.setattr(get_settings(), "max_upload_mb", 1)
    app = create_app(get_settings())
    with TestClient(app) as raw:
        too_big = raw.post(
            "/api/v1/ingestion/uploads",
            content=b"x" * (3 * 1024 * 1024),
            headers={"content-type": "multipart/form-data; boundary=x"},
        )
        assert too_big.status_code == 413

        def chunks() -> Any:
            yield b"x" * 10

        no_length = raw.post(
            "/api/v1/ingestion/uploads",
            content=chunks(),
            headers={"content-type": "multipart/form-data; boundary=x"},
        )
        assert no_length.status_code == 411


def test_viewer_cannot_upload_but_can_read(login: Callable[..., LoggedIn], seeded: Session) -> None:
    viewer = login("vic")
    assert _upload(viewer, _jsonl(FLOWS)).status_code == 403
    assert viewer.client.get("/api/v1/ingestion/batches").status_code == 200


def test_rejections_listing_and_retry_rules(
    analyst: LoggedIn, session_factory: sessionmaker[Session]
) -> None:
    rows = _jsonl(FLOWS[:2]) + b"{bad json\n" + b'{"event_type": "network_flow"}\n'
    batch_id = _upload(analyst, rows).json()["batch_id"]
    _run_worker(session_factory)
    page = analyst.client.get(
        f"/api/v1/ingestion/batches/{batch_id}/rejections", params={"limit": 1}
    ).json()
    assert page["total"] == 2 and len(page["items"]) == 1 and page["next_cursor"]
    rest = analyst.client.get(
        f"/api/v1/ingestion/batches/{batch_id}/rejections", params={"cursor": page["next_cursor"]}
    ).json()
    codes = {page["items"][0]["error_code"], rest["items"][0]["error_code"]}
    assert codes == {"MALFORMED_JSON", "MISSING_REQUIRED_FIELD"}
    retry = analyst.client.post(
        f"/api/v1/ingestion/batches/{batch_id}/retry", headers=analyst.headers()
    )
    assert retry.status_code == 409  # only failed batches can be retried


@pytest.fixture
def loaded(analyst: LoggedIn, session_factory: sessionmaker[Session]) -> str:
    batch_id = _upload(analyst, _jsonl(FLOWS)).json()["batch_id"]
    _run_worker(session_factory)
    return str(batch_id)


RANGE = {"from": "2026-01-05T00:00:00Z", "to": "2026-01-06T00:00:00Z"}


def test_event_search_filters_and_pagination(analyst: LoggedIn, loaded: str) -> None:
    c = analyst.client
    all_events = c.get("/api/v1/events", params=RANGE).json()["items"]
    assert len(all_events) == 7
    assert all(isinstance(e["event_id"], str) for e in all_events)
    times = [e["event_time"] for e in all_events]
    assert times == sorted(times, reverse=True)

    assert len(c.get("/api/v1/events", params={**RANGE, "dst_port": 22}).json()["items"]) == 3
    assert len(c.get("/api/v1/events", params={**RANGE, "ip": "198.51.100.7"}).json()["items"]) == 6
    assert len(c.get("/api/v1/events", params={**RANGE, "event_type": "auth"}).json()["items"]) == 1
    assert len(c.get("/api/v1/events", params={**RANGE, "user_name": "ALICE"}).json()["items"]) == 1
    brute = c.get("/api/v1/events", params={**RANGE, "ground_truth_category": "brute_force"})
    assert len(brute.json()["items"]) == 3
    assert all(e["ground_truth_category"] == "BRUTE_FORCE" for e in brute.json()["items"])
    assert c.get("/api/v1/events", params={**RANGE, "batch_id": loaded}).json()["items"]

    seen: list[str] = []
    cursor = None
    while True:
        params: dict[str, Any] = {**RANGE, "limit": 3}
        if cursor:
            params["cursor"] = cursor
        page = c.get("/api/v1/events", params=params).json()
        seen += [e["event_id"] for e in page["items"]]
        cursor = page["next_cursor"]
        if not cursor:
            break
    assert sorted(seen) == sorted(e["event_id"] for e in all_events)


@pytest.mark.parametrize(
    "params",
    [
        {},  # from/to required
        {"from": "2026-01-05T00:00:00", "to": "2026-01-06T00:00:00Z"},  # naive
        {**RANGE, "to": "2026-01-04T00:00:00Z"},  # inverted
        {"from": "2020-01-01T00:00:00Z", "to": "2026-01-06T00:00:00Z"},  # > 400 days
        {**RANGE, "src_ip": "not-an-ip"},
        {**RANGE, "src_ip": "1.1.1.1' OR '1'='1"},
        {**RANGE, "sort": "event_time"},  # unknown parameter
        {**RANGE, "cursor": "!!!"},
    ],
)
def test_event_search_rejects_bad_filters(analyst: LoggedIn, params: dict[str, Any]) -> None:
    resp = analyst.client.get("/api/v1/events", params=params)
    assert resp.status_code == 422, resp.text


def test_event_detail_raw_and_provenance(
    analyst: LoggedIn, loaded: str, login: Callable[..., LoggedIn]
) -> None:
    c = analyst.client
    event = c.get("/api/v1/events", params={**RANGE, "event_type": "auth"}).json()["items"][0]
    detail = c.get(f"/api/v1/events/{event['event_id']}").json()
    assert set(detail) == {
        "event_id",
        "observed",
        "provenance",
        "ground_truth",
        "model_outputs",
        "threat_intel",
        "alerts",
        "analyst",
    }
    assert detail["threat_intel"] == {"matches": [], "attack_techniques": []}
    assert detail["alerts"] == [] and detail["analyst"] == {"feedback": []}
    assert detail["model_outputs"] == {
        "classifications": [],
        "web_payload_classifications": [],
    }  # nothing scored yet
    assert detail["observed"]["user_name"] == "Alice"
    prov = detail["provenance"]
    assert prov["batch_id"] == loaded and prov["record_number"] == 7
    assert len(prov["file_sha256"]) == 64 and prov["adapter_version"] == "canonical_jsonl@1.0"
    assert detail["ground_truth"] is None  # this record carried no label

    raw = c.get(f"/api/v1/events/{event['event_id']}/raw").json()
    assert raw["raw_payload"]["user_name"] == "Alice"
    assert c.get("/api/v1/events/999999999").status_code == 404
    viewer = login("vic")
    assert viewer.client.get(f"/api/v1/events/{event['event_id']}/raw").status_code == 403


def test_analytics(analyst: LoggedIn, loaded: str) -> None:
    c = analyst.client
    ts = c.get(
        "/api/v1/analytics/timeseries",
        params={**RANGE, "interval": "hour", "group_by": "event_type"},
    ).json()
    totals: dict[str, float] = {}
    for bucket in ts["buckets"]:
        for key, value in bucket["series"].items():
            totals[key] = totals.get(key, 0) + value
    assert totals == {"network_flow": 6, "auth": 1}
    assert [b["ts"][:13] for b in ts["buckets"]] == [
        "2026-01-05T10",
        "2026-01-05T11",
        "2026-01-05T12",
    ]

    bytes_ts = c.get(
        "/api/v1/analytics/timeseries", params={**RANGE, "metric": "bytes_total"}
    ).json()
    assert sum(b["series"]["bytes_total"] for b in bytes_ts["buckets"]) == 6 * 150

    top = c.get("/api/v1/analytics/top-entities", params={**RANGE, "dimension": "src_ip"}).json()
    assert top["items"][0] == {"value": "192.0.2.10", "count": 3}

    dist = c.get(
        "/api/v1/analytics/distribution", params={**RANGE, "dimension": "ground_truth_category"}
    ).json()
    assert {i["value"]: i["count"] for i in dist["items"]} == {
        "BRUTE_FORCE": 3,
        "BENIGN": 3,
        "(unlabelled)": 1,
    }

    for bad in ({"dimension": "password_hash"}, {"dimension": "src_ip; DROP TABLE x"}):
        assert c.get("/api/v1/analytics/top-entities", params={**RANGE, **bad}).status_code == 422
    assert (
        c.get("/api/v1/analytics/timeseries", params={**RANGE, "interval": "minute"}).status_code
        == 422
    )


def test_empty_range_returns_honest_empty_results(analyst: LoggedIn, loaded: str) -> None:
    empty = {"from": "2025-01-01T00:00:00Z", "to": "2025-01-02T00:00:00Z"}
    assert analyst.client.get("/api/v1/events", params=empty).json()["items"] == []
    ts = analyst.client.get("/api/v1/analytics/timeseries", params=empty).json()
    assert ts["buckets"] == []


def test_sources_and_adapters(login: Callable[..., LoggedIn], seeded: Session) -> None:
    admin = login("root", Role.ADMIN)
    c = admin.client
    adapters = {a["name"] for a in c.get("/api/v1/adapters").json()}
    assert adapters == {
        "canonical_csv",
        "canonical_json",
        "canonical_jsonl",
        "zeek_conn",
        "suricata_eve",
        "auth_jsonl",
        "endpoint_jsonl",
        "cicids2017",
        "unsw_nb15",
        "nginx_access",
    }
    created = c.post(
        "/api/v1/sources",
        headers=admin.headers(),
        json={
            "source_key": "lab-zeek",
            "name": "Lab Zeek",
            "source_type": "network_sensor",
            "default_adapter": "zeek_conn",
            "default_timezone": "UTC",
        },
    )
    assert created.status_code == 201
    sid = created.json()["source_id"]
    dup = c.post(
        "/api/v1/sources",
        headers=admin.headers(),
        json={"source_key": "lab-zeek", "name": "x", "source_type": "other"},
    )
    assert dup.status_code == 409
    bad = c.post(
        "/api/v1/sources",
        headers=admin.headers(),
        json={
            "source_key": "x2",
            "name": "x",
            "source_type": "other",
            "default_timezone": "Nowhere/X",
        },
    )
    assert bad.status_code == 422
    patched = c.patch(
        f"/api/v1/sources/{sid}",
        headers=admin.headers(),
        json={"default_timezone": "America/Halifax", "is_active": False},
    )
    assert patched.json()["default_timezone"] == "America/Halifax"
    detail = c.get(f"/api/v1/sources/{sid}").json()
    assert detail["counts"] == {"batches": 0, "events": 0}


def test_assets_api(login: Callable[..., LoggedIn], seeded: Session, tmp_path: Path) -> None:
    admin = login("root", Role.ADMIN)
    csv = b"asset_id,hostname,ip_address,criticality\nsrv-01,srv-01,198.51.100.7,high\n"
    resp = admin.client.post(
        "/api/v1/assets/import",
        headers=admin.headers(),
        files={"file": ("assets.csv", csv, "text/csv")},
    )
    assert resp.status_code == 200 and resp.json()["created"] == 1
    listed = admin.client.get("/api/v1/assets", params={"q": "srv"}).json()
    assert [a["asset_id"] for a in listed["items"]] == ["srv-01"]


def test_data_quality_summary(analyst: LoggedIn, loaded: str) -> None:
    summary = analyst.client.get(
        "/api/v1/data-quality/summary",
        params={"from": "2000-01-01T00:00:00Z", "to": "2100-01-01T00:00:00Z"},
    ).json()
    synthetic = next(s for s in summary["by_source"] if s["source_key"] == "synthetic")
    assert synthetic["pass"] > 0
