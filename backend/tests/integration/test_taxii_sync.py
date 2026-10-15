"""TAXII feed sync end to end with a local stub transport (AC-8.4)."""

from __future__ import annotations

import json
import uuid
from collections.abc import Callable
from datetime import timedelta
from typing import Any

import httpx
import pytest
from sqlalchemy.orm import Session, sessionmaker

from app.core import clock
from app.core.security import Role
from app.services import threat_intel
from app.ti import taxii
from tests.conftest import LoggedIn

pytestmark = pytest.mark.integration


def _page(values: list[str], last: str) -> httpx.Response:
    objects = [
        {
            "type": "indicator",
            "id": f"indicator--{v}",
            "pattern_type": "stix",
            "pattern": f"[ipv4-addr:value = '{v}']",
            "valid_from": "2026-01-01T00:00:00Z",
            "confidence": 70,
        }
        for v in values
    ]
    return httpx.Response(
        200,
        content=json.dumps({"objects": objects, "more": False}).encode(),
        headers={"X-TAXII-Date-Added-Last": last},
    )


def test_taxii_feed_sync(
    login: Callable[..., LoggedIn],
    session_factory: sessionmaker[Session],
    seeded: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admin = login("root", Role.ADMIN)
    h = admin.headers()
    feed = admin.client.post(
        "/api/v1/threat-intel/feeds",
        json={
            "feed_key": "stub-taxii",
            "name": "Stub TAXII",
            "feed_type": "taxii",
            "url": "https://taxii.example.test/api1",
            "collection_id": "col-1",
            "reliability": "B",
            "credentials_ref": "CTI_FEED_STUB_TOKEN",
        },
        headers=h,
    ).json()
    monkeypatch.delenv("CTI_FEED_STUB_TOKEN", raising=False)
    feeds = {f["feed_key"]: f for f in admin.client.get("/api/v1/threat-intel/feeds").json()}
    assert feeds["stub-taxii"]["health"] == "not_configured"
    missing = admin.client.post(f"/api/v1/threat-intel/feeds/{feed['feed_id']}/sync", headers=h)
    assert missing.status_code == 409 and "CTI_FEED_STUB_TOKEN" in missing.json()["detail"]

    monkeypatch.setenv("CTI_FEED_STUB_TOKEN", "stub-secret")
    resp = admin.client.post(f"/api/v1/threat-intel/feeds/{feed['feed_id']}/sync", headers=h)
    assert resp.status_code == 202, resp.text
    again = admin.client.post(f"/api/v1/threat-intel/feeds/{feed['feed_id']}/sync", headers=h)
    assert again.status_code == 409  # one queued already

    seen: list[httpx.Request] = []
    pages = [_page(["198.51.100.1", "198.51.100.2"], "2026-02-01T00:00:00Z")]

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return pages.pop(0)

    run = threat_intel.run_sync(
        session_factory,
        uuid.UUID(resp.json()["id"]),
        transport=httpx.MockTransport(handler),
        sleep=lambda s: None,
    )
    assert run.status == "succeeded" and run.indicators_created == 2
    assert run.report["cursor"] == "2026-02-01T00:00:00Z"
    assert seen[0].headers["Authorization"] == "Bearer stub-secret"
    assert "added_after" not in seen[0].url.params

    # Second sync (after the minimum spacing) resumes from the cursor; a failure keeps data.
    real_now = clock.now()
    clock.set_clock(lambda: real_now + timedelta(minutes=10))
    second = admin.client.post(f"/api/v1/threat-intel/feeds/{feed['feed_id']}/sync", headers=h)
    assert second.status_code == 202, second.text
    pages.append(httpx.Response(401))
    with pytest.raises(taxii.TaxiiError):
        threat_intel.run_sync(
            session_factory,
            uuid.UUID(second.json()["id"]),
            transport=httpx.MockTransport(handler),
            sleep=lambda s: None,
        )
    assert seen[1].url.params["added_after"] == "2026-02-01T00:00:00Z"
    indicators: dict[str, Any] = admin.client.get(
        "/api/v1/threat-intel/indicators", params={"feed_id": feed["feed_id"]}
    ).json()
    assert len(indicators["items"]) == 2
    report = admin.client.get(f"/api/v1/threat-intel/imports/{second.json()['id']}").json()
    assert report["status"] == "failed" and "401" in report["error"]
    feeds = {f["feed_key"]: f for f in admin.client.get("/api/v1/threat-intel/feeds").json()}
    assert feeds["stub-taxii"]["health"] == "error"
