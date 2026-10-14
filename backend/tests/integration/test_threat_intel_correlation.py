"""Threat intel, correlation, alerts, cases, and feedback end to end (Phase 5, AC-5.x).

Uses the deterministic synthetic scenario (seed 42), whose planted patterns and expected
indicator matches are listed in ``expected.json``.
"""

from __future__ import annotations

import json
import socket
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings
from app.core.security import Role
from app.devtools.synthetic import write
from app.jobs.registry import HANDLERS
from app.jobs.worker import Worker
from app.models import AuditLog, TiFeed
from app.services import correlation, threat_intel
from app.services.actors import CLI_ACTOR
from tests.conftest import LoggedIn
from tests.integration.ingestion_helpers import ingest

pytestmark = pytest.mark.integration

RANGE = {"from": "2026-01-01T00:00:00Z", "to": "2026-01-11T00:00:00Z"}


def _run_worker(factory: sessionmaker[Session]) -> None:
    worker = Worker(factory, get_settings(), HANDLERS)
    while worker.run_once():
        pass


@pytest.fixture
def scenario(
    session_factory: sessionmaker[Session], seeded: Session, import_root: Path
) -> dict[str, Any]:
    paths = write(import_root / "syn", seed=42, days=10)
    assert ingest(session_factory, paths["events"], "synthetic").status == "completed"
    expected: dict[str, Any] = json.loads(paths["expected"].read_text(encoding="utf-8"))
    expected["indicators_csv"] = paths["indicators"]
    return expected


def _local_feed(db: Session) -> str:
    with db.begin():
        feed_id = db.scalar(select(TiFeed.feed_id).where(TiFeed.feed_key == "local-csv"))
    assert feed_id is not None
    return str(feed_id)


def _import_and_match(
    admin: LoggedIn, db: Session, factory: sessionmaker[Session], csv_path: Path
) -> dict[str, Any]:
    resp = admin.client.post(
        "/api/v1/threat-intel/imports",
        data={"feed_id": _local_feed(db), "format": "csv"},
        files={"file": ("indicators.csv", csv_path.read_bytes(), "text/csv")},
        headers=admin.headers(),
    )
    assert resp.status_code == 202, resp.text
    _run_worker(factory)
    run = admin.client.get(f"/api/v1/threat-intel/imports/{resp.json()['id']}").json()
    assert run["status"] == "succeeded", run
    resp = admin.client.post("/api/v1/threat-intel/match-runs", json=RANGE, headers=admin.headers())
    assert resp.status_code == 202, resp.text
    _run_worker(factory)
    return run


def _correlate(user: LoggedIn, factory: sessionmaker[Session]) -> dict[str, Any]:
    resp = user.client.post("/api/v1/correlation/runs", json=RANGE, headers=user.headers())
    assert resp.status_code == 202, resp.text
    _run_worker(factory)
    job = user.client.get(f"/api/v1/jobs/{resp.json()['job_id']}").json()
    assert job["status"] == "succeeded", job
    result: dict[str, Any] = job["result"]
    return result


def _alerts(user: LoggedIn) -> dict[tuple[str, str], dict[str, Any]]:
    items = user.client.get("/api/v1/alerts", params={"limit": 200}).json()["items"]
    return {(a["rule"]["rule_key"], a["primary_entity_value"]): a for a in items}


def test_platform_works_without_threat_intel(
    login: Callable[..., LoggedIn],
    session_factory: sessionmaker[Session],
    scenario: dict[str, Any],
) -> None:
    analyst = login("ana", Role.ANALYST)
    feeds = analyst.client.get("/api/v1/threat-intel/feeds").json()
    assert [(f["feed_key"], f["indicator_count"]) for f in feeds] == [("local-csv", 0)]
    summary = _correlate(analyst, session_factory)
    assert summary["rules"]["ti_match_active"]["evidence_available"] == {"match": 0}
    # No classifier is active in this test, so model-based steps have no evidence.
    assert summary["rules"]["recon_then_attack"]["evidence_available"] == {
        "recon": 0,
        "attack": 0,
    }
    alerts = _alerts(analyst)
    assert ("bruteforce_then_success", "svc-backup") in alerts
    assert ("repeated_ids_signature", "203.0.113.88") in alerts
    assert not any(key[0] == "ti_match_active" for key in alerts)


def test_indicator_import_matching_and_correlation(
    login: Callable[..., LoggedIn],
    db: Session,
    session_factory: sessionmaker[Session],
    scenario: dict[str, Any],
) -> None:
    admin = login("root", Role.ADMIN)
    run = _import_and_match(admin, db, session_factory, scenario["indicators_csv"])
    assert run["indicators_received"] == 5
    assert run["indicators_created"] == 5 and run["indicators_rejected"] == 0

    indicators = admin.client.get("/api/v1/threat-intel/indicators").json()["items"]
    by_value = {i["value_normalized"]: i for i in indicators}
    url = by_value["http://payload.example.test/a.bin"]
    assert url["display_value"] == "hxxp://payload[.]example[.]test/a[.]bin"
    assert by_value["203.0.113.200"]["state"] == "expired"

    planted = next(p for p in scenario["planted"] if p["pattern"] == "indicator_matches")
    for expected in planted["indicators"]:
        indicator = by_value[expected["value"]]
        matches = admin.client.get(
            "/api/v1/threat-intel/matches",
            params={"indicator_id": indicator["indicator_id"], "limit": 500},
        ).json()
        fields = {m["matched_field"] for m in matches["items"]}
        assert len(matches["items"]) == expected["expected_matches"], expected
        assert fields == {expected["matched_field"]}
        assert {m["indicator_state_at_match"] for m in matches["items"]} == {"active"}
        assert "not proof of compromise" in matches["note"]

    # Matching is idempotent.
    again = admin.client.post(
        "/api/v1/threat-intel/match-runs", json=RANGE, headers=admin.headers()
    )
    _run_worker(session_factory)
    job = admin.client.get(f"/api/v1/jobs/{again.json()['job_id']}").json()
    assert job["result"]["matches_created"] == 0

    summary = _correlate(admin, session_factory)
    alerts = _alerts(admin)
    ti_alert = alerts[("ti_match_active", planted["entity"])]
    assert ti_alert["severity"] in ("medium", "high", "critical")
    detail = admin.client.get(f"/api/v1/alerts/{ti_alert['alert_id']}").json()
    breakdown = detail["risk_breakdown"]
    assert breakdown["components"]["threat_intel"]["value"] > 0
    assert breakdown["score"] == detail["risk_score"]
    assert {e["category"] for e in detail["evidence"]} == {"threat_intel_match"}
    assert all(e["event_id"] and e["link"].endswith(e["event_id"]) for e in detail["evidence"])

    # Re-running correlation updates existing alerts instead of duplicating them.
    rerun = _correlate(admin, session_factory)
    assert rerun["alerts_created"] == 0
    assert rerun["alerts_updated"] == summary["alerts_created"] + summary["alerts_updated"]
    assert len(_alerts(admin)) == len(alerts)

    # Event detail shows threat-intel context separately from observed facts.
    event_ref = admin.client.get(
        "/api/v1/threat-intel/matches",
        params={"indicator_id": by_value["203.0.113.99"]["indicator_id"], "limit": 1},
    ).json()["items"][0]
    event = admin.client.get(f"/api/v1/events/{event_ref['event_id']}").json()
    assert event["threat_intel"]["matches"][0]["value_normalized"] == "203.0.113.99"
    assert {t["technique_id"] for t in event["threat_intel"]["attack_techniques"]} >= {"T1071"}
    assert any(a["alert_id"] == ti_alert["alert_id"] for a in event["alerts"])


def test_alert_case_and_feedback_workflow(
    login: Callable[..., LoggedIn],
    session_factory: sessionmaker[Session],
    scenario: dict[str, Any],
    db: Session,
) -> None:
    analyst = login("ana", Role.ANALYST)
    _correlate(analyst, session_factory)
    alerts = _alerts(analyst)
    brute = alerts[("bruteforce_then_success", "svc-backup")]
    ids = alerts[("repeated_ids_signature", "203.0.113.88")]
    url = f"/api/v1/alerts/{brute['alert_id']}"
    h = analyst.headers()

    assert analyst.client.patch(url, json={"status": "in_review"}, headers=h).status_code == 409
    resp = analyst.client.post(
        f"{url}/escalate", json={"new_case": {"title": "x" * 5, "severity": "high"}}, headers=h
    )
    assert resp.status_code == 409  # must be acknowledged first
    assert analyst.client.patch(url, json={"status": "acknowledged"}, headers=h).status_code == 200
    assert analyst.client.patch(url, json={"status": "in_review"}, headers=h).status_code == 200
    resp = analyst.client.post(
        f"{url}/escalate",
        json={"new_case": {"title": "Brute force on svc-backup", "severity": "high"}},
        headers=h,
    )
    assert resp.status_code == 200, resp.text
    case_id = resp.json()["case"]["case_id"]
    assert resp.json()["alert"]["status"] == "escalated"

    case_url = f"/api/v1/cases/{case_id}"
    assert (
        analyst.client.post(
            f"{case_url}/notes", json={"body": "checked VPN logs"}, headers=h
        ).status_code
        == 201
    )
    timeline = analyst.client.get(f"{case_url}/timeline").json()
    types = [e["entry_type"] for e in timeline]
    assert "alert_linked" in types and "note" in types and "evidence" in types
    times = [e["entry_time"] for e in timeline]
    assert times == sorted(times)

    resp = analyst.client.patch(case_url, json={"status": "closed"}, headers=h)
    assert resp.status_code == 422
    resp = analyst.client.patch(
        case_url, json={"status": "closed", "disposition": "confirmed_incident"}, headers=h
    )
    assert resp.status_code == 200 and resp.json()["confirmed_incident"] is True
    assert analyst.client.get(url).json()["status"] == "closed"
    assert (
        analyst.client.post(f"{case_url}/notes", json={"body": "late"}, headers=h).status_code
        == 409
    )

    # Dismissal needs a reason and records analyst feedback.
    ids_url = f"/api/v1/alerts/{ids['alert_id']}"
    assert analyst.client.patch(ids_url, json={"status": "dismissed"}, headers=h).status_code == 422
    resp = analyst.client.patch(
        ids_url,
        json={
            "status": "dismissed",
            "dismiss_reason": "authorised scanner",
            "verdict": "benign_unusual",
        },
        headers=h,
    )
    assert resp.status_code == 200 and resp.json()["dismiss_reason"] == "authorised scanner"

    resp = analyst.client.post(
        "/api/v1/feedback",
        json={
            "target_type": "alert",
            "target_id": brute["alert_id"],
            "verdict": "true_positive",
            "comment": "confirmed with owner",
        },
        headers=h,
    )
    assert resp.status_code == 201 and resp.json()["kind"] == "analyst_conclusion"
    bad = analyst.client.post(
        "/api/v1/feedback",
        json={"target_type": "event", "target_id": "999999999", "verdict": "false_positive"},
        headers=h,
    )
    assert bad.status_code == 404
    summary = analyst.client.get("/api/v1/feedback/summary").json()
    counts = {(r["rule_key"], r["verdict"]): r["count"] for r in summary["by_rule"]}
    assert counts == {
        ("bruteforce_then_success", "true_positive"): 1,
        ("repeated_ids_signature", "benign_unusual"): 1,
    }

    # A new matching sequence after closure opens a new alert linked to the old one.
    rerun = _correlate(analyst, session_factory)
    assert rerun["rules"]["bruteforce_then_success"]["alerts_created"] == 1
    fresh = analyst.client.get(
        "/api/v1/alerts", params={"rule_key": "bruteforce_then_success", "status": "new"}
    ).json()["items"]
    assert fresh[0]["related_alert_id"] == brute["alert_id"]

    with db.begin():
        actions = set(db.scalars(select(AuditLog.action)))
    assert {
        "alert.created",
        "alert.updated",
        "case.created",
        "case.alert_linked",
        "case.note_added",
        "case.updated",
        "feedback.created",
        "correlation.run",
    } <= actions


def test_rule_management_versions_and_validation(
    login: Callable[..., LoggedIn], seeded: Session
) -> None:
    admin = login("root", Role.ADMIN)
    h = admin.headers()
    rules = admin.client.get("/api/v1/correlation/rules").json()
    assert len(rules) == 5 and all(r["version"] == 1 for r in rules)
    bad = admin.client.post(
        "/api/v1/correlation/rules",
        json={
            "key": "evil_rule",
            "name": "evil",
            "description": "sql injection attempt",
            "entity_type": "account",
            "window": "1h",
            "base_severity": "low",
            "steps": [{"id": "a", "evidence": "event", "where": {"raw": "1=1; drop table"}}],
        },
        headers=h,
    )
    assert bad.status_code == 422
    base = next(r for r in rules if r["rule_key"] == "repeated_ids_signature")
    body = {
        "name": base["name"],
        "description": base["description"],
        "base_severity": "medium",
        **base["definition"],
    }
    body["steps"][0]["min_count"] = 10
    resp = admin.client.put(
        "/api/v1/correlation/rules/repeated_ids_signature", json=body, headers=h
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["version"] == 2
    versions = admin.client.get("/api/v1/correlation/rules/repeated_ids_signature/versions").json()
    assert [v["version"] for v in versions] == [1, 2]
    resp = admin.client.patch(
        "/api/v1/correlation/rules/repeated_ids_signature", json={"enabled": False}, headers=h
    )
    assert resp.json()["enabled"] is False


def test_stix_import_reports_unsupported_patterns(
    login: Callable[..., LoggedIn],
    db: Session,
    session_factory: sessionmaker[Session],
    seeded: Session,
) -> None:
    admin = login("root", Role.ADMIN)
    bundle = {
        "type": "bundle",
        "id": "bundle--x",
        "objects": [
            {
                "type": "indicator",
                "id": "indicator--1",
                "pattern_type": "stix",
                "pattern": "[domain-name:value = 'c2.example.test']",
                "confidence": 60,
                "valid_from": "2026-01-01T00:00:00Z",
            },
            {
                "type": "indicator",
                "id": "indicator--2",
                "pattern_type": "stix",
                "pattern": "[ipv4-addr:value = '1.2.3.4'] AND [ipv4-addr:value = '5.6.7.8']",
            },
        ],
    }
    resp = admin.client.post(
        "/api/v1/threat-intel/imports",
        data={"feed_id": _local_feed(db), "format": "stix"},
        files={"file": ("bundle.json", json.dumps(bundle).encode(), "application/json")},
        headers=admin.headers(),
    )
    assert resp.status_code == 202, resp.text
    _run_worker(session_factory)
    run = admin.client.get(f"/api/v1/threat-intel/imports/{resp.json()['id']}").json()
    assert run["indicators_created"] == 1
    assert run["report"]["unsupported_patterns"][0]["stix_id"] == "indicator--2"
    assert "stored_path" not in run["report"]

    wrong = admin.client.post(
        "/api/v1/threat-intel/imports",
        data={"feed_id": _local_feed(db), "format": "csv"},
        files={"file": ("bundle.json", b"{}", "application/json")},
        headers=admin.headers(),
    )
    assert wrong.status_code == 415
    sync = admin.client.post(
        f"/api/v1/threat-intel/feeds/{_local_feed(db)}/sync", headers=admin.headers()
    )
    assert sync.status_code == 409 and "Phase 8" in sync.json()["detail"]


@pytest.fixture
def no_network(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    def refuse(*args: Any, **kwargs: Any) -> None:
        raise AssertionError(f"unexpected outbound connection: {args!r}")

    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket.socket, "connect", refuse)
    yield


def test_import_match_and_correlate_make_no_network_calls(
    session_factory: sessionmaker[Session],
    db: Session,
    scenario: dict[str, Any],
    no_network: None,
) -> None:
    settings = get_settings()
    feed_id = threat_intel.feed_id_for_key(db, "local-csv")
    path: Path = scenario["indicators_csv"]
    run = threat_intel.start_import(
        db,
        settings,
        CLI_ACTOR,
        feed_id=feed_id,
        fmt="csv",
        filename=path.name,
        data=path.read_bytes(),
        enqueue=False,
    )
    done = threat_intel.run_import(session_factory, settings, run.feed_run_id)
    assert done.status == "succeeded"
    result = threat_intel.run_match(session_factory, {**RANGE, "batch_ids": []}, None)
    assert result["matches_created"] > 0
    from datetime import datetime

    summary = correlation.run_correlation(
        db,
        CLI_ACTOR,
        datetime.fromisoformat("2026-01-01T00:00:00+00:00"),
        datetime.fromisoformat("2026-01-11T00:00:00+00:00"),
    )
    assert summary["rules"]["ti_match_active"]["alerts_created"] >= 1


def _technique(tid: str, name: str, **extra: Any) -> dict[str, Any]:
    return {
        "type": "attack-pattern",
        "id": f"attack-pattern--{tid}",
        "name": name,
        "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "discovery"}],
        "external_references": [{"source_name": "mitre-attack", "external_id": tid}],
        **extra,
    }


def test_attack_import_validates_category_mappings(
    login: Callable[..., LoggedIn], db: Session, seeded: Session
) -> None:
    bundle = {
        "type": "bundle",
        "id": "bundle--attack",
        "objects": [
            {"type": "x-mitre-collection", "x_mitre_version": "test-1"},
            _technique("T1046", "Network Service Discovery"),
            _technique("T1110", "Brute Force", revoked=True),
        ],
    }
    result = threat_intel.import_attack(db, CLI_ACTOR, json.dumps(bundle).encode())
    assert result["techniques"] == 2 and result["attack_version"] == "test-1"
    assert result["mappings_applied"] == 1
    skipped = {s["technique_id"]: s["reason"] for s in result["mappings_skipped"]}
    assert skipped["T1110"] == "technique deprecated or revoked"
    assert skipped["T1595"] == "technique not in imported ATT&CK data"

    viewer = login("val", Role.VIEWER)
    categories = {c["code"]: c for c in viewer.client.get("/api/v1/attack/categories").json()}
    recon = categories["RECONNAISSANCE"]["techniques"]
    assert [t["technique_id"] for t in recon] == ["T1046"]
    assert recon[0]["rationale"] and recon[0]["mapping_confidence"] == "medium"
    assert categories["BRUTE_FORCE"]["techniques"] == []
    found = viewer.client.get("/api/v1/attack/techniques", params={"q": "network"}).json()
    assert [t["technique_id"] for t in found] == ["T1046"]
