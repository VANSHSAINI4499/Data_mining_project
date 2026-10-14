"""Adapter tests on synthetic files that reproduce each format's structure and quirks.

Values are synthetic (documentation IP ranges); no rows are copied from public datasets.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.models import (
    DimAsset,
    EventGroundTruth,
    FactSecurityEvent,
    IngestionBatch,
    RejectedRecord,
)
from app.services import assets as assets_service
from app.services.actors import CLI_ACTOR
from app.services.ingestion import BatchOptions
from tests.integration.ingestion_helpers import add_source, ingest

pytestmark = pytest.mark.integration


def _events(db: Session, batch_id: Any) -> list[FactSecurityEvent]:
    with db.begin():
        rows = list(
            db.scalars(
                select(FactSecurityEvent)
                .where(FactSecurityEvent.batch_id == batch_id)
                .order_by(FactSecurityEvent.event_time)
            )
        )
        for r in rows:
            db.expunge(r)
        return rows


def _rejections(db: Session, batch_id: Any) -> list[tuple[int, str]]:
    with db.begin():
        return [
            (r.record_number, r.error_code)
            for r in db.scalars(
                select(RejectedRecord)
                .where(RejectedRecord.batch_id == batch_id)
                .order_by(RejectedRecord.record_number)
            )
        ]


def _labels(db: Session, batch_id: Any) -> dict[str, tuple[str, bool | None]]:
    with db.begin():
        rows = db.execute(
            select(
                EventGroundTruth.label_raw,
                EventGroundTruth.mapping_status,
                EventGroundTruth.is_attack,
            )
            .join(
                FactSecurityEvent,
                (FactSecurityEvent.event_id == EventGroundTruth.event_id)
                & (FactSecurityEvent.event_time == EventGroundTruth.event_time),
            )
            .where(FactSecurityEvent.batch_id == batch_id)
        )
        return {label: (status, attack) for label, status, attack in rows}


def _meta(db: Session, batch_id: Any) -> dict[str, Any]:
    with db.begin():
        batch = db.get(IngestionBatch, batch_id)
        assert batch is not None
        return dict(batch.batch_metadata)


# --- Zeek ---

ZEEK_TSV = (
    "#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n"
    "#path\tconn\n"
    "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration"
    "\torig_bytes\tresp_bytes\tconn_state\tmissed_bytes\thistory\torig_pkts\torig_ip_bytes"
    "\tresp_pkts\tresp_ip_bytes\n"
    "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tstring"
    "\tcount\tstring\tcount\tcount\tcount\tcount\n"
    "1767607200.123456\tCabc1\t192.0.2.10\t51544\t198.51.100.7\t22\ttcp\tssh\t1.5\t2048\t512"
    "\tSF\t0\tShAdDaFf\t12\t2600\t9\t1000\n"
    "1767607201.000000\tCabc2\t192.0.2.11\t53000\t198.51.100.8\t53\tudp\t-\t-\t-\t-\tS0\t0"
    "\tD\t1\t60\t0\t0\n"
    "1767607202.000000\tCabc3\tnot-an-ip\t1\t198.51.100.8\t53\tudp\t-\t-\t-\t-\tS0\t0\tD\t1"
    "\t60\t0\t0\n"
    "1767607203.000000\tCabc4\ttoo-few-fields\n"
    "#close\t2026-01-05-10-00-00\n"
)


def test_zeek_tsv(
    session_factory: sessionmaker[Session], seeded: Session, import_root: Path, db: Session
) -> None:
    add_source(db, "zeek", "zeek_conn")
    path = import_root / "conn.log"
    path.write_text(ZEEK_TSV, encoding="utf-8")
    outcome = ingest(session_factory, path, "zeek")
    assert (outcome.records_total, outcome.records_loaded, outcome.records_rejected) == (4, 2, 2)
    first, second = _events(db, outcome.batch_id)
    assert (first.source_event_id, str(first.src_ip), first.dst_port) == ("Cabc1", "192.0.2.10", 22)
    assert (first.protocol, first.app_protocol, first.bytes_out, first.packets_in) == (
        "tcp",
        "ssh",
        2048,
        9,
    )
    assert first.time_quality == "exact"
    assert first.attributes["history"] == "ShAdDaFf" and first.attributes["orig_ip_bytes"] == "2600"
    assert second.app_protocol is None and second.duration_s is None  # "-" means unset
    assert _rejections(db, outcome.batch_id) == [(3, "INVALID_IP"), (4, "WRONG_FIELD_COUNT")]


def test_zeek_json_and_missing_fields_header(
    session_factory: sessionmaker[Session], seeded: Session, import_root: Path, db: Session
) -> None:
    add_source(db, "zeek", "zeek_conn")
    row = {
        "ts": 1767607200.5,
        "uid": "Cj1",
        "id.orig_h": "192.0.2.10",
        "id.orig_p": 1,
        "id.resp_h": "198.51.100.7",
        "id.resp_p": 443,
        "proto": "tcp",
        "orig_bytes": 10,
    }
    path = import_root / "conn.json"
    path.write_text(json.dumps(row) + "\n", encoding="utf-8")
    ok = ingest(session_factory, path, "zeek")
    assert ok.records_loaded == 1 and _meta(db, ok.batch_id)["variant"] == "json"

    bad = import_root / "nofields.log"
    bad.write_text("#separator \\x09\n1\t2\t3\n", encoding="utf-8")
    failed = ingest(session_factory, bad, "zeek")
    assert failed.status == "failed"
    assert failed.error is not None and failed.error["code"] == "UNSUPPORTED_VARIANT"


# --- Suricata ---


def test_suricata_eve_types(
    session_factory: sessionmaker[Session], seeded: Session, import_root: Path, db: Session
) -> None:
    add_source(db, "ids", "suricata_eve")
    common = {
        "src_ip": "192.0.2.10",
        "src_port": 4000,
        "dest_ip": "198.51.100.7",
        "dest_port": 80,
        "proto": "TCP",
        "flow_id": 1234,
    }
    rows = [
        {
            **common,
            "timestamp": "2026-01-05T10:00:00.000001+0000",
            "event_type": "alert",
            "alert": {
                "signature_id": 2001219,
                "signature": "<script>alert(1)</script>",
                "category": "Attempted Information Leak",
                "severity": 2,
            },
        },
        {
            **common,
            "timestamp": "2026-01-05T10:00:01+0000",
            "event_type": "flow",
            "flow": {
                "pkts_toserver": 5,
                "pkts_toclient": 4,
                "bytes_toserver": 500,
                "bytes_toclient": 400,
                "start": "2026-01-05T09:59:00+0000",
                "end": "2026-01-05T10:00:01+0000",
            },
        },
        {
            **common,
            "timestamp": "2026-01-05T10:00:02+0000",
            "event_type": "dns",
            "dns": {"rrname": "Example.TEST."},
        },
        {
            **common,
            "timestamp": "2026-01-05T10:00:03+0000",
            "event_type": "http",
            "http": {"hostname": "portal.example.test", "url": "/login.php?id=1"},
        },
        {
            **common,
            "timestamp": "2026-01-05T10:00:04+0000",
            "event_type": "tls",
            "tls": {"sni": "x.example.test"},
        },
        {**common, "timestamp": "2026-01-05T10:00:05+0000", "event_type": "alert", "alert": {}},
        {**common, "timestamp": "2026-01-05T10:00:06+0000"},
    ]
    path = import_root / "eve.json"
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    outcome = ingest(session_factory, path, "ids")
    assert (outcome.records_loaded, outcome.records_rejected) == (5, 2)
    events = {e.event_type: e for e in _events(db, outcome.batch_id)}
    alert = events["ids_alert"]
    assert alert.signature_id == 2001219 and alert.signature == "<script>alert(1)</script>"
    assert alert.source_severity == 2 and alert.protocol == "tcp"
    flow = events["network_flow"]
    assert (flow.packets_out, flow.bytes_in) == (5, 400)
    assert flow.event_time.isoformat() == "2026-01-05T09:59:00+00:00"
    assert events["dns"].dns_query == "example.test"
    assert events["http"].url == "/login.php?id=1"
    assert events["other"].attributes["eve_event_type"] == "tls"
    assert _rejections(db, outcome.batch_id) == [
        (6, "MISSING_REQUIRED_FIELD"),
        (7, "MISSING_REQUIRED_FIELD"),
    ]


# --- auth and endpoint ---


def test_auth_and_endpoint_jsonl(
    session_factory: sessionmaker[Session], seeded: Session, import_root: Path, db: Session
) -> None:
    add_source(db, "auth", "auth_jsonl")
    add_source(db, "edr", "endpoint_jsonl")
    auth_rows = [
        {
            "timestamp": "2026-03-01T10:15:02Z",
            "user_name": "alice",
            "auth_result": "failure",
            "auth_method": "password",
            "src_ip": "192.0.2.10",
            "host_name": "srv-01",
            "service": "sshd",
            "label_raw": "BRUTE_FORCE",
            "session": "s1",
        },
        {"timestamp": "2026-03-01T10:15:03Z", "user_name": "alice"},
        {"user_name": "bob", "auth_result": "success"},
    ]
    auth_path = import_root / "auth.jsonl"
    auth_path.write_text("\n".join(json.dumps(r) for r in auth_rows), encoding="utf-8")
    auth = ingest(session_factory, auth_path, "auth")
    assert (auth.records_loaded, auth.records_rejected) == (1, 2)
    (event,) = _events(db, auth.batch_id)
    assert event.auth_method == "password" and event.attributes == {"session": "s1"}
    assert _labels(db, auth.batch_id) == {"BRUTE_FORCE": ("mapped", None)}

    endpoint_rows = [
        {
            "timestamp": "2026-03-01T11:00:00Z",
            "host_name": "ws-042",
            "event_action": "process_start",
            "process_name": "powershell.exe",
            "process_command_line": "powershell -enc AAAA; rm -rf /",
            "parent_process_name": "winword.exe",
            "user_name": "carol",
        },
        {
            "timestamp": "2026-03-01T11:00:01Z",
            "host_name": "ws-042",
            "event_action": "file_create",
            "file_path": "C:\\Users\\Public\\a.dll",
            "file_sha256": "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
        },
        {"timestamp": "2026-03-01T11:00:02Z", "host_name": "ws-042", "event_action": "teleport"},
        {
            "timestamp": "2026-03-01T11:00:03Z",
            "event_action": "network_connect",
            "dst_ip": "203.0.113.9",
        },
    ]
    ep_path = import_root / "edr.jsonl"
    ep_path.write_text("\n".join(json.dumps(r) for r in endpoint_rows), encoding="utf-8")
    ep = ingest(session_factory, ep_path, "edr")
    assert (ep.records_loaded, ep.records_rejected) == (2, 2)
    proc, file_event = _events(db, ep.batch_id)
    assert proc.event_type == "endpoint_process"
    assert proc.process_command_line == "powershell -enc AAAA; rm -rf /"  # stored inertly
    assert (
        file_event.file_sha256 == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    assert _rejections(db, ep.batch_id) == [
        (3, "UNKNOWN_EVENT_TYPE"),
        (4, "MISSING_REQUIRED_FIELD"),
    ]


# --- CIC-IDS2017 ---

CIC_IDS_HEADER = (
    "Flow ID, Source IP, Source Port, Destination IP, Destination Port, Protocol, Timestamp,"
    " Flow Duration, Total Fwd Packets, Total Backward Packets,Total Length of Fwd Packets,"
    " Total Length of Bwd Packets, Fwd Header Length,Flow Bytes/s, Flow Packets/s,"
    " Fwd Header Length, Label"
)


def _cic_row(ts: str, label: str, **over: str) -> str:
    v = {
        "id": "192.0.2.10-198.51.100.7-40000-22-6",
        "src": "192.0.2.10",
        "sport": "40000",
        "dst": "198.51.100.7",
        "dport": "22",
        "proto": "6",
        "ts": ts,
        "dur": "1500000",
        "fp": "10",
        "bp": "8",
        "fl": "1200",
        "bl": "900",
        "fh": "200",
        "bps": "1400.5",
        "pps": "12",
        "fh2": "200",
        "label": label,
    }
    v.update(over)
    return ",".join(
        v[k]
        for k in (
            "id",
            "src",
            "sport",
            "dst",
            "dport",
            "proto",
            "ts",
            "dur",
            "fp",
            "bp",
            "fl",
            "bl",
            "fh",
            "bps",
            "pps",
            "fh2",
            "label",
        )
    )


def test_cicids2017_flows_with_ids(
    session_factory: sessionmaker[Session], seeded: Session, import_root: Path, db: Session
) -> None:
    lines = [
        CIC_IDS_HEADER,
        _cic_row("5/7/2017 8:55", "BENIGN"),
        _cic_row("5/7/2017 8:56", "SSH-Patator", bps="Infinity", pps="NaN"),
        _cic_row("13/7/2017 9:00", "Web Attack \x96 Brute Force"),  # cp1252 en dash
        _cic_row("5/7/2017 9:01", "Strange-New-Label"),
        _cic_row("bogus", "BENIGN"),
    ]
    path = import_root / "Wednesday.csv"
    # latin-1 turns U+0096 into byte 0x96: an en dash in cp1252 and invalid as UTF-8.
    path.write_bytes(b"\r\n".join(line.encode("latin-1") for line in lines) + b"\r\n")
    with db.begin():
        from app.models import DimSource

        src = db.scalar(select(DimSource).where(DimSource.source_key == "cicids2017"))
        assert src is not None and src.default_timezone is None

    # 1. timezone never configured -> refused
    refused = ingest(session_factory, path, "cicids2017")
    assert refused.error is not None and refused.error["code"] == "TIMEZONE_NOT_CONFIGURED"

    # 2. ambiguous day/month without --date-order -> refused (new file name, same content is a
    #    duplicate only when the earlier batch did not fail; re-register via a copy)
    copy = import_root / "Wednesday2.csv"
    copy.write_bytes(path.read_bytes() + b"\r\n")
    ambiguous = ingest(
        session_factory, copy, "cicids2017", options=BatchOptions(timezone="America/Halifax")
    )
    assert ambiguous.error is not None and ambiguous.error["code"] == "TIMESTAMP_FORMAT_AMBIGUOUS"

    # 3. explicit order -> loads; 13/7 is unambiguous and consistent with dmy
    copy2 = import_root / "Wednesday3.csv"
    copy2.write_bytes(path.read_bytes() + b"\r\n\r\n")
    ok = ingest(
        session_factory,
        copy2,
        "cicids2017",
        options=BatchOptions(timezone="America/Halifax", date_order="dmy"),
    )
    assert (ok.records_total, ok.records_loaded, ok.records_rejected) == (5, 4, 1)
    events = _events(db, ok.batch_id)
    assert events[0].event_time.isoformat() == "2017-07-05T11:55:00+00:00"  # ADT = UTC-3
    assert events[0].duration_s == pytest.approx(1.5)  # microseconds -> seconds
    assert (events[0].packets_out, events[0].bytes_in, events[0].ip_proto) == (10, 900, 6)
    patator = next(e for e in events if e.event_time.minute == 56)
    assert patator.attributes["flow_bytes_s"] is None  # Infinity stored as null
    meta = _meta(db, ok.batch_id)
    assert meta["variant"] == "flows_with_ids"
    assert meta["duplicated_headers"] == ["fwd header length__2"]
    assert meta["non_finite_values"] == 2
    assert meta["encodings"].get("cp1252", 0) >= 1
    labels = _labels(db, ok.batch_id)
    assert labels["SSH-Patator"] == ("mapped", None)
    assert labels["Web Attack \u2013 Brute Force"][0] == "mapped"
    assert labels["Strange-New-Label"][0] == "unmapped"
    assert _rejections(db, ok.batch_id) == [(5, "INVALID_TIMESTAMP")]


def test_cicids2017_features_only_requires_assumed_date(
    session_factory: sessionmaker[Session], seeded: Session, import_root: Path, db: Session
) -> None:
    header = (
        " Destination Port, Flow Duration, Total Fwd Packets, Total Backward Packets,"
        "Total Length of Fwd Packets, Total Length of Bwd Packets, Label"
    )
    body = [header, "80,1000,1,1,10,10,BENIGN", "80,1000,1,1,10,10,BENIGN", "22,5,1,0,0,0,DDoS"]
    path = import_root / "ml.csv"
    path.write_text("\n".join(body) + "\n", encoding="utf-8")
    missing = ingest(session_factory, path, "cicids2017")
    assert missing.error is not None and missing.error["code"] == "MISSING_OPTION"

    copy = import_root / "ml2.csv"
    copy.write_text("\n".join(body) + "\n\n", encoding="utf-8")
    from datetime import date

    ok = ingest(
        session_factory,
        copy,
        "cicids2017",
        options=BatchOptions(assume_event_date=date(2017, 7, 3)),
    )
    # identical feature rows are real repeated rows: both are kept (record number in fingerprint)
    assert (ok.records_loaded, ok.records_duplicate) == (3, 0)
    assert {e.time_quality for e in _events(db, ok.batch_id)} == {"assumed"}
    assert _meta(db, ok.batch_id)["variant"] == "features_only"


def test_cicids2017_unsupported_header(
    session_factory: sessionmaker[Session], seeded: Session, import_root: Path
) -> None:
    path = import_root / "other.csv"
    path.write_text("a,b,c\n1,2,3\n", encoding="utf-8")
    failed = ingest(session_factory, path, "cicids2017")
    assert failed.error is not None and failed.error["code"] == "UNSUPPORTED_VARIANT"
    assert "destination port" in failed.error["detail"]


# --- UNSW-NB15 ---

UNSW_PARTITION_HEADER = (
    "id,dur,proto,service,state,spkts,dpkts,sbytes,dbytes,rate,sttl,attack_cat,label"
)


def test_unsw_partition(
    session_factory: sessionmaker[Session], seeded: Session, import_root: Path, db: Session
) -> None:
    from datetime import date

    rows = [
        UNSW_PARTITION_HEADER,
        "1,0.12,tcp,-,FIN,6,4,258,172,74.08,252,Normal,0",
        "2,0.5,udp,dns,INT,2,0,114,0,inf,254,Generic,1",
        "3,0.5,udp,dns,INT,2,0,114,0,1.0,254,Backdoors ,1",
        "4,0.5,udp,dns,INT,2,0,114,0,1.0,254,,0",
        "5,0.5,udp,dns,INT,2,0,114,0,1.0,254,,1",
        "6,0.5,udp,dns,INT,2,0,114,0,1.0,254,Exploits,0",
        "7,0.5,udp,dns,INT,2,0,114,0,1.0,254,Exploits,maybe",
    ]
    path = import_root / "UNSW_NB15_training-set.csv"
    path.write_text("\n".join(rows) + "\n", encoding="utf-8")
    ok = ingest(
        session_factory,
        path,
        "unsw-nb15",
        options=BatchOptions(assume_event_date=date(2015, 1, 22), dataset_partition="training"),
    )
    assert (ok.records_loaded, ok.records_rejected) == (6, 1)
    labels = _labels(db, ok.batch_id)
    assert labels["Normal"] == ("mapped", False)
    assert labels["Generic"] == ("mapped", True)
    assert labels["Backdoors"] == ("mapped", True)
    assert labels["Exploits"] == ("ambiguous", False)  # category contradicts label = 0
    meta = _meta(db, ok.batch_id)
    assert meta["variant"] == "partition" and meta["dataset_partition"] == "training"
    assert meta["non_finite_values"] == 1
    events = _events(db, ok.batch_id)
    assert {e.time_quality for e in events} == {"assumed"}
    assert events[0].app_protocol in (None, "dns")
    with db.begin():
        statuses = sorted(db.scalars(select(EventGroundTruth.mapping_status)))
    assert statuses.count("ambiguous") == 2  # "" with label 1, and Exploits with label 0


def test_unsw_raw_records_use_column_spec(
    session_factory: sessionmaker[Session], seeded: Session, import_root: Path, db: Session
) -> None:
    from app.ingestion.adapters.datasets import unsw_raw_columns

    columns = unsw_raw_columns()
    assert len(columns) == 49

    def raw_row(**over: str) -> str:
        values = {c: "0" for c in columns}
        values.update(
            srcip="192.0.2.10",
            sport="1390",
            dstip="198.51.100.7",
            dsport="53",
            proto="udp",
            state="CON",
            dur="0.001",
            sbytes="132",
            dbytes="164",
            spkts="2",
            dpkts="2",
            service="dns",
            stime="1421927414",
            ltime="1421927415",
            attack_cat="",
            label="0",
        )
        values.update(over)
        return ",".join(values[c] for c in columns)

    rows = [
        raw_row(),
        raw_row(sport="1391", dsport="0x000b", attack_cat="Exploits", label="1"),
        raw_row(sport="1392", dsport="-"),
        "192.0.2.1,1,2",
    ]
    path = import_root / "UNSW-NB15_1.csv"
    path.write_text("\n".join(rows) + "\n", encoding="utf-8")
    ok = ingest(session_factory, path, "unsw-nb15")
    assert (ok.records_loaded, ok.records_rejected) == (3, 1)
    events = _events(db, ok.batch_id)
    assert events[0].event_time.isoformat() == "2015-01-22T11:50:14+00:00"
    assert events[0].event_end_time is not None
    ports = sorted((e.src_port, e.dst_port) for e in events)
    assert ports == [(1390, 53), (1391, 11), (1392, None)]  # hex port parsed, "-" is null
    assert _meta(db, ok.batch_id)["variant"] == "raw_records"
    assert _rejections(db, ok.batch_id) == [(4, "WRONG_FIELD_COUNT")]


# --- assets ---


def test_asset_import_scd2_and_event_linking(
    session_factory: sessionmaker[Session], seeded: Session, import_root: Path, db: Session
) -> None:
    csv_v1 = (
        b"asset_id,hostname,ip_address,criticality,owner,environment\n"
        b"srv-01,SRV-01,198.51.100.7,high,it,prod\nws-42,ws-042,,low,,\nbad,,999.1.1.1,low,,\n"
    )
    result = assets_service.import_assets_csv(db, CLI_ACTOR, csv_v1)
    assert (result.created, result.updated, len(result.rejected)) == (2, 0, 1)
    again = assets_service.import_assets_csv(db, CLI_ACTOR, csv_v1)
    assert (again.created, again.unchanged) == (0, 2)
    changed = assets_service.import_assets_csv(
        db,
        CLI_ACTOR,
        b"asset_id,hostname,ip_address,criticality\nsrv-01,srv-01,198.51.100.7,critical\n",
    )
    assert changed.updated == 1
    with db.begin():
        versions = db.scalars(
            select(DimAsset).where(DimAsset.asset_id == "srv-01").order_by(DimAsset.valid_from)
        ).all()
        assert [(v.criticality, v.is_current) for v in versions] == [
            ("high", False),
            ("critical", True),
        ]

    add_source(db, "zeek", "zeek_conn")
    path = import_root / "conn.log"
    path.write_text(ZEEK_TSV, encoding="utf-8")
    outcome = ingest(session_factory, path, "zeek")
    first = _events(db, outcome.batch_id)[0]
    # The 2026 event falls in the first version's validity (before the change was imported).
    assert first.dst_asset_key == versions[0].asset_key
    assert first.src_asset_key is None
