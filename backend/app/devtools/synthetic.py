"""Deterministic synthetic security scenarios (TESTING_STRATEGY.md §3).

Produces canonical JSON lines with *planted, known* patterns plus benign background, a CSV of
synthetic indicators, and ``expected.json`` describing what later pipeline stages should find.
Everything is synthetic: documentation IP ranges (RFC 5737), ``.test`` domains, fictional
users. Same seed and parameters => byte-identical output.
"""

from __future__ import annotations

import json
import random
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

BASE_TIME = datetime(2026, 1, 1, tzinfo=UTC)
INTERNAL_HOSTS = [f"192.0.2.{i}" for i in range(10, 31)]
SERVERS = [f"198.51.100.{i}" for i in range(1, 11)]
SERVICE_PORTS = [(443, "https"), (80, "http"), (22, "ssh"), (53, "dns")]
USERS = ["alice", "bob", "carol", "dave", "erin"]

BRUTE_SRC, BRUTE_USER = "203.0.113.66", "svc-backup"
SCAN_SRC, SCAN_TARGET = "203.0.113.77", "198.51.100.20"
ANOMALY_USER = "mallory"
C2_IP, C2_DOMAIN, C2_HOST = "203.0.113.99", "c2.example.test", "192.0.2.20"
IDS_SRC, IDS_SIGNATURE = "203.0.113.88", 2001219


@dataclass
class Scenario:
    seed: int = 42
    days: int = 10
    flows_per_hour: int = 8
    events: list[dict[str, Any]] = field(default_factory=list)
    planted: list[dict[str, Any]] = field(default_factory=list)

    def iso(self, moment: datetime) -> str:
        return moment.isoformat().replace("+00:00", "Z")


def _flow(
    sc: Scenario,
    t: datetime,
    src: str,
    dst: str,
    port: int,
    label: str,
    rng: random.Random,
    *,
    sport: int | None = None,
    bytes_out: int | None = None,
) -> dict[str, Any]:
    return {
        "event_type": "network_flow",
        "event_time": sc.iso(t),
        "src_ip": src,
        "src_port": sport if sport is not None else rng.randint(32768, 60999),
        "dst_ip": dst,
        "dst_port": port,
        "protocol": "udp" if port == 53 else "tcp",
        "duration_s": round(rng.uniform(0.01, 5.0), 3),
        "bytes_out": bytes_out if bytes_out is not None else rng.randint(200, 20_000),
        "bytes_in": rng.randint(200, 80_000),
        "packets_out": rng.randint(2, 60),
        "packets_in": rng.randint(2, 80),
        "label_raw": label,
    }


def _auth(
    sc: Scenario, t: datetime, user: str, result: str, src: str, label: str
) -> dict[str, Any]:
    return {
        "event_type": "auth",
        "event_time": sc.iso(t),
        "user_name": user,
        "auth_result": result,
        "auth_method": "password",
        "src_ip": src,
        "host_name": "srv-auth-01",
        "service": "sshd",
        "label_raw": label,
    }


def _background(sc: Scenario, rng: random.Random) -> None:
    for hour in range(sc.days * 24):
        start = BASE_TIME + timedelta(hours=hour)
        busy = 7 <= start.hour < 19
        count = sc.flows_per_hour if busy else max(1, sc.flows_per_hour // 4)
        for _ in range(count):
            port, _svc = rng.choice(SERVICE_PORTS)
            t = start + timedelta(seconds=rng.randint(0, 3599))
            sc.events.append(
                _flow(sc, t, rng.choice(INTERNAL_HOSTS), rng.choice(SERVERS), port, "BENIGN", rng)
            )
        if busy and rng.random() < 0.5:
            user = rng.choice(USERS)
            t = start + timedelta(seconds=rng.randint(0, 3599))
            result = "failure" if rng.random() < 0.05 else "success"
            sc.events.append(_auth(sc, t, user, result, rng.choice(INTERNAL_HOSTS), "BENIGN"))
    # The anomaly account's normal behaviour: two daytime logins per day from one host.
    for day in range(sc.days):
        for hour in (9, 15):
            t = BASE_TIME + timedelta(days=day, hours=hour, minutes=rng.randint(0, 59))
            sc.events.append(_auth(sc, t, ANOMALY_USER, "success", "192.0.2.50", "BENIGN"))


def _plant_bruteforce(sc: Scenario, rng: random.Random) -> None:
    start = BASE_TIME + timedelta(days=sc.days - 2, hours=2)
    failures = 25
    for i in range(failures):
        t = start + timedelta(seconds=20 * i + rng.randint(0, 5))
        sc.events.append(_auth(sc, t, BRUTE_USER, "failure", BRUTE_SRC, "BRUTE_FORCE"))
    success_at = start + timedelta(seconds=20 * failures + 30)
    sc.events.append(_auth(sc, success_at, BRUTE_USER, "success", BRUTE_SRC, "BRUTE_FORCE"))
    sc.planted.append(
        {
            "pattern": "bruteforce_then_success",
            "entity_type": "account",
            "entity": BRUTE_USER,
            "src_ip": BRUTE_SRC,
            "failures": failures,
            "successes": 1,
            "window_start": sc.iso(start),
            "window_end": sc.iso(success_at),
            "expected_rule": "bruteforce_then_success",
        }
    )


def _plant_scan_then_exploit(sc: Scenario, rng: random.Random) -> None:
    start = BASE_TIME + timedelta(days=sc.days - 2, hours=14)
    ports = list(range(1, 201))
    for i, port in enumerate(ports):
        t = start + timedelta(seconds=i)
        sc.events.append(
            _flow(sc, t, SCAN_SRC, SCAN_TARGET, port, "RECONNAISSANCE", rng, bytes_out=60)
        )
    exploit_start = start + timedelta(minutes=30)
    for i in range(30):
        t = exploit_start + timedelta(seconds=10 * i)
        sc.events.append(_flow(sc, t, SCAN_SRC, SCAN_TARGET, 80, "EXPLOIT", rng))
    sc.planted.append(
        {
            "pattern": "recon_then_attack",
            "entity_type": "src_ip",
            "entity": SCAN_SRC,
            "target": SCAN_TARGET,
            "scan_flows": len(ports),
            "exploit_flows": 30,
            "window_start": sc.iso(start),
            "window_end": sc.iso(exploit_start + timedelta(seconds=290)),
            "expected_rule": "recon_then_attack",
        }
    )


def _plant_anomalous_account(sc: Scenario, rng: random.Random) -> None:
    start = BASE_TIME + timedelta(days=sc.days - 1, hours=3)
    sources = [f"203.0.113.{i}" for i in range(120, 130)]
    for i in range(40):
        t = start + timedelta(seconds=60 * i + rng.randint(0, 30))
        sc.events.append(
            _auth(sc, t, ANOMALY_USER, "success", sources[i % len(sources)], "OTHER_MALICIOUS")
        )
    sc.planted.append(
        {
            "pattern": "anomalous_account",
            "entity_type": "account",
            "entity": ANOMALY_USER,
            "logins": 40,
            "distinct_src_ips": len(sources),
            "window_start": sc.iso(start),
            "window_end": sc.iso(start + timedelta(hours=1)),
            "expected_window_size": "1h",
            "baseline": "two daytime logins per day from 192.0.2.50",
        }
    )


def _plant_c2(sc: Scenario, rng: random.Random) -> None:
    start = BASE_TIME + timedelta(days=sc.days - 3, hours=10)
    for i in range(5):
        t = start + timedelta(minutes=12 * i)
        sc.events.append(_flow(sc, t, C2_HOST, C2_IP, 443, "BOTNET", rng))
    for i in range(3):
        t = start + timedelta(minutes=12 * i, seconds=-1)
        sc.events.append(
            {
                "event_type": "dns",
                "event_time": sc.iso(t),
                "src_ip": C2_HOST,
                "dst_ip": "198.51.100.53",
                "dst_port": 53,
                "protocol": "udp",
                "dns_query": C2_DOMAIN,
                "label_raw": "BOTNET",
            }
        )
    sc.planted.append(
        {
            "pattern": "indicator_matches",
            "entity_type": "host",
            "entity": C2_HOST,
            "indicators": [
                {"type": "ipv4", "value": C2_IP, "expected_matches": 5, "matched_field": "dst_ip"},
                {
                    "type": "domain",
                    "value": C2_DOMAIN,
                    "expected_matches": 3,
                    "matched_field": "dns_query",
                },
            ],
            "window_start": sc.iso(start - timedelta(seconds=1)),
            "window_end": sc.iso(start + timedelta(minutes=48)),
            "expected_rule": "ti_match_active",
        }
    )


def _plant_ids(sc: Scenario, rng: random.Random) -> None:
    start = BASE_TIME + timedelta(days=sc.days - 2, hours=20)
    for i in range(8):
        t = start + timedelta(minutes=3 * i)
        sc.events.append(
            {
                "event_type": "ids_alert",
                "event_time": sc.iso(t),
                "src_ip": IDS_SRC,
                "src_port": rng.randint(32768, 60999),
                "dst_ip": rng.choice(SERVERS),
                "dst_port": 22,
                "protocol": "tcp",
                "signature_id": IDS_SIGNATURE,
                "signature": "SYNTHETIC SCAN Potential SSH Scan",
                "alert_category": "Attempted Information Leak",
                "source_severity": 2,
                "label_raw": "RECONNAISSANCE",
            }
        )
    sc.planted.append(
        {
            "pattern": "repeated_ids_signature",
            "entity_type": "src_ip",
            "entity": IDS_SRC,
            "signature_id": IDS_SIGNATURE,
            "alerts": 8,
            "window_start": sc.iso(start),
            "window_end": sc.iso(start + timedelta(minutes=21)),
            "expected_rule": "repeated_ids_signature",
        }
    )


def _indicators(sc: Scenario) -> str:
    first = sc.iso(BASE_TIME - timedelta(days=30))
    last = sc.iso(BASE_TIME + timedelta(days=sc.days))
    until = sc.iso(BASE_TIME + timedelta(days=sc.days + 60))
    expired = sc.iso(BASE_TIME - timedelta(days=1))
    header = (
        "indicator_type,value,confidence,first_seen,last_seen,valid_until,description,tlp,"
        "technique_ids"
    )
    rows = [
        f"ipv4,{C2_IP},80,{first},{last},{until},Synthetic C2 server,TLP:CLEAR,T1071",
        f"domain,{C2_DOMAIN},70,{first},{last},{until},Synthetic C2 domain,TLP:CLEAR,T1071",
        f"ipv4,{BRUTE_SRC},60,{first},{last},{until},Synthetic brute-force source,TLP:CLEAR,T1110",
        f"ipv4,203.0.113.200,90,{first},{expired},{expired},Synthetic expired indicator,TLP:CLEAR,",
        f"url,hxxp://payload.example[.]test/a.bin,50,{first},{last},{until},"
        "Synthetic defanged URL,TLP:CLEAR,",
    ]
    return "\n".join([header, *rows]) + "\n"


def generate(seed: int = 42, days: int = 10, flows_per_hour: int = 8) -> tuple[str, str, str]:
    """Returns (events_jsonl, indicators_csv, expected_json) as text."""
    if days < 4:
        raise ValueError("days must be at least 4 so planted patterns have history")
    rng = random.Random(seed)  # noqa: S311 (deterministic synthetic data, not security)
    sc = Scenario(seed=seed, days=days, flows_per_hour=flows_per_hour)
    _background(sc, rng)
    _plant_bruteforce(sc, rng)
    _plant_scan_then_exploit(sc, rng)
    _plant_anomalous_account(sc, rng)
    _plant_c2(sc, rng)
    _plant_ids(sc, rng)
    sc.events.sort(key=lambda e: (e["event_time"], json.dumps(e, sort_keys=True)))
    events = "".join(json.dumps(e, sort_keys=True, separators=(",", ":")) + "\n" for e in sc.events)
    by_type: dict[str, int] = {}
    by_label: dict[str, int] = {}
    for e in sc.events:
        by_type[e["event_type"]] = by_type.get(e["event_type"], 0) + 1
        by_label[e["label_raw"]] = by_label.get(e["label_raw"], 0) + 1
    expected = {
        "generator": "cti generate-synthetic",
        "seed": seed,
        "days": days,
        "flows_per_hour": flows_per_hour,
        "time_range": {"from": sc.iso(BASE_TIME), "to": sc.iso(BASE_TIME + timedelta(days=days))},
        "event_count": len(sc.events),
        "events_by_type": dict(sorted(by_type.items())),
        "events_by_label": dict(sorted(by_label.items())),
        "planted": sc.planted,
        "note": "Synthetic data only: RFC 5737 addresses, .test domains, fictional accounts.",
    }
    return events, _indicators(sc), json.dumps(expected, indent=2, sort_keys=True) + "\n"


def write(
    out_dir: Path, seed: int = 42, days: int = 10, flows_per_hour: int = 8
) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    events, indicators, expected = generate(seed, days, flows_per_hour)
    paths = {
        "events": out_dir / "events.jsonl",
        "indicators": out_dir / "synthetic_indicators.csv",
        "expected": out_dir / "expected.json",
    }
    for key, text in (("events", events), ("indicators", indicators), ("expected", expected)):
        paths[key].write_text(text, encoding="utf-8", newline="\n")
    return paths
