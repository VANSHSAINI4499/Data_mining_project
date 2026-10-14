"""NFR-04 benchmark: paginated event queries against a running API (cti_bench database).

Usage: python bench_api.py BASE_URL PASSWORD_FILE
Prints p50/p95/max latency per query type (wall time measured by the client, localhost).
"""

import json
import statistics
import sys
import time
from pathlib import Path

import httpx

base = sys.argv[1].rstrip("/") + "/api/v1"
password = Path(sys.argv[2]).read_text().strip()
RUNS = 40

QUERIES = {
    "events_30d_page1": {"from": "2026-01-15T00:00:00Z", "to": "2026-02-14T00:00:00Z"},
    "events_30d_src_ip": {"from": "2026-01-15T00:00:00Z", "to": "2026-02-14T00:00:00Z", "src_ip": "192.0.2.12"},
    "events_30d_event_type_auth": {"from": "2026-01-15T00:00:00Z", "to": "2026-02-14T00:00:00Z", "event_type": "auth"},
    "events_30d_dst_port": {"from": "2026-01-15T00:00:00Z", "to": "2026-02-14T00:00:00Z", "dst_port": "443"},
    "events_30d_user": {"from": "2026-01-15T00:00:00Z", "to": "2026-02-14T00:00:00Z", "user_name": "alice"},
    "events_400d_page1": {"from": "2026-01-01T00:00:00Z", "to": "2027-02-01T00:00:00Z"},
    "events_400d_ip_either": {"from": "2026-01-01T00:00:00Z", "to": "2027-02-01T00:00:00Z", "ip": "198.51.100.2"},
}


def session() -> httpx.Client:
    client = httpx.Client(timeout=60)
    resp = client.post(f"{base}/auth/login", json={"username": "bench", "password": password})
    resp.raise_for_status()
    return client


def pct(values: list[float], p: float) -> float:
    ordered = sorted(values)
    k = max(0, min(len(ordered) - 1, round(p / 100 * len(ordered) + 0.5) - 1))
    return ordered[k]


results = {}
for name, params in QUERIES.items():
    client = session()
    timings: list[float] = []
    for i in range(RUNS):
        t0 = time.perf_counter()
        resp = client.get(f"{base}/events", params={**params, "limit": 50})
        timings.append(time.perf_counter() - t0)
        assert resp.status_code == 200, resp.text
    # Cursor pages 2-5 of the same query.
    page_t: list[float] = []
    cursor = resp.json()["next_cursor"]
    for _ in range(4):
        if not cursor:
            break
        t0 = time.perf_counter()
        resp = client.get(f"{base}/events", params={**params, "limit": 50, "cursor": cursor})
        page_t.append(time.perf_counter() - t0)
        cursor = resp.json()["next_cursor"]
    results[name] = {
        "runs": RUNS,
        "rows_returned": len(resp.json()["items"]),
        "p50_ms": round(statistics.median(timings) * 1000, 1),
        "p95_ms": round(pct(timings, 95) * 1000, 1),
        "max_ms": round(max(timings) * 1000, 1),
        "next_pages_ms": [round(t * 1000, 1) for t in page_t],
    }
    print(name, json.dumps(results[name]), flush=True)
    client.close()

client = session()
for name, path, params in [
    ("timeseries_30d_by_type", "/analytics/timeseries", {"from": "2026-01-15T00:00:00Z", "to": "2026-02-14T00:00:00Z", "interval": "day", "group_by": "event_type"}),
    ("dashboard_overview_30d", "/dashboard/overview", {"from": "2026-01-15T00:00:00Z", "to": "2026-02-14T00:00:00Z"}),
]:
    timings = []
    for _ in range(20):
        t0 = time.perf_counter()
        resp = client.get(f"{base}{path}", params=params)
        timings.append(time.perf_counter() - t0)
        assert resp.status_code == 200, resp.text
    results[name] = {"runs": 20, "p50_ms": round(statistics.median(timings) * 1000, 1),
                     "p95_ms": round(pct(timings, 95) * 1000, 1), "max_ms": round(max(timings) * 1000, 1)}
    print(name, json.dumps(results[name]), flush=True)
