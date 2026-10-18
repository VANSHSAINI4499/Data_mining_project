# Performance measurements (NFR-03, NFR-04)

Measured on 2026-10-15 for [AC-7.6](../ACCEPTANCE_CRITERIA.md#phase-7--security-testing-deployment-documentation). All numbers below are **measured**; nothing is extrapolated.

## Environment

| Item | Value |
|---|---|
| Machine | Windows 11 laptop, AMD Ryzen (family 23 model 104), 12 logical CPUs |
| Database | PostgreSQL 18.6 (Scoop), local, default configuration, separate database `cti_bench` |
| Backend | Python 3.12.5, single `uvicorn` process, no `--reload`, log level WARNING |
| Client | `httpx` on the same machine (no network latency) |

## Important caveat: no public dataset

Neither UNSW-NB15 nor CIC-IDS2017 is present in this environment (AC-2.8 / AC-3.9 were also not run for this reason). NFR-03 names "the full UNSW-NB15 training partition (≈175k rows)". It was measured instead on a **synthetic file of comparable size** (`cti generate-synthetic --days 60 --flows-per-hour 200`, 180,784 canonical JSON lines). Throughput on the real dataset (CSV adapter, more columns) may differ and must be re-measured when the dataset is available.

## NFR-03 — CLI ingestion throughput

Command: `cti ingest --source synthetic data/bench/nfr03b/events.jsonl` (inline, includes normalisation, fingerprinting, raw-record storage, dedup, ground truth, and data-quality checks).

| Run | Loader | Rows | Wall time | Throughput |
|---|---|---:|---:|---:|
| 1 | multi-row `INSERT … RETURNING` (Phase 2 implementation) | 180,792 | 299.3 s | **604 rows/s** |
| 2 | `COPY` into a temporary table + `INSERT … SELECT … ON CONFLICT` (Phase 7) | 180,784 | 201.1 s | **899 rows/s** |
| 3 | 2026-10-18 changes below, defaults (`CTI_INGEST_CHUNK_SIZE=10000`, `CTI_INGEST_WRITERS=2`) — three consecutive runs | 180,784 | 78.7 / 92.6 / 84.6 s | **2,297 / 1,952 / 2,137 rows/s** (median 2,137) |

**Result (2026-10-18): the target of ≥ 2,000 rows/s is met at the median of three runs (2,137 rows/s), but not with a wide margin: one of the three runs reached 1,952 rows/s.** Runs vary by about ±10 % on this laptop; free RAM was below 1 GB during the measurements (other applications open). Wall time includes interpreter start-up (~4 s). Each run used a fresh database cloned from a migrated, seeded template (`cti_perf_tpl`), and the same synthetic file as run 2.

### What changed (2026-10-18), and why — each step measured on a 40,000-line slice

| Step | Finding | Effect |
|---|---|---|
| Profiling | Writing 40k `event_ground_truth` rows took 18.8 s — more than inserting the events. | — |
| Diagnosis | Not missing statistics (`ANALYZE` first: no change in the same transaction) and not the plan shape (`enable_seqscan=off`: no change). The per-row foreign-key check against the **partitioned** `fact_security_event` was being **re-planned for every row** (default plan cache mode picks custom plans), at ~0.45 ms per row. In psql on 40k rows: `force_custom_plan` 20.2 s, `force_generic_plan` 2.4 s. | — |
| Fix 1 | `SET LOCAL plan_cache_mode = force_generic_plan` in ingest transactions (generic plan prunes partitions at run time). | 40k slice 47.4 s → 30.7 s |
| Fix 2 | Read/normalise on one thread while one writer thread writes the previous chunk; build storable rows and serialise JSON on the reading thread; COPY raw records directly into `raw_record` (IDs read back via the `(batch_id, record_number)` index) instead of temp table + `INSERT … SELECT`. | full file 131.5 s → 111 s |
| Fix 3 | Two writer threads on separate connections, **committing strictly in order** (`_CommitOrder`); events already held by an uncommitted earlier chunk are counted as duplicates up front; partitions are created only with no write in flight; 30 s lock timeout per chunk as a backstop against cycles with other concurrent loads. | full file → ~98 s |
| Fix 4 | Exact-equivalent fast paths: cached IP canonicalisation (`lru_cache`), skip the JSON depth walk when the text has ≤ 64 opening brackets, ASCII fast path in NUL/surrogate escaping; chunk size 10,000. | full file → 79–93 s |

A first attempt — a writer thread that waited for its turn **while holding its transaction open** — deadlocked in the test suite when a later chunk inserted a duplicate event before the earlier chunk did (the wait was in Python, so PostgreSQL could not detect it). That is why duplicates against in-flight chunks are now resolved before writing.

**Equivalence check:** the 180k-row file was loaded once with the previous code (commit `fbd27b1`) and once with the new code into separate databases; checksums over all stored event columns, raw records (payload, text, record number ↔ event link), ground-truth labels, and the batch counters/metadata were **identical**.

Remaining cost on this machine (40k slice, writer thread): event insert into 11 indexes plus 6 foreign-key checks per row (~6.4 s, of which FK checks ~2.6 s), raw-record COPY (~5 s), ground truth (~2.4 s); reading/normalising ~9–11 s on the reading thread. Throughput on the real UNSW-NB15 CSV (more columns) has **not** been measured — the dataset is still not present.

## NFR-04 — API latency on ≈3M events

Data: the two synthetic files above (404,282 events), then replicated with SQL to **2,829,974 events** by copying them with `event_time` shifted in 70-day steps (`scripts/benchmarks/replicate_events.py`; benchmark database only). Statistics were refreshed with `ANALYZE`.

Script: `scripts/benchmarks/bench_api.py` — 40 requests per query (`limit=50`), then four cursor pages.

| Query (`GET /api/v1/events`) | p50 | p95 | max | Next pages (ms) |
|---|---:|---:|---:|---|
| 30-day range, no filter | 22.3 ms | 28.3 ms | 238.7 ms | 36.8, 23.5, 22.9, 22.9 |
| 30-day range, `src_ip` | 23.4 ms | 29.2 ms | 35.2 ms | 36.9, 33.0, 31.2, 30.8 |
| 30-day range, `event_type=auth` | 22.5 ms | 29.1 ms | 48.7 ms | 67.5, 55.4, 52.8, 52.5 |
| 30-day range, `dst_port=443` | 22.3 ms | 24.6 ms | 139.1 ms | 28.7, 25.0, 26.3, 24.7 |
| 30-day range, `user_name` | 19.8 ms | 24.3 ms | 31.9 ms | 40.3 |
| 396-day range, no filter | 27.3 ms | 30.4 ms | 37.1 ms | 51.2, 30.7, 29.2, 30.2 |
| 396-day range, `ip` (either side) | 29.4 ms | 31.0 ms | 37.8 ms | 46.5, 36.6, 34.4, 39.5 |

| Aggregation (20 requests) | p50 | p95 | max |
|---|---:|---:|---:|
| `GET /analytics/timeseries` (30 days, daily, by event type) | 275.2 ms | 710.5 ms | 710.5 ms |
| `GET /dashboard/overview` (30 days) | 123.1 ms | 480.7 ms | 480.7 ms |

**Result: met.** Paginated event queries stay well below the p95 < 1 s target. Aggregations are slower but also below 1 s at p95 for a 30-day range; wider aggregation ranges were not measured. No index was added in Phase 7 because no measured query needed one.

## Reproducing

```bash
# 1. benchmark database (role cti has CREATEDB): CREATE DATABASE cti_bench OWNER cti;
export CTI_DATABASE_URL=postgresql+psycopg://cti:<password>@localhost:5432/cti_bench
(cd backend && uv run alembic upgrade head)
uv run --project backend cti seed-reference
uv run --project backend cti generate-synthetic --seed 9 --days 60 --flows-per-hour 200 --out data/bench/nfr03b
time uv run --project backend cti ingest --source synthetic data/bench/nfr03b/events.jsonl
# 2. replicate to ~3M rows, start the API on port 8001, create a user "bench", then:
python scripts/benchmarks/replicate_events.py
python scripts/benchmarks/bench_api.py http://localhost:8001 <password-file>
```
