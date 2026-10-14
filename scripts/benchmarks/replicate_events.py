"""Benchmark only: replicate events in cti_bench with shifted times to reach ~3M rows.

Refuses to run unless CTI_DATABASE_URL ends in /cti_bench. Rows are copies of ingested
synthetic events with event_time shifted by 70-day steps; they are not new observations.
"""
import os, time
from sqlalchemy import create_engine, text
url = os.environ["CTI_DATABASE_URL"]
assert url.endswith("/cti_bench"), url
eng = create_engine(url)
with eng.begin() as c:
    cols = [r[0] for r in c.execute(text(
        "select column_name from information_schema.columns where table_name='fact_security_event' "
        "and column_name <> 'event_id' order by ordinal_position"))]
    base = c.scalar(text("select count(*) from fact_security_event"))
    lo, hi = c.execute(text("select min(event_time), max(event_time) from fact_security_event")).one()
print("base rows", base, lo, hi)
collist = ", ".join(f'"{x}"' for x in cols)
sel = ", ".join(f'"{x}"' if x != "event_time" else "event_time + make_interval(days => :shift)" for x in cols)
n = 0
copies = 1
while base * (copies + 1) < 3_100_000:
    copies += 1
for k in range(1, copies):
    shift = 70 * k
    t0 = time.time()
    with eng.begin() as c:
        c.execute(text("select ensure_event_partitions(:a, :b)"),
                  {"a": lo + __import__('datetime').timedelta(days=shift), "b": hi + __import__('datetime').timedelta(days=shift + 1)})
        r = c.execute(text(f"insert into fact_security_event ({collist}) select {sel} from fact_security_event "
                           f"where batch_id in (select batch_id from ingestion_batch) and event_time < :hi_orig"),
                      {"shift": shift, "hi_orig": hi + __import__('datetime').timedelta(seconds=1)})
        n += r.rowcount
    print("copy", k, "rows", r.rowcount, "secs", round(time.time() - t0, 1), flush=True)
with eng.begin() as c:
    c.execute(text("analyze fact_security_event"))
    print("total", c.scalar(text("select count(*) from fact_security_event")))
