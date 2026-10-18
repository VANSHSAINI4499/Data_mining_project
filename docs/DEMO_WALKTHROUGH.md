# Live demo walkthrough (local web-attack detection)

This is a self-contained demonstration of the CTI pipeline detecting web attacks **live**, with
no external website, no deployment, and no file uploads. A small demo target site runs on this
machine, its access log is followed as it grows, and the dashboard shows classifications and
alerts within a few seconds.

Everything is local and synthetic: the demo site binds to `127.0.0.1` only and **never executes,
queries, or fetches** anything it receives — inputs are echoed back HTML-escaped and written to
an access log, which is what the pipeline analyses. Generated traffic uses documentation IP
ranges (RFC 5737). This is a detection demo, not a firewall.

## What it shows

- HTTP query-parameter values classified as `SQLI`, `XSS`, `PATH_TRAVERSAL`, `CMDI`, or `BENIGN`
  by the `web_attack_classifier` model.
- An **alert** per client IP that sends ≥ 2 attack-like values within an hour
  (`web_attack_payloads_from_client`).
- The event explorer, Classification page, and Alerts queue updating as new requests arrive.

## One-time setup

The database, migrations, and a **promoted** web payload model must exist (see
[DEPLOYMENT_GUIDE.md](../DEPLOYMENT_GUIDE.md) §4–5 and the web attack model card
[docs/models/web_attack_classifier.md](models/web_attack_classifier.md)):

```bash
cd backend && uv run alembic upgrade head && uv run cti seed-reference
uv run cti train web-payload --dataset-dir ../data/external/httpparams   # prints a model_id
uv run cti models promote <model_id>                                     # make it active
```

## Running the demo (four terminals)

Each command runs from the repository root; the backend ones need the `uv run --project backend`
prefix (or `cd backend` first). Start PostgreSQL first (`pg_ctl -D .local/pgdata start`).

1. **API + worker** (dashboard data, and automatic processing):

   ```bash
   uv run --project backend uvicorn app.main:app --port 8000
   uv run --project backend cti worker          # separate terminal
   ```

2. **Dashboard:** `cd frontend && npm run dev`, then open the printed URL and sign in. Turn on
   the **Live** switch in the top bar: the Classification page (summary and the scored-HTTP-
   parameters card) and the Alerts queue then refresh every 10 seconds on their own. Leave Live
   off for normal use, where each view loads once.

3. **Demo target site:**

   ```bash
   uv run --project backend cti demo-site
   ```

   Serves <http://127.0.0.1:8800> and writes `data/demo/demoshop.access.log`. Open it in a
   browser: the search, downloads, status, and login pages all take input.

4. **Live tailing** (imports new log lines, scores them, runs correlation):

   ```bash
   uv run --project backend cti tail --log data/demo/demoshop.access.log --from-end --process
   ```

## Driving traffic

**By hand (most convincing):** in the demo site, submit payloads into the forms, e.g.

- Search: `1' OR '1'='1' --` and `<script>alert(document.cookie)</script>`
- Status (`/ping`): `127.0.0.1; cat /etc/passwd`
- Downloads: `../../../../etc/passwd`

Within a few seconds each appears on the **Classification** page with its predicted class, and
after two attack-like values from the same browser an **alert** appears on the Alerts page. The
page itself only echoes your input as plain text — nothing runs.

**Automatically:** append a mix of benign and attack lines to the same log (pure log *data*,
sent nowhere):

```bash
uv run --project backend cti demo-traffic --count 60 --attack-ratio 0.3 --rate 4
```

`--rate 4` writes ~4 lines/second so you can watch the dashboard fill; omit it to write all at
once. The simulated attackers use distinct source IPs, so several alerts appear.

## Verifying it worked (optional, no dashboard)

```bash
uv run --project backend cti tail --log data/demo/demoshop.access.log --once --process
# the printed summary shows parameters_scored and alerts_created
```

## Resetting

Stop the four commands (Ctrl-C). `data/demo/` is git-ignored; delete it to start clean. Dropping
and recreating the database (DEPLOYMENT_GUIDE.md §10) clears all events, predictions, and alerts.

## Honesty notes for the presentation

- A prediction means "this value resembles the training payloads", **not** "this request
  succeeded or was malicious"; a security scanner produces the same signals. Scores are
  uncalibrated, not probabilities.
- Only query-string values are analysed — not POST bodies, headers, or cookies.
- The model was trained on a public dataset, so expect occasional false positives on unusual but
  legitimate input; mark them on the event page (feedback is stored separately and never
  overwrites a prediction).
