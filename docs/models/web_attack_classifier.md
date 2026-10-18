# Model card: `web_attack_classifier` (HTTP parameter payloads)

## What it does — and does not do

- **Input:** one HTTP parameter value as text (for example the value of `?q=`), up to 8,192 characters (longer values are truncated and flagged).
- **Output:** one of `BENIGN`, `SQLI` (SQL injection), `XSS` (cross-site scripting), `PATH_TRAVERSAL`, `CMDI` (OS command injection), plus per-class scores. Scores are **not calibrated probabilities**.
- **It does not** analyse full HTTP requests, headers, URLs, sessions, or access logs, does not see request timing or response codes, does not detect attack campaigns, and never blocks traffic. A prediction means "this value looks like the payloads in the training data", not "this request was an attack".
- It is separate from the network-flow `attack_classifier`: different task (`web_payload_classification`), different input schema, different artifact. Neither model is ever given the other's input.

## Data

| Item | Value |
|---|---|
| Source | Kaggle `evg3n1j/httpparamsdataset` (HTTPParamsDataset), downloaded with KaggleHub (public, no credentials needed) on 2026-10-15 |
| Local copy | `data/external/httpparams/` (git-ignored) |
| Training file | `payload_full.csv` (SHA-256 `a4e62ba1…f03d`), 31,067 rows; it is exactly `payload_train.csv` ∪ `payload_test.csv` |
| Excluded | 15 rows (all labelled `xss`) whose declared `length` ≠ actual length: CSV quoting broke and the next record — including the text `cmdi,anom` — was glued into the payload (label leakage) |
| Used | 31,052 rows: BENIGN 19,304 · SQLI 10,852 · XSS 517 · PATH_TRAVERSAL 290 · CMDI 89 |
| Label meaning | From the `attack_type` values and inspected examples (`norm`, `sqli`, `xss`, `path-traversal`, `cmdi`); no README was included in the download |
| Out-of-distribution file | `payload_test_lexical.csv` (1,106 rows: forum sentences vs SQL/JS *source code*, labels `sql-syntax`/`js-syntax`) — used only as a sanity check, not for training or model selection |

## Method

- **Split first:** `StratifiedGroupKFold` (seed 42): 20 % test, then 20 % of the rest as validation → train 19,873 / validation 4,969 / test 6,210 rows. Groups are *template signatures* (lower-case, digit runs → `0`, whitespace collapsed) so generated variants of one payload template never cross splits (27,949 groups; 0 cross-split groups). Pure-number benign values are grouped by exact value.
- **Features:** character n-gram TF-IDF (`char_wb`, 1–4, min_df 2, sublinear tf, ≤ 100k features), fitted on the training split only; final vocabulary 52,306.
- **Models:** stratified dummy baseline; Logistic Regression (`class_weight=balanced`, C=4); linear SVM (`class_weight=balanced`, C=0.5). Selection by validation macro-F1; the test split is used once afterwards. Random Forest was not used: on ~52k sparse n-gram features it adds cost without a clear benefit, and both linear models already saturate validation.

## Results (run `78df0678-5d1a-417c-9fc0-c9f92066b9a3`, held-out grouped test split, 6,210 rows)

| Model | Validation macro-F1 | Test macro-F1 | Test weighted-F1 | Test accuracy |
|---|---:|---:|---:|---:|
| dummy (stratified) | 0.2141 | 0.2148 | 0.5139 | 0.5148 |
| linear SVM | 1.0000 | 0.9835 | 0.9992 | 0.9992 |
| **logistic regression (selected)** | 1.0000 | **0.9835** | **0.9992** | 0.9992 |

Both linear models tie on validation (1.0); the tie is broken in favour of logistic regression. Test macro-F1 95 % bootstrap interval (1,000 resamples): 0.9586 – 0.9989.

| Class | Precision | Recall | F1 | Support |
|---|---:|---:|---:|---:|
| BENIGN | 0.9992 | 0.9997 | 0.9995 | 3,860 |
| SQLI | 1.0000 | 1.0000 | 1.0000 | 2,171 |
| XSS | 1.0000 | 0.9712 | 0.9854 | 104 |
| PATH_TRAVERSAL | 0.9831 | 1.0000 | 0.9915 | 58 |
| CMDI | 0.9412 | 0.9412 | 0.9412 | 17 |

Confusion matrix (rows = true, columns = predicted; order BENIGN, CMDI, PATH_TRAVERSAL, SQLI, XSS):

```
BENIGN          3859    1    0     0    0
CMDI               0   16    1     0    0
PATH_TRAVERSAL     0    0   58     0    0
SQLI               0    0    0  2171    0
XSS                3    0    0     0  101
```

Attack-vs-benign: 3 false negatives (XSS fragments `confirm(2)>/`, `confirm(2)>`, `<? echo('<scr)';` predicted benign), 1 false positive (`enid` predicted CMDI), plus 1 attack-family confusion (`cat /etc/passwd`: CMDI → PATH_TRAVERSAL).

**Out-of-distribution check (lexical file):** only 42 of 106 SQL/JS code samples (39.6 %) were flagged, and 32 of 1,000 ordinary sentences (3.2 %) were flagged. The model generalises poorly beyond the style of the training payloads.

## Cost

Measured on Windows 11, AMD Ryzen (12 logical CPUs), 9.85 GB RAM (2.43 GB free at start), CPU only (no GPU used):

| Stage | Seconds |
|---|---:|
| Dataset download (KaggleHub, 876 KB) | 22.8 |
| Loading/preprocessing | 0.2 |
| Grouped split | 33.7 |
| Training (2 pipelines + dummy) | 12.0 |
| Validation | 2.2 |
| Test evaluation incl. bootstrap CI | 23.8 |
| Total in-process (incl. artifact save) | 75.9 |
| CLI wall time incl. interpreter start-up | 87.3 |

Model artifact: 1,325,790 bytes (joblib, compressed). Latency: 1.29 ms p50 / 1.76 ms p95 for a single value; 70.5 ms for a batch of 1,000 (0.07 ms per value).

## Limitations

- **Payload classification only** (see top). Real traffic needs parameter extraction from requests, URL decoding/normalisation, and context the model never sees.
- The dataset is **synthetic-looking and easy**: attack payloads are tool-generated (sqlmap-style) and benign values are Spanish names, addresses, numbers, and e-mails. Near-perfect scores mean "separable on this dataset", not production accuracy; the lexical check shows the gap.
- Minority classes are small (CMDI has 17 test samples), so per-class numbers are noisy.
- Obfuscated payloads (e.g. `/**/` comment-separated SQL) get lower scores.
- No benign data from your own applications was used; expect false positives on legitimate inputs containing quotes, angle brackets, or path-like strings.

## Using it

```bash
uv run --project backend cti train web-payload --dataset-dir data/external/httpparams   # registers a candidate
uv run --project backend cti models promote <MODEL_ID>                                   # make it active (admin decision)
uv run --project backend cti classify-payload "1' or '1'='1' --" "calle mayor 5"           # active model
uv run --project backend cti classify-payload --model-id <MODEL_ID> "<img src=x onerror=alert(1)>"
uv run --project backend cti ingest --source web-server data/samples/web-access/access_sample.log
uv run --project backend cti score web-payload --from 2026-10-15T00:00:00Z --to 2026-10-16T00:00:00Z
```

**Scoring stored access logs.** `cti score web-payload` (or `POST /api/v1/web-payloads/scoring-runs`, job `ml.score_web_payloads`) runs the model on every non-empty decoded query parameter of `http` events in scope and stores one row per parameter in `web_payload_result`. It still classifies **values only**: the URL path, method, status, user agent, and request bodies are not used (POST bodies are not in access logs at all). A flagged value is a hypothesis for an analyst, not a detected attack. The default correlation rule `web_attack_payloads_from_client` raises an alert when one client sends ≥ 2 attack-like values (score ≥ 0.6) within an hour ([ATTACK_CORRELATION.md §4](../../ATTACK_CORRELATION.md#4-default-rules-mvp)); on the sample log it alerted on the two clients that sent the planted payloads (203.0.113.50: SQLI + XSS; 203.0.113.51: PATH_TRAVERSAL + CMDI), risk 27 / medium each, and on no other client. Measured on the 12-line synthetic sample log (dev database, 2026-10-18): 11 HTTP events, 7 parameters scored, 4 events with an attack-like value; the four planted payloads were classified `SQLI`, `XSS`, `PATH_TRAVERSAL`, `CMDI` and the three ordinary values `BENIGN`. That sample was written for this project and is not an accuracy measurement.

API (analyst): `POST /api/v1/web-payloads/classify` with `{"payloads": ["…", …]}` (1–100 values, ≤ 8,192 chars each). Dashboard: **Classification → Web payload classifier** (ad-hoc values) and **Classification → HTTP query parameters scored by the web payload model** (stored results; analysts can queue scoring for the selected range). Event detail shows per-parameter predictions under *Model outputs*.
