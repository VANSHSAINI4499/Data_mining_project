# Threat Intelligence and MITRE ATT&CK

Indicator management, matching, enrichment, and ATT&CK references. Tables: [DATABASE_DESIGN.md](DATABASE_DESIGN.md#34-threat-intelligence-and-attck). Code: `backend/app/ti/`, `backend/app/enrichment/`.

## 1. Principles

- **Feeds are optional.** The system is fully usable with zero feeds and no external credentials. Indicator matching simply yields no matches.
- **No fabricated indicators.** The repository ships no "known bad" lists. Test fixtures use only reserved documentation values (IPs in `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`; domains under `.invalid`/`.test`/`example.*`) and are labelled synthetic.
- **No active interaction with indicators.** Never visit URLs, resolve domains, connect to IPs, download files, or submit samples. Indicators are inert strings.
- **Provenance always.** Every indicator records its feed, feed run, first/last seen, validity, and confidence; every match snapshots them.
- A match is **evidence that an observed value appears on a list**, not proof of compromise.

## 2. Indicator types

| `indicator_type` | Matchable in MVP | Event fields matched |
|---|---|---|
| `ipv4`, `ipv6` | Yes | `src_ip`, `dst_ip` |
| `domain` | Yes (exact) | `dns_query`, `http_host` |
| `url` | Yes (exact, normalised) | `url` combined with `http_host` when `url` is a path |
| `sha256` | Yes | `file_sha256` |
| `sha1`, `md5` | Stored, not matched (no canonical field) | — |
| `email` | Stored, not matched | — |

CIDR ranges, parent-domain/wildcard matching, and fuzzy matching are **future work**.

## 3. Source reliability and confidence

- **Feed reliability** uses the Admiralty-style scale on `ti_feed.reliability` and `dim_source.reliability`: `A` completely reliable, `B` usually reliable, `C` fairly reliable, `D` not usually reliable, `E` unreliable, `F` cannot be judged. Set by an admin; default `F`.
- **Indicator confidence** is 0–100: taken from the feed (STIX `confidence`, CSV column) or the feed's `default_confidence`; manual indicators require an explicit value.
- Reliability weights for risk scoring ([ATTACK_CORRELATION.md](ATTACK_CORRELATION.md#6-risk-scoring)): A 1.0, B 0.8, C 0.6, D 0.4, E 0.2, F 0.3. Configurable in `config/correlation_rules/risk_weights.toml`.

## 4. Lifecycle: first seen, last seen, validity, expiration

| Field | Meaning |
|---|---|
| `first_seen` | Earliest time the feed (or our imports) observed the indicator. |
| `last_seen` | Latest time the feed reported it. Updated on re-import. |
| `valid_from` / `valid_until` | Validity window (STIX `valid_from`/`valid_until`, CSV columns, or defaults). |
| `revoked` | Feed revoked the indicator (STIX `revoked: true`) or an admin revoked it. |

- **Effective expiry** = `valid_until` if set, else `last_seen + feed.default_ttl_days` (default 90 days). Indicators past effective expiry are **stale/expired**.
- Expired and revoked indicators are **kept** (history) but excluded from new matching by default (`include_expired = false`). Retro-hunting can include them explicitly; such matches are labelled `expired`/`revoked`.
- Changes to confidence, validity, or revocation append a `ti_indicator_version` snapshot.
- **State at match time** (`indicator_state_at_match`) is computed relative to the **event time**: `active` if the event time is within the effective validity window and not revoked; `expired` if outside it; `revoked` if revoked. Only `active` matches contribute to risk by default.

## 5. Ingestion and normalization

Import paths:

| Path | Format |
|---|---|
| Manual entry | `POST /api/v1/threat-intel/indicators` (admin). |
| CSV file (`ti_csv`) | Columns: `indicator_type`, `value`, `confidence`, `first_seen`, `last_seen`, `valid_until`, `description`, `tlp`, `technique_ids` (semicolon-separated). |
| STIX 2.1 bundle (`stix21_bundle`) | JSON file with `type: "bundle"`; `indicator` objects with simple patterns (§8). |
| TAXII 2.1 collection | Optional (§8). |

Uploads use the same safety controls as event ingestion ([DATA_INGESTION.md](DATA_INGESTION.md#3-upload-limits-and-safe-parsing)).

Normalisation (`value_normalized`; `value_raw` kept):

| Type | Rules |
|---|---|
| `ipv4` | Strict dotted-quad; leading zeros rejected (ambiguous octal); canonical text. |
| `ipv6` | Parsed with `ipaddress`; compressed lowercase. IPv4-mapped → `ipv4`. |
| `domain` | Re-fang (`[.]` → `.`), trim, lowercase, strip trailing dot, IDNA → ASCII (punycode); must have ≥ 1 dot; wildcards rejected. |
| `url` | Re-fang (`hxxp` → `http`, `[.]`, `[:]`), lowercase scheme and host, remove default ports, drop fragment; path and query preserved exactly. Never fetched. |
| hashes | Trim, lowercase, exact hex length (md5 32, sha1 40, sha256 64). |
| `email` | Trim, lowercase domain part. |

Invalid indicators are rejected per record with reasons (count in `ti_feed_run.indicators_rejected`). The UI displays URLs and domains **defanged** (`hxxp://example[.]test`) and never as clickable links.

## 6. Exact matching

- Matching job (`POST /api/v1/threat-intel/match-runs`, `cti match-indicators`) with scope: batch IDs or event time range, optional `include_expired`.
- Implementation: set-based SQL joins between `fact_security_event` (scoped, index-backed) and `ti_indicator` on `(indicator_type, value_normalized)`, per matchable field; inserts into `indicator_match` with `ON CONFLICT DO NOTHING`.
- Each match stores `matched_field`, `matched_value`, indicator confidence and state at match, `matcher_version`, `job_id`.
- When new indicators are imported, a match run over the configured look-back (default 30 days of event time) can be enqueued automatically (setting `CTI_TI_RETROHUNT_DAYS`; `0` disables).

## 7. Event enrichment

- **Indicator context:** event detail shows matches with feed, reliability, confidence, state, description, TLP, and linked techniques.
- **Asset context:** `src_asset_key`/`dst_asset_key` resolved at load time ([DATA_INGESTION.md](DATA_INGESTION.md#48-asset_inventory_csv)).
- **ATT&CK context:** techniques derived from (a) indicator `technique_ids`, (b) category→technique mapping for ground-truth labels and predictions. The source of every technique reference is shown (`via indicator`, `via predicted category`, `via dataset label`). Predicted-category techniques are labelled as model-derived.
- Enrichment adds rows/links; it never modifies observed event fields.

## 8. STIX/TAXII integration

References: OASIS CTI documentation — <https://oasis-open.github.io/cti-documentation/> (verified).

**STIX 2.1 bundle import (MVP):**

- Accept `indicator` objects (and ignore other SDOs/SROs except `attack-pattern` references via `relationship` objects `indicates` → `attack-pattern` with an ATT&CK external ID, which populate `technique_ids`).
- Supported patterns: a **single comparison** or `OR` of comparisons using `=` on `ipv4-addr:value`, `ipv6-addr:value`, `domain-name:value`, `url:value`, `file:hashes.'SHA-256'`, `file:hashes.'SHA-1'`, `file:hashes.MD5`, `email-addr:value`. Each comparison yields one indicator.
- Unsupported patterns (`AND`, `FOLLOWEDBY`, `MATCHES`, `LIKE`, `ISSUBSET`, qualifiers, other object paths) are **stored as unsupported** in the run report and not matched. The parser is a small, tested, non-evaluating tokenizer — no `eval`, no regex execution from feed content.
- Mapped fields: `id` → `stix_id`, `confidence`, `valid_from`, `valid_until`, `revoked`, `created`/`modified` (first/last seen if no better data), `description`, `object_marking_refs` (TLP markings → `tlp`).

**TAXII 2.1 polling (optional, extra `[taxii]`, may complete in Phase 8):**

- Feed config: API root URL, collection ID, `credentials_ref` (name of an environment variable holding a token/password — the secret itself is never stored in the DB).
- Poll with `added_after` = last successful cursor; paginate with a max page count per run.
- TLS verification always on; request timeout 30 s; response size cap 50 MB per page.
- Disabled by default; a feed with missing credentials is shown as `not_configured`, not as an error.

## 9. MITRE ATT&CK references

Reference: MITRE ATT&CK — <https://attack.mitre.org/> (verified; v20 was the current release at time of writing). STIX data: <https://github.com/mitre-attack/attack-stix-data> (verified), file `enterprise-attack/enterprise-attack.json`.

- **Import:** the user downloads the Enterprise bundle manually into `data/external/attack/`; `cti attack-import <path>` loads `attack-pattern` objects into `attack_technique` (`technique_id` from the `mitre-attack` external reference, `name`, tactics from `kill_chain_phases`, subtechnique flag, `revoked`, deprecation flag, URL from the external reference). The ATT&CK version from the bundle's collection object is stored in `attack_version`.
- No ATT&CK data is fetched automatically or committed beyond IDs in mapping config.
- **Category → technique mapping:** `config/attack_mappings/category_techniques.toml`, each entry with `confidence` and a written `rationale`. Initial proposal (to be validated against the imported bundle; IDs missing or revoked in the imported version are reported and skipped):

| Category | Technique(s) | Confidence | Rationale |
|---|---|---|---|
| `RECONNAISSANCE` | T1046 Network Service Discovery; T1595 Active Scanning | medium | Port scans / probing. |
| `BRUTE_FORCE` | T1110 Brute Force | high | Credential guessing. |
| `DOS` | T1498 Network Denial of Service; T1499 Endpoint Denial of Service | medium | Depends on tool/layer. |
| `DDOS` | T1498 Network Denial of Service | medium | Volumetric/distributed. |
| `WEB_ATTACK` | T1190 Exploit Public-Facing Application | medium | Injection/XSS against web apps. |
| `EXPLOIT` | T1190 Exploit Public-Facing Application | low | Dataset category is broad. |
| `BOTNET` | T1071 Application Layer Protocol | low | Bot C2 commonly uses app-layer protocols; weak link. |
| Others | — | — | No defensible mapping; left unmapped rather than guessed. |

- Mappings are suggestions shown with confidence and rationale, never presented as confirmed adversary behaviour.

## 10. Feed updates, retries, and rate limits

- Feed syncs run as jobs (`POST /api/v1/threat-intel/feeds/{feed_id}/sync` → job `ti.sync`). Implemented in Phase 8 (`app/ti/taxii.py`): `added_after` cursor stored in the last successful run's report, `more`/`next` pagination (max 20 pages per run), retries and 429 handling as below, 50 MB page cap, 30 s timeout, TLS always verified, bearer token read from the environment variable named by `credentials_ref`. Tested against a local stub transport only — no real TAXII server was contacted. Scheduled (automatic) polling is **not** implemented; syncs are started manually.
- Retries: transient network errors and HTTP 5xx → up to 3 attempts with exponential back-off (30 s, 2 min, 10 min) plus jitter. HTTP 429 → honour `Retry-After` (capped at 1 h), else back-off.
- Per-feed minimum poll interval (default 60 min) prevents hammering providers; manual sync is rejected with 409 if a sync is already running or the last one started < 5 min ago.
- 4xx other than 429 (e.g., 401/403/404) → no retry; feed `last_error` set; feed remains enabled but marked unhealthy.
- A failed sync never deletes existing indicators.
- Feed health (last success, last error, indicator counts) is shown on the Threat Intelligence page.

## 11. Configuration

| Variable | Default | Meaning |
|---|---|---|
| `CTI_TI_RETROHUNT_DAYS` | `30` | Look-back for automatic matching after import (0 = off). Implemented. |
| *(per feed)* `default_ttl_days` | `90` | Effective expiry fallback; a feed setting (`PATCH /threat-intel/feeds/{id}`), not an environment variable. |
| *(constant)* TAXII timeout | 30 s | `TIMEOUT_S` in `app/ti/taxii.py`; not an environment variable in this build. |
| *(constant)* TAXII page size cap | 50 MB | `MAX_RESPONSE_BYTES` in `app/ti/taxii.py`. |
| `<feed credentials_ref>` | — | e.g., `CTI_FEED_EXAMPLE_TOKEN`; only needed for authenticated optional feeds. |
