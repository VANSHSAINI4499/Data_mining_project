# Anomaly Mining

Unsupervised detection of **unusual** host, account, and network behaviour. Storage: `anomaly_result` in [DATABASE_DESIGN.md](DATABASE_DESIGN.md#35-ml-registry-and-model-outputs). Code: `backend/app/ml/anomaly/`, `backend/app/ml/features/windows.py`.

## 1. Principles

- **Unusual ≠ malicious.** A flagged window means behaviour deviates from a reference; it is evidence for review, never a confirmed attack. The UI and API label it "unusual behaviour".
- **Scores are not probabilities.** Isolation Forest and robust z-scores are uncalibrated and comparable only within the same model version. We expose a percentile against the reference distribution instead of any "probability".
- **Explainability over sophistication.** Every flagged window shows which features deviated and by how much relative to the entity's own history.
- Anomaly mining requires real timestamps: events with `time_quality = 'assumed'` are excluded.

## 2. Entities and windows

| Entity type | Key | Events used |
|---|---|---|
| `host` | `host_name`, else `src_ip` for network-only sources (recorded as `src_ip`) | endpoint, network, auth (as target host) |
| `account` | `user_name_normalized` | `auth` |
| `src_ip` | `src_ip` | `network_flow`, `ids_alert`, `auth` |

- Tumbling windows; default size **1 hour**; allowed sizes `15m`, `1h`, `1d` (config). Windows are aligned to UTC boundaries.
- A window exists only if the entity had ≥ 1 event in it (no fabricated zero windows), except where zero-activity baselines are explicitly needed (computed counts may be 0 within existing windows).
- Late events: rescoring a window is allowed; results are unique per `(model, entity, window_start)` and the newer scoring run supersedes via a new model version or explicit rescoring run (old rows kept).

## 3. Feature-window construction (`window_v1`)

| Feature | Entities | Definition |
|---|---|---|
| `event_count` | all | Events in window. |
| `distinct_dst_ips` | host, src_ip | Unique `dst_ip`. |
| `distinct_dst_ports` | host, src_ip | Unique `dst_port`. |
| `bytes_out_sum`, `bytes_in_sum` | host, src_ip | Sums (NULLs ignored; count of NULLs kept as `bytes_null_count`). |
| `mean_duration_s` | host, src_ip | Mean of non-null durations. |
| `failed_auth_count` | account, src_ip, host | `auth_result = 'failure'`. |
| `success_auth_count` | account, src_ip, host | `auth_result = 'success'`. |
| `failed_auth_ratio` | account, src_ip | failures / (failures + successes); NULL if no auth. |
| `distinct_src_ips_for_account` | account | Unique `src_ip`. |
| `distinct_hosts_for_account` | account | Unique `host_name`. |
| `new_dst_port_count` | host, src_ip | Ports never seen for the entity in the baseline period. |
| `new_src_ip_for_account` | account | Source IPs not seen for the account in the baseline period. |
| `ids_alert_count` | host, src_ip | `ids_alert` events. |
| `off_hours_fraction` | all | Fraction of events outside 07:00–19:00 in the configured site timezone (`CTI_SITE_TIMEZONE`, default UTC). |

Feature computation is done in SQL aggregates (repository layer) or pandas from extracted events; either way, unit tests verify results on hand-computed fixtures. Feature vectors used for scoring are stored in `anomaly_result.feature_snapshot`.

## 4. Methods

### 4.1 Statistical baseline — robust z-score (`robust_zscore`)

- For each entity and feature, baseline = trailing window of `baseline_days` (default 14) **before** the scored window: median and MAD.
- `z = 0.6745 × (x − median) / MAD`; if MAD = 0, use `(x − median) / (mean absolute deviation + ε)` and mark `mad_zero = true`.
- `anomaly_score = max |z|` over features; `top_deviations` lists features with |z| ≥ 3.
- Requires ≥ `min_baseline_windows` (default 24) for the entity; otherwise the window is `insufficient_history` (not scored, counted).
- Strength: per-entity, explainable. Weakness: univariate; seasonality not modelled in the MVP.

### 4.2 Isolation Forest (`isolation_forest`)

- One model per `(entity_type, window_size, feature set version)`, trained on windows in a reference period (config: start/end or batch IDs).
- Pipeline: `SimpleImputer(median)` → `log1p` on counts → `StandardScaler` → `IsolationForest(n_estimators=200, max_samples="auto", contamination="auto", random_state=seed)`.
- `anomaly_score = −score_samples(X)` so higher = more unusual.
- `contamination` is **not** used to set the flag threshold (we don't know the true anomaly rate); thresholds are chosen as in §5.
- Explanation: for each flagged window, compute per-feature robust z versus the entity's history (as in 4.1) and versus the population; report the top deviations. (Isolation Forest itself does not provide per-feature attributions; we do not invent them.)

## 5. Threshold selection

- Default: threshold = the **99th percentile** of anomaly scores on the reference (training) windows (`threshold_percentile`, configurable 90–99.9).
- The threshold, method, and percentile are stored with the model (`ml_model.threshold`) and on each result (`threshold`).
- Optional **alert budget** mode: choose the percentile so that the expected flagged count per day on the reference period ≤ `max_flags_per_day`. Recorded as such.
- When labelled data exist (lab datasets), a threshold report shows precision/recall of flags against ground truth at several percentiles **as a proxy evaluation only** (see §9).

## 6. Score interpretation (shown in API/UI)

| Field | How to read it |
|---|---|
| `anomaly_score` | Higher = more unusual for this model version. Not comparable across models or methods. |
| `score_percentile` | "More unusual than X % of reference windows." |
| `is_flagged` | Score ≥ threshold. Means "worth a look", not "malicious". |
| `top_deviations` | What changed, with value vs. baseline median/MAD. |

Forbidden wording in UI/API/docs: "probability of attack", "malicious score", "confidence that this is an attack" for anomaly outputs.

## 7. Historical comparisons

The anomaly detail endpoint (`GET /api/v1/anomalies/{result_id}`) returns:

- The entity's feature values for the scored window vs. baseline median/MAD over `baseline_days`.
- A time series of the entity's scores for the previous N windows (default 7 days).
- Same-hour-of-week comparison when ≥ 4 weeks of history exist; otherwise flagged `insufficient_history_for_seasonal_comparison`.
- Linked events in the window (paginated) and any classification results/indicator matches for those events.

## 8. Review workflow

1. Analyst opens a flagged window in the Anomaly Explorer ([FRONTEND_SPECIFICATION.md](FRONTEND_SPECIFICATION.md#56-anomaly-explorer)).
2. Reviews deviations, history, and linked events.
3. Records feedback: `true_positive` (malicious), `benign_unusual` (unusual but legitimate), `false_positive` (data/feature error), `needs_more_info`.
4. Optionally the window becomes evidence in an alert via correlation rules ([ATTACK_CORRELATION.md](ATTACK_CORRELATION.md)) or is attached to a case.
5. Feedback is used for reporting (flag precision by verdict) and, in future, threshold tuning — never to rewrite past scores.

## 9. Evaluation and its limitations

- There is usually no ground truth for "anomalous". When lab labels exist, we report proxy metrics: precision@k, recall of windows containing attack events, PR-AUC of scores vs. "window contains ≥1 attack event". These are labelled **proxy evaluation** in reports.
- Lab attacks are often extremely loud; proxy metrics overstate real-world usefulness.
- Isolation Forest is sensitive to feature scaling, window size, and reference-period contamination (attacks inside the reference period become "normal").
- Robust z needs history; new entities are not scored until they have enough windows.
- These limitations are shown on the Anomaly page and in model reports.

## 10. Model versioning

- Registry names: `<entity_type>_window_<size>_iforest` (e.g., `account_window_1h_iforest`) and `<entity_type>_window_<size>_robustz` (stored as a model with parameters but no fitted estimator beyond configuration; it still gets a version and training-run record so results are traceable).
- Same persistence, integrity, and promotion rules as classification ([ML_CLASSIFICATION.md](ML_CLASSIFICATION.md#10-model-persistence-and-versioning)), minus the classification-specific gate. Anomaly promotion gate: training run succeeded, reference period ≥ 7 days of windows (configurable), threshold report present.

## 11. Concept-drift monitoring (Phase 8)

- **Feature drift:** Population Stability Index (PSI) per feature between the reference period and each recent period (default weekly), with bins fixed from the reference. PSI ≥ 0.25 → drift warning (configurable).
- **Score drift:** flagged-rate change versus the reference (e.g., > 3× or < ⅓) → warning.
- **Classification drift:** distribution shift of predicted categories and of `predicted_score`; drop in agreement with analyst feedback.
- Drift warnings create informational records shown on the Models page and recommend retraining; they never retrain or re-threshold automatically.

## 12. Configuration example

`config/ml/anomaly_account_1h.toml`:

```toml
name = "account_window_1h_iforest"
method = "isolation_forest"
entity_type = "account"
window_size = "1h"
feature_set = "window_v1"
random_seed = 42
reference_start = "2026-01-01T00:00:00Z"
reference_end = "2026-01-31T00:00:00Z"
threshold_percentile = 99.0
baseline_days = 14
min_baseline_windows = 24

[iforest]
n_estimators = 200
```
