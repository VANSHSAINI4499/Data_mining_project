# config/

Versioned domain configuration in TOML (read with the standard-library `tomllib`):

| Directory | Contents | Added in |
|---|---|---|
| `label_mappings/` | Dataset label → canonical attack category | Phase 2 |
| `datasets/` | Dataset column specs / field paths | Phase 2 |
| `feature_sets/` | ML feature-set allowlists | Phase 3 |
| `ml/` | Training configurations | Phase 3–4 |
| `attack_mappings/` | Category → ATT&CK technique mappings | Phase 5 |
| `correlation_rules/` | Correlation rules and risk weights | Phase 5 |

See [ARCHITECTURE.md §4](../ARCHITECTURE.md#4-repository-layout-target).
