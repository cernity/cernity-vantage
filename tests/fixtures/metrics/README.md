# Metrics fixtures (plan 011 · U0)

Provenance for tests. Synthetic fixtures for the metrics adapter tests.

**REAL** (captured from the live stack 2026-09-26, sanitized to metric names/labels — no secrets):
- `prom_exposition_behavioral.txt` — real `:9108/metrics` ndr_ families from behavioral-detectors (the only service with findings/records counters).
- `prom_exposition_base.txt` — real ndr_ families from finding-service (**base only**: config_reloads + evaluate_seconds; NO findings/records — proves the "shared module present != rich metrics" trap).
- `readyz.txt` — real `/readyz` body (`ready`).
- `rpk_group_describe.txt` — real redpanda consumer-group lag output (final-topic offsets + lag).
- `topics.txt`, `versions.txt`, `es_count.json` — real topic list, versions (redpanda v26.2.1 / ES 9.2.1 / ClickHouse 26.7.3.19), ES `_count` shape.

**SYNTHETIC but grounded** (modeled on the real names/labels above; used to unit-test the adapter without a live backend — node_exporter/cAdvisor/InfluxDB are not deployed until U5/U6):
- `synthetic_prom_query_instant.json`, `synthetic_prom_query_range.json`, `synthetic_prom_error.json` — Prometheus HTTP `/api/v1/query[_range]` response shapes.
- `synthetic_influx_instant.json` — InfluxDB 3 InfluxQL response shape (alternate backend, U6).
