# Vantage metrics & dashboard setup (plan 011)

Vantage's Overview is a **native health glance** backed by a **store-agnostic metrics-query seam**.
This guide stands up the opinionated default stack, documents the adapter contract so you can bring
your own backend, and gives a worked InfluxDB alternate. Semantics (what each metric really means,

Use configurable hostnames below (`CENTRAL_HOST`) — never hard-code private addresses. Keep all
URLs/credentials server-side; the browser never supplies a query, host, or secret.

## 1. Default stack — Prometheus + Grafana + node_exporter + cAdvisor

The Cernity services already expose Prometheus `/metrics` on `:9108`; the default stack just scrapes
them plus host/container/broker sources. It ships in the **cernityndr** repo at
`deploy/central/monitoring/` (pinned images; retention has both a duration and a size budget on a
persistent volume; colocation with what it monitors means it cannot be an independent monitor of its
own host outage).

```bash
# on the central host (CENTRAL_HOST), against the same docker network as the services (`ndr`)
cd deploy/central/monitoring
GRAFANA_ADMIN_PASSWORD=<choose one> docker compose up -d
# Prometheus :9090, Grafana :3000 (datasource + starter dashboard provisioned)
```

`prometheus.yml` scrape jobs: `cernity-services` (each `<svc>:9108`), `node` (node_exporter on the
host net — observes the HOST, not a container), `cadvisor`, `redpanda` (`:9644/public_metrics`).
Adjust the target list to your running services. `scrape_up` means "collector reached target" — not
readiness or health.

**Point Vantage at it** (env on the Vantage container):

| env | value | meaning |
|---|---|---|
| `METRICS_BACKEND` | `prometheus` (default) | which adapter the seam uses |
| `METRICS_URL` | `http://CENTRAL_HOST:9090` (or `http://prometheus:9090` on the shared net) | backend endpoint (server-side) |
| `METRICS_CA` | path to CA bundle | verified TLS when the backend is HTTPS (omit for plain-http on a trusted net) |
| `METRICS_TIMEOUT` | `5` | bounded per-request deadline (seconds) |
| `METRICS_TOKEN` | (optional) | `Authorization` header, server-side only |
| `GRAFANA_URL` | `http://CENTRAL_HOST:3000` | the Overview "Metrics ↗" deep-dive link |

Restart Vantage; the Overview cards flip from `not deployed` (grey) to measured (green) as targets
come up. Required checks without a wired source stay honestly amber (e.g. readiness, consumer lag).

## 2. Adapter contract — bring your own backend

The seam lives in `metrics_backend.py`. Native cards call **named metric IDs** from
[`metrics-capabilities.json`](../metrics-capabilities.json) — never raw queries, hosts, or credentials
from the browser. A backend implements:

```
class Backend:
    kind = "<name>"                         # matches metrics-capabilities.json backends.<name>
    def query(self, metric_id, window_s=None, step_s=None) -> envelope
```

- Resolve `metric_id` against the manifest (`UnknownMetric` for an ID not in it — a programmer error,
  distinct from a metric this backend can't measure yet → `quality="unsupported"`).
- Execute the metric's dialect query (allowlisted in the manifest / adapter), with a bounded timeout
  and configured TLS.
- Return the **normalized R2 envelope**: `contract_version, metric_id, unit, kind, dimensions, value,
  series, sample_at, evaluated_at, window, step, quality, reason, source, covered_targets,
  expected_targets`. `quality ∈ {fresh, stale, no_data, error, unsupported}`. **Unknown ⇒ `null`,
  never `0`/`NaN`; range gaps stay gaps.** Handle counter resets per instance before summing.
- Register it in `metrics_backend.get_backend()` behind `METRICS_BACKEND=<name>`.

The manifest gates rendering: each metric's `status` (`available | needs-U5 | needs-R7 | needs-wiring`)
decides whether a card shows measured data or an honest `unknown`/`not-applicable`. Add a metric by
adding an entry (id, backend, query, unit, kind, dimensions, freshness_s, criticality, status, meaning).

**Parity across stores is contract-level, not byte-level:** the same `metric_id` must yield the same
envelope shape and semantic identity on every backend; counter-rate *values* may differ by dialect
(e.g. PromQL `rate()` extrapolation vs InfluxQL `non_negative_derivative`) within a declared tolerance.
A required supported metric must produce a measured value on every backend you claim to support.

## 3. Worked alternate — InfluxDB 3 Core + Telegraf

InfluxDB 3 Core (InfluxQL — **not** Flux) is the proven alternate. Config: cernityndr
`deploy/central/monitoring/influxdb/` (pinned InfluxDB 3 + Telegraf; checked-in, reproducible).

```bash
cd deploy/central/monitoring/influxdb
# 1. create an admin token + the `cernity` database on first run:
#    docker compose up -d influxdb3
#    docker exec cernity-influxdb3 influxdb3 create token --admin      # -> INFLUX_TOKEN
#    docker exec cernity-influxdb3 influxdb3 create database cernity
# 2. bring up Telegraf with that token (scrapes the same :9108 metrics -> InfluxDB):
INFLUX_TOKEN=<token> docker compose up -d
```

Point Vantage at it — the SAME cards, no code change:

```
METRICS_BACKEND=influxdb3
METRICS_URL=http://CENTRAL_HOST:8181
METRICS_DB=cernity
METRICS_TOKEN=Token <token>
```

Telegraf writes each Prometheus family as an InfluxDB measurement (tags = labels); the InfluxBackend's
InfluxQL twins query those. Collection stats stay ES-specific (the seam is store-agnostic, the whole
dashboard is not) so collection cards read `unsupported` under the Influx backend — that is correct.

## 4. Alerting

Vantage is **display-only**. Alert rules, silences, and notification channels live in the bundled
Grafana; any starter alert rules ship disabled with no contact point until you configure one.
