"""InfluxDB 3 Core alternate backend (plan 011 U6). Proves the metrics seam is store-agnostic by
satisfying the SAME normalized contract as the Prometheus adapter in a DIFFERENT dialect (InfluxQL —
InfluxDB 3 supports InfluxQL/SQL, not Flux; review R5).

Parity is contract-level, not byte-level (review R2): Prometheus `rate()` extrapolates and detects
resets; InfluxQL `non_negative_derivative` does not — so counter-rate values may differ within a
declared tolerance. What must match is the normalized ENVELOPE (metric_id, unit, kind, dimensions,
quality semantics) and that a required supported metric produces a measured value on BOTH stacks.

Telegraf (deploy/central/monitoring/influxdb) scrapes the same :9108 /metrics and writes each family
as a measurement with its labels as tags, so `influxql` expressions below query the same series.
"""
import os
import time

import metrics_backend as mb

# per-metric InfluxQL, keyed by metric_id — the Influx-dialect twin of the manifest's PromQL.
# Telegraf writes prometheus families as measurements named after the metric, tags = prom labels.
INFLUXQL = {
    "detector_activity": 'SELECT non_negative_derivative(last("counter"),1s) FROM "ndr_findings_total" WHERE time > now()-5m GROUP BY "detector_id"',
    "records_processed": 'SELECT non_negative_derivative(last("counter"),1s) FROM "ndr_records_total" WHERE time > now()-5m GROUP BY "event_type"',
    "records_dropped":   'SELECT non_negative_derivative(last("counter"),1s) FROM "ndr_records_dropped_total" WHERE time > now()-5m GROUP BY "reason"',
    "host_cpu":          'SELECT 100-mean("usage_idle") FROM "cpu" WHERE time > now()-5m',
    "host_mem":          'SELECT mean("used_percent") FROM "mem" WHERE time > now()-5m',
    "scrape_up":         'SELECT last("gauge") FROM "up" GROUP BY "instance"',
}


class InfluxBackend:
    """InfluxDB 3 Core via the InfluxQL HTTP endpoint. Same envelope as PromBackend."""

    kind = "influxdb3"

    def __init__(self, url=None, manifest=None, database=None):
        self.url = (url if url is not None else mb.METRICS_URL).rstrip("/")
        self.database = database or os.environ.get("METRICS_DB", "cernity")
        self.manifest = manifest or mb._load_manifest()

    def _influxql(self, q):
        if not self.url:
            raise mb.BackendError("METRICS_URL not configured")
        import urllib.parse
        qs = urllib.parse.urlencode({"db": self.database, "q": q})
        return _parse_influx(mb._http_get_json(self.url + "/query?" + qs))

    def query(self, metric_id, window_s=None, step_s=None):
        spec = mb._spec(self.manifest, metric_id)                 # raises UnknownMetric
        # Collection stays ES-specific (A2); anything without an InfluxQL twin is unsupported here.
        if spec.get("backend") == "elasticsearch":
            return mb._envelope(spec, quality="unsupported", reason="collection is ES-specific (A2)", source=self.kind)
        if metric_id not in INFLUXQL or spec.get("status") != "available":
            return mb._envelope(spec, quality="unsupported",
                                reason="no InfluxQL twin or status=%s" % spec.get("status"), source=self.kind)
        try:
            rows, newest = self._influxql(INFLUXQL[metric_id])
            if not rows:
                return mb._envelope(spec, quality="no_data", source=self.kind)
            q = "fresh" if (newest is None or (time.time() - newest) <= spec.get("freshness_s", 45)) else "stale"
            return mb._envelope(spec, quality=q, value=rows, sample_at=newest, source=self.kind)
        except mb.BackendError as e:
            return mb._envelope(spec, quality="error", reason=str(e), source=self.kind)


def _parse_influx(js):
    """InfluxQL v1-compatible response: {"results":[{"series":[{tags,columns,values}]}]}.
    Returns (rows, newest_ts) in the same row shape PromBackend uses: {labels, v}."""
    results = js.get("results", [])
    if results and results[0].get("error"):
        raise mb.BackendError("influx: %s" % results[0]["error"])
    rows, newest = [], None
    for res in results:
        for s in res.get("series", []):
            cols = s.get("columns", [])
            vi = next((i for i, c in enumerate(cols) if c != "time"), len(cols) - 1)
            ti = cols.index("time") if "time" in cols else None
            for row in s.get("values", []):
                val = row[vi]
                if val is None:
                    continue                       # gaps stay gaps, never coerced to 0
                rows.append({"labels": dict(s.get("tags") or {}), "v": float(val)})
                if ti is not None:
                    ts = _epoch(row[ti])
                    newest = ts if newest is None else max(newest, ts)
    return rows, newest


def _epoch(t):
    if isinstance(t, (int, float)):
        return float(t) / (1e9 if t > 1e12 else 1)   # ns or s
    try:
        import datetime
        return datetime.datetime.fromisoformat(str(t).replace("Z", "+00:00")).timestamp()
    except Exception:                                # noqa: BLE001
        return None
