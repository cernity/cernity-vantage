"""Store-agnostic metrics-query seam (plan 011 U1/U6).

The dashboard's native cards call NAMED metric IDs from metrics-capabilities.json — never
raw PromQL/InfluxQL, host URLs, or credentials from the browser. A backend (Prometheus default,
InfluxDB 3 alternate) resolves a metric ID to its dialect query, executes it with a bounded
timeout + configured TLS, and returns the R2 normalized result. Unknown values are null, never
0/NaN; freshness and provenance travel with every result so a card can honestly render
fresh / stale / no_data / error / unsupported.

Design rules (review R1/R2):
  - meaning precedes layout: query IDs + semantics are the allowlist in metrics-capabilities.json.
  - a missing/unsupported metric yields quality=unsupported (card degrades), not a silent 0.
  - UnknownMetric (ID not in the manifest) is a PROGRAMMER error, distinct from unsupported.
  - counter resets/extrapolation live in the PromQL (rate() before sum); we pass values through.
"""
import json
import math
import os
import ssl
import time
import urllib.request
import urllib.error
from contextlib import closing

CONTRACT_VERSION = "011-u0.1"
_MANIFEST_PATH = os.environ.get("METRICS_CAPABILITIES", os.path.join(os.path.dirname(__file__), "metrics-capabilities.json"))

BACKEND = os.environ.get("METRICS_BACKEND", "prometheus")
METRICS_URL = os.environ.get("METRICS_URL", "").rstrip("/")
METRICS_TIMEOUT = float(os.environ.get("METRICS_TIMEOUT", "5"))       # bounded per-request deadline
METRICS_CA = os.environ.get("METRICS_CA", "")                        # path to CA bundle -> verified TLS
METRICS_TOKEN = os.environ.get("METRICS_TOKEN", "")                  # optional bearer/basic, server-side only


class UnknownMetric(KeyError):
    """metric_id is not in the manifest — a programmer error, not a degraded card."""


class UnsupportedMetric(Exception):
    """The metric exists but this backend/deploy cannot measure it yet (status != available, or
    the backend has no query for it). Cards render quality=unsupported, never a fabricated value."""


class BackendError(Exception):
    """The backend was unreachable, returned non-200, or sent malformed data. quality=error."""


def _load_manifest(path=None):
    with open(path or _MANIFEST_PATH, encoding="utf-8") as fh:
        return json.load(fh)


def _spec(manifest, metric_id):
    for m in manifest.get("metrics", []):
        if m["id"] == metric_id:
            return m
    raise UnknownMetric(metric_id)


def _ssl_ctx():
    # verified TLS when a CA is configured; a plain-http endpoint needs no context. We do NOT
    # reuse app.py's unverified _CTX here (review R1: verified CA config for the metrics plane).
    if METRICS_CA:
        return ssl.create_default_context(cafile=METRICS_CA)
    return ssl.create_default_context()


def _http_get_json(url, timeout=None):
    req = urllib.request.Request(url)
    if METRICS_TOKEN:
        req.add_header("Authorization", METRICS_TOKEN)
    ctx = _ssl_ctx() if url.startswith("https") else None
    try:
        with closing(urllib.request.urlopen(req, timeout=timeout or METRICS_TIMEOUT, context=ctx)) as r:
            if r.status != 200:
                raise BackendError("backend HTTP %s" % r.status)
            return json.load(r)
    except urllib.error.HTTPError as e:
        raise BackendError("backend HTTP %s" % e.code)
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise BackendError("backend unreachable: %s" % type(e).__name__)
    except ValueError:
        raise BackendError("backend returned malformed JSON")


def _now():
    return time.time()


def _envelope(spec, *, quality, value=None, series=None, sample_at=None, window=None, step=None,
              reason="", source=BACKEND, covered=0, expected=0):
    """R2 normalized result. Unknown -> value/series null; range gaps stay gaps."""
    return {
        "contract_version": CONTRACT_VERSION,
        "metric_id": spec["id"],
        "unit": spec.get("unit"),
        "kind": spec.get("kind"),
        "dimensions": spec.get("dimensions", []),
        "criticality": spec.get("criticality"),
        "value": value,                 # instant: list of {labels, v} or None
        "series": series,               # range: list of {labels, points:[[ts,v]]} or None
        "sample_at": sample_at,         # freshest underlying sample ts (None if no_data)
        "evaluated_at": _now(),         # when WE asked (never proof the sample is fresh)
        "window": window,
        "step": step,
        "quality": quality,             # fresh|stale|no_data|error|unsupported
        "reason": reason,
        "source": source,
        "covered_targets": covered,
        "expected_targets": expected,
    }


class PromBackend:
    """Prometheus HTTP API (/api/v1/query[_range]). PromQL comes only from the manifest."""

    kind = "prometheus"

    def __init__(self, url=None, manifest=None):
        self.url = (url if url is not None else METRICS_URL).rstrip("/")
        self.manifest = manifest or _load_manifest()

    # --- primitives (allowlisted PromQL string in, parsed rows out) --------------
    def instant(self, promql):
        if not self.url:
            raise BackendError("METRICS_URL not configured")
        import urllib.parse
        q = urllib.parse.urlencode({"query": promql})
        return self._parse_vector(_http_get_json(self.url + "/api/v1/query?" + q))

    def range(self, promql, since_s, step_s):
        if not self.url:
            raise BackendError("METRICS_URL not configured")
        import urllib.parse
        end = _now()
        q = urllib.parse.urlencode({"query": promql, "start": end - since_s, "end": end, "step": step_s})
        return self._parse_matrix(_http_get_json(self.url + "/api/v1/query_range?" + q))

    @staticmethod
    def _parse_vector(js):
        if js.get("status") != "success":
            raise BackendError("prometheus: %s" % js.get("error", "query failed"))
        rows, newest = [], None
        for r in js.get("data", {}).get("result", []):
            ts, val = r["value"]
            f = float(val)
            if not math.isfinite(f):            # review item 6: NaN/Inf are not measured values
                continue
            rows.append({"labels": r.get("metric", {}), "v": f})
            newest = ts if newest is None else max(newest, ts)
        return rows, newest

    @staticmethod
    def _parse_matrix(js):
        if js.get("status") != "success":
            raise BackendError("prometheus: %s" % js.get("error", "query failed"))
        series, newest = [], None
        for r in js.get("data", {}).get("result", []):
            # review item 6: keep gaps as gaps; drop NaN/Inf points rather than plotting them as 0
            pts = [[p[0], float(p[1])] for p in r.get("values", []) if math.isfinite(float(p[1]))]
            series.append({"labels": r.get("metric", {}), "points": pts})
            if pts:
                newest = pts[-1][0] if newest is None else max(newest, pts[-1][0])
        return series, newest

    # --- named-metric resolution -> normalized envelope -------------------------
    def query(self, metric_id, window_s=None, step_s=None):
        spec = _spec(self.manifest, metric_id)          # raises UnknownMetric for bad IDs
        if spec.get("backend") != self.kind or spec.get("status") != "available":
            # exists in the catalog but this backend/deploy can't measure it yet
            return _envelope(spec, quality="unsupported",
                             reason="status=%s backend=%s" % (spec.get("status"), spec.get("backend")))
        promql = spec["query"]
        try:
            if window_s:
                series, newest = self.range(promql, window_s, step_s or max(15, window_s // 300))
                if not series:
                    return _envelope(spec, quality="no_data", window=window_s, step=step_s)
                return _envelope(spec, quality=self._freshness(spec, newest), series=series,
                                 sample_at=newest, window=window_s, step=step_s or max(15, window_s // 300))
            rows, newest = self.instant(promql)
            if not rows:
                return _envelope(spec, quality="no_data")
            return _envelope(spec, quality=self._freshness(spec, newest), value=rows, sample_at=newest)
        except BackendError as e:
            return _envelope(spec, quality="error", reason=str(e))

    @staticmethod
    def _freshness(spec, sample_at):
        if sample_at is None:
            return "no_data"
        limit = spec.get("freshness_s", 45)
        return "fresh" if (_now() - sample_at) <= limit else "stale"


def get_backend(manifest=None):
    """Factory. Prometheus default; InfluxDB 3 alternate (U6) selected by METRICS_BACKEND=influxdb3."""
    if BACKEND in ("influxdb3", "influx"):
        from influx_backend import InfluxBackend        # lazy: only when selected
        return InfluxBackend(manifest=manifest)
    return PromBackend(manifest=manifest)


if __name__ == "__main__":  # tiny smoke against a live METRICS_URL, if set
    b = get_backend()
    for mid in ("detector_activity", "collection_findings", "host_cpu"):
        try:
            print(mid, "->", b.query(mid).get("quality"))
        except UnknownMetric:
            print(mid, "-> UNKNOWN (not in manifest)")
