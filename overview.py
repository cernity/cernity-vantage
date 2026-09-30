"""Overview dashboard assembly (plan 011 U2). Pure logic — no FastAPI, no I/O of its own;
callers inject the metrics `backend` (metrics_backend.get_backend()) and an `es_count(index, day)`
callable (app.py's ES layer). Kept import-light so it unit-tests without fastapi.

Honest semantics (review R1/R3):
  - the hero verdict is a scoped reduction over EXPECTED REQUIRED capabilities, reporting coverage
    (fresh measured required / expected required), never "everything healthy".
  - a source that isn't deployed/wired yet is `unsupported` (amber), not a fabricated green.
  - if the metrics backend itself is down, dependent checks are `unknown/error`, not proven-down.
"""
import datetime
import json
import os

import metrics_backend as mb

_MANIFEST = json.load(open(os.environ.get("METRICS_CAPABILITIES",
             os.path.join(os.path.dirname(__file__), "metrics-capabilities.json")), encoding="utf-8"))

# quality values that count as a satisfied required check
_GOOD = {"fresh"}
_DEGRADED = {"stale", "no_data"}
_BAD = {"error"}
_NA = {"unsupported"}


def _utc_day():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")


def _resolve(metric, backend, es_count, probe_ready=None):
    """Return an R2-shaped envelope for one metric, routing by its declared backend."""
    mid, be = metric["id"], metric.get("backend")
    if be == "elasticsearch" and es_count is not None:
        idx = {"collection_findings": "ndr-findings-*", "collection_eve": "suricata-eve-*",
               "collection_zeek": "zeek-*"}.get(mid)
        try:
            n = es_count(idx, _utc_day())
            return mb._envelope(metric, quality="fresh", value=[{"labels": {"index": idx}, "v": n}],
                                sample_at=None, source="elasticsearch")
        except Exception as e:                                   # noqa: BLE001
            return mb._envelope(metric, quality="error", reason="es: %s" % type(e).__name__,
                                source="elasticsearch")
    if be == "readyz_probe" and probe_ready is not None:
        svcs = _MANIFEST["_meta"].get("readiness_services", [])
        rows, reachable, notready = [], 0, []
        import time as _t
        for s in svcs:
            try:
                ok = probe_ready(s); reachable += 1
                rows.append({"labels": {"service": s}, "v": 1.0 if ok else 0.0})
                if not ok:
                    notready.append(s)
            except Exception:                                    # noqa: BLE001
                rows.append({"labels": {"service": s}, "v": None})
        if reachable == 0:
            return mb._envelope(metric, quality="error", reason="no readiness probe reachable", source="readyz")
        # we measured readiness now -> quality is fresh; a not-ready service is a measured DOWN state
        # (derived in _state_of from the v=0 rows), never a stale-data signal (review item 1/3).
        return mb._envelope(metric, quality="fresh", value=rows, sample_at=_t.time(),
                            source="readyz", covered=reachable, expected=len(svcs))
    if be == "prometheus":
        return backend.query(mid)
    return mb._envelope(metric, quality="unsupported", reason="source not wired (%s)" % be, source=be)


def build_health(backend, es_count=None, probe_ready=None):
    """R3 verdict: reduce over required checks; report coverage + reasons; never overclaim."""
    checks = []
    for m in _MANIFEST["metrics"]:
        if m.get("criticality") != "required":
            continue
        env = _resolve(m, backend, es_count, probe_ready)
        state, note = _state_of(m["id"], env["quality"], env.get("value"))
        checks.append({"metric_id": m["id"], "quality": env["quality"], "state": state,
                       "reason": (env.get("reason") or note), "value": env.get("value")})
    expected = len(checks)
    # V0 (review items 1-2): a required check is SATISFIED only when it is fresh AND its measured
    # state is ok. A fresh scrape whose value is up=0, or a saturated resource, is not "healthy".
    healthy = [c for c in checks if c["quality"] in _GOOD and c["state"] == "ok"]
    down = [c for c in checks if c["state"] == "down"]                 # measured failure of a required check
    degraded = [c for c in checks if c["state"] == "degraded"]         # fresh but failing/saturated
    unmeasured = [c for c in checks if c["quality"] not in _GOOD]      # stale/no_data/error/unsupported
    if down:
        verdict = "red"
        label = "Required checks failing: " + ", ".join(c["metric_id"] for c in down)
    elif degraded or unmeasured:
        bits = []
        if unmeasured:
            bits.append("%d/%d required checks measured" % (len(healthy) + len(degraded), expected))
        if degraded:
            bits.append("degraded: " + ", ".join(c["metric_id"] for c in degraded))
        verdict = "amber"
        label = "Attention — " + "; ".join(bits)
    else:
        verdict = "green"
        label = "Monitored required checks healthy"
    return {"verdict": verdict, "label": label,
            "coverage": {"healthy": len(healthy), "expected": expected,
                         "down": len(down), "degraded": len(degraded), "unmeasured": len(unmeasured)},
            "checks": checks, "utc_day": _utc_day(),
            "note": "Scoped to monitored capabilities; not a claim of complete telemetry or detection correctness."}


def _state_of(metric_id, quality, value):
    """Derive the MEASURED operational state (ok / degraded / down / unknown) — distinct from
    quality (fresh/stale/error/...). Review item 1: a fresh sample can still report a failed probe
    or a saturated resource. Only finite numeric values count. Returns (state, note)."""
    if quality not in _GOOD:
        return "unknown", ""
    rows = [v for v in (value or []) if isinstance(v, dict)]
    if metric_id == "scrape_up":
        downs = [v.get("labels", {}).get("instance", "?") for v in rows if v.get("v") == 0]
        # broad target set may include optional/expected-down services -> degraded, not a hard outage
        return ("degraded", "scrape target(s) down: " + ", ".join(downs)) if downs else ("ok", "")
    if metric_id == "service_ready":
        downs = [v.get("labels", {}).get("service", "?") for v in rows if v.get("v") == 0]
        return ("down", "not ready: " + ", ".join(downs)) if downs else ("ok", "")
    if metric_id in ("host_cpu", "host_mem", "host_fs"):
        vals = [v.get("v") for v in rows if isinstance(v.get("v"), (int, float))]
        hot = [x for x in vals if x > 95]
        return ("degraded", "%s saturated (%.0f%%)" % (metric_id, max(vals))) if hot else ("ok", "")
    # consumer_lag / collection: measured. Lag > 0 is investigative evidence, never an outage rule (item 4).
    return "ok", ""


def build_collection(es_count):
    """Receiver document counts for the UTC day (A2: ES-specific). Documents are revisions, not
    unique findings; observations are the observed=true subset (surfaced by the caller if needed)."""
    day = _utc_day()
    out = {"utc_day": day, "kind": "documents", "note": "ES document counts (revisions), not packets/unique findings", "cards": []}
    for mid, idx in (("collection_findings", "ndr-findings-*"), ("collection_eve", "suricata-eve-*"),
                     ("collection_zeek", "zeek-*")):
        try:
            out["cards"].append({"metric_id": mid, "index": idx, "count": es_count(idx, day), "quality": "fresh"})
        except Exception as e:                                   # noqa: BLE001
            out["cards"].append({"metric_id": mid, "index": idx, "count": None, "quality": "error",
                                 "reason": type(e).__name__})
    return out


def build_cernity(backend):
    """Pipeline-flow + per-service view. detector_activity is measured (behavioral) once Prometheus
    is up; finals/lag come from the broker (not wired into the seam yet -> unsupported); the diagram
    is a topology aid, not a conservation equation."""
    stages = ["sensor", "fluent-bit", "redpanda", "detectors", "finding-service", "final-topic", "forwarder", "sinks"]
    metrics = {mid: backend.query(mid) if _spec(mid).get("backend") == "prometheus"
               else mb._envelope(_spec(mid), quality="unsupported", reason="source not wired")
               for mid in ("detector_activity", "records_processed", "final_topic_throughput",
                           "consumer_lag", "dlq_unresolved", "finalization_rate", "enrichment_pending")}
    return {"stages": stages, "metrics": metrics,
            "note": "Topology aid, not a conservation equation; candidates may be grouped/suppressed/enriched/retried."}


def build_traffic(backend, window_s=900, step_s=60):
    out = {"window_s": window_s, "step_s": step_s, "series": {}}
    for mid in ("records_processed", "detector_activity", "final_topic_throughput"):
        sp = _spec(mid)
        out["series"][mid] = (backend.query(mid, window_s=window_s, step_s=step_s)
                              if sp.get("backend") == "prometheus"
                              else mb._envelope(sp, quality="unsupported", reason="source not wired", window=window_s))
    return out


def _spec(mid):
    for m in _MANIFEST["metrics"]:
        if m["id"] == mid:
            return m
    raise mb.UnknownMetric(mid)
