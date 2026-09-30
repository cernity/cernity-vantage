"""U6: InfluxDB 3 (InfluxQL) alternate backend + cross-store parity.

Parity is contract-level (review R2): the normalized ENVELOPE must match across Prometheus and
InfluxDB for the same metric_id (unit/kind/dimensions/quality semantics), even though counter-rate
VALUES differ (PromQL rate() extrapolation vs InfluxQL non_negative_derivative). A required supported
metric must produce a measured value on BOTH stacks; all-unknown parity does not pass.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import metrics_backend as mb
import influx_backend as ib

FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "metrics")


def _fix(name):
    with open(os.path.join(FIX, name), encoding="utf-8") as fh:
        return json.load(fh)


def _influx(fake):
    b = ib.InfluxBackend(url="http://influx.test:8181", database="cernity")
    def _get(url, timeout=None):
        if isinstance(fake, Exception):
            raise fake
        return fake
    mb._http_get_json = _get
    return b


def _prom(fake):
    b = mb.PromBackend(url="http://prom.test:9090")
    def _get(url, timeout=None):
        if isinstance(fake, Exception):
            raise fake
        return fake
    mb._http_get_json = _get
    return b


def test_influx_normalizes_same_envelope():
    b = _influx(_fix("synthetic_influx_instant.json"))
    r = b.query("detector_activity")
    assert r["quality"] in ("fresh", "stale"), r["quality"]
    assert r["source"] == "influxdb3" and r["metric_id"] == "detector_activity"
    assert r["value"] and r["value"][0]["labels"].get("detector_id") == "ndpi_risk"


def test_envelope_shape_parity_across_stores():
    prom = _prom(_fix("synthetic_prom_query_instant.json")).query("detector_activity")
    infl = _influx(_fix("synthetic_influx_instant.json")).query("detector_activity")
    # same contract fields + same semantic identity; values may differ by dialect (tolerance-bounded)
    assert set(prom.keys()) == set(infl.keys())
    for k in ("metric_id", "unit", "kind", "dimensions", "criticality"):
        assert prom[k] == infl[k], "parity mismatch on %s" % k
    assert prom["quality"] in ("fresh", "stale") and infl["quality"] in ("fresh", "stale")  # measured on both


def test_collection_is_unsupported_on_influx():
    b = _influx(_fix("synthetic_influx_instant.json"))
    r = b.query("collection_findings")
    assert r["quality"] == "unsupported" and "ES-specific" in r["reason"]


def test_metric_without_influxql_twin_is_unsupported():
    b = _influx(_fix("synthetic_influx_instant.json"))
    r = b.query("evaluate_latency")            # available on prom, no InfluxQL twin
    assert r["quality"] == "unsupported"


def test_unknown_metric_raises():
    b = _influx(_fix("synthetic_influx_instant.json"))
    try:
        b.query("nope_xyz"); assert False
    except mb.UnknownMetric:
        pass


def test_backend_error_is_typed_not_zero():
    b = _influx(mb.BackendError("influx down"))
    r = b.query("detector_activity")
    assert r["quality"] == "error" and r["value"] is None


def test_influx_error_body_surfaces():
    b = _influx({"results": [{"error": "database not found"}]})
    r = b.query("detector_activity")
    assert r["quality"] == "error"


def test_factory_selects_influx():
    saved = mb.BACKEND
    try:
        mb.BACKEND = "influxdb3"
        assert isinstance(mb.get_backend(), ib.InfluxBackend)
    finally:
        mb.BACKEND = saved


if __name__ == "__main__":
    for _n, _f in sorted(globals().items()):
        if _n.startswith("test_") and callable(_f):
            _f(); print("ok  " + _n)
    print("\nall influx_backend + parity tests passed")
