"""U1: MetricsBackend seam + Prometheus adapter. Pure stdlib; runs anywhere.

Fakes the HTTP layer with the fixtures in tests/fixtures/metrics/. Asserts the R2 normalized
contract, the named-query allowlist, unknown-vs-unsupported distinction, and that failures
surface as quality=error — never a fabricated 0/green.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import metrics_backend as mb

FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "metrics")


def _fix(name):
    with open(os.path.join(FIX, name), encoding="utf-8") as fh:
        return json.load(fh)


def _backend(fake):
    """PromBackend whose HTTP layer returns `fake` (a dict) or raises (an Exception instance)."""
    b = mb.PromBackend(url="http://prom.test:9090")
    def _get(url, timeout=None):
        if isinstance(fake, Exception):
            raise fake
        return fake
    mb._http_get_json = _get
    return b


def test_instant_normalizes_to_r2_contract():
    b = _backend(_fix("synthetic_prom_query_instant.json"))
    r = b.query("detector_activity")
    assert r["quality"] in ("fresh", "stale"), r["quality"]
    assert r["metric_id"] == "detector_activity" and r["unit"] == "candidates_per_s"
    assert r["value"] and r["value"][0]["labels"]["detector_id"] == "ndpi_risk"
    for k in ("contract_version", "kind", "dimensions", "sample_at", "evaluated_at", "quality", "source"):
        assert k in r, "missing R2 field %s" % k
    assert r["series"] is None       # instant -> value, not series


def test_range_returns_series_with_gaps_preserved():
    b = _backend(_fix("synthetic_prom_query_range.json"))
    r = b.query("records_processed", window_s=900, step_s=60)
    assert r["series"] and r["series"][0]["labels"]["event_type"] == "flow"
    assert len(r["series"][0]["points"]) == 3
    assert r["window"] == 900 and r["value"] is None


def test_unknown_metric_id_is_programmer_error():
    b = _backend(_fix("synthetic_prom_query_instant.json"))
    try:
        b.query("no_such_metric_xyz")
        assert False, "expected UnknownMetric"
    except mb.UnknownMetric:
        pass


def test_unsupported_metric_degrades_not_zero():
    # pcap_retained is status=needs-wiring (MinIO inventory not wired) -> unsupported, never a fake 0
    b = _backend(_fix("synthetic_prom_query_instant.json"))
    r = b.query("pcap_retained")
    assert r["quality"] == "unsupported", r["quality"]
    assert r["value"] is None and r["series"] is None


def test_backend_error_is_typed_never_fake_zero():
    b = _backend(mb.BackendError("boom unreachable"))
    r = b.query("detector_activity")
    assert r["quality"] == "error", r["quality"]
    assert r["value"] is None                 # NOT 0/green
    assert "boom" in r["reason"] or "unreachable" in r["reason"]


def test_prometheus_error_status_surfaces_as_error():
    b = _backend(_fix("synthetic_prom_error.json"))
    r = b.query("detector_activity")
    assert r["quality"] == "error"
    assert r["value"] is None


def test_empty_result_is_no_data_not_zero():
    b = _backend({"status": "success", "data": {"resultType": "vector", "result": []}})
    r = b.query("records_processed")
    assert r["quality"] == "no_data"
    assert r["value"] is None


def test_stale_when_sample_older_than_freshness_limit():
    old = 1.0  # epoch 1970 -> way older than freshness_s
    b = _backend({"status": "success", "data": {"resultType": "vector",
                  "result": [{"metric": {"detector_id": "ndpi_risk"}, "value": [old, "1.0"]}]}})
    r = b.query("detector_activity")
    assert r["quality"] == "stale", r["quality"]
    assert r["value"] is not None and r["sample_at"] == old


def test_config_selects_backend():
    # default is prometheus; the factory returns a PromBackend
    assert isinstance(mb.get_backend(), mb.PromBackend)


if __name__ == "__main__":
    for _n, _f in sorted(globals().items()):
        if _n.startswith("test_") and callable(_f):
            _f(); print("ok  " + _n)
    print("\nall metrics_backend tests passed")
