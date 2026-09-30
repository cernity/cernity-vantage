"""U2 + V0: overview assembly + R3 hero-verdict reduction by MEASURED STATE.

Asserts: collection uses real ES counts (errors surface, not 0); the verdict reduces over required
checks by (quality AND state) — a fresh scrape whose value is up=0 degrades the verdict (V0 review
item 1-2), a not-ready core service is red, and green requires all required checks fresh AND ok.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import metrics_backend as mb
import overview


class FakeBackend:
    """query(metric_id) -> envelope. qmap sets per-id quality (default unsupported); vmap overrides
    the value rows (to simulate up=0 scrapes, saturated hosts, etc.)."""
    def __init__(self, qmap=None, vmap=None):
        self.qmap = qmap or {}
        self.vmap = vmap or {}
    def query(self, metric_id, window_s=None, step_s=None):
        spec = overview._spec(metric_id)
        q = self.qmap.get(metric_id, "unsupported")
        if metric_id in self.vmap:
            val = self.vmap[metric_id]
        else:
            val = [{"labels": {}, "v": 1.0}] if q in ("fresh", "stale") else None
        return mb._envelope(spec, quality=q, value=val)


def _es_ok(idx, day):
    return {"ndr-findings-*": 89127, "suricata-eve-*": 3077388, "zeek-*": 2983915}[idx]


def _all_fresh():
    return {m["id"]: "fresh" for m in overview._MANIFEST["metrics"]}


def test_collection_real_counts():
    c = overview.build_collection(_es_ok)
    ids = {card["metric_id"]: card for card in c["cards"]}
    assert ids["collection_findings"]["count"] == 89127 and ids["collection_findings"]["quality"] == "fresh"


def test_collection_es_error_is_error_not_zero():
    def _boom(idx, day):
        raise RuntimeError("es down")
    c = overview.build_collection(_boom)
    for card in c["cards"]:
        assert card["count"] is None and card["quality"] == "error"


def test_green_only_when_all_required_fresh_and_ok():
    h = overview.build_health(FakeBackend(_all_fresh()), es_count=_es_ok, probe_ready=lambda s: True)
    assert h["verdict"] == "green", h
    assert h["coverage"]["healthy"] == h["coverage"]["expected"]


def test_fresh_scrape_with_down_target_is_not_green():
    # V0 review item 1/2: scrape_up fresh but a target is up=0 -> degraded, verdict amber (NOT green)
    vmap = {"scrape_up": [{"labels": {"instance": "ndr-zeek-central:9108"}, "v": 0.0},
                          {"labels": {"instance": "ndr-finding-service:9108"}, "v": 1.0}]}
    h = overview.build_health(FakeBackend(_all_fresh(), vmap), es_count=_es_ok, probe_ready=lambda s: True)
    assert h["verdict"] == "amber", h["verdict"]
    sc = [c for c in h["checks"] if c["metric_id"] == "scrape_up"][0]
    assert sc["state"] == "degraded" and "ndr-zeek-central:9108" in sc["reason"]
    assert h["coverage"]["degraded"] >= 1


def test_not_ready_core_service_is_red():
    h = overview.build_health(FakeBackend(_all_fresh()), es_count=_es_ok,
                              probe_ready=lambda s: s != "ndr-normalizer")
    assert h["verdict"] == "red", h["verdict"]
    assert "service_ready" in h["label"]


def test_saturated_host_degrades():
    vmap = {"host_cpu": [{"labels": {"host": "central-155"}, "v": 99.2}]}
    h = overview.build_health(FakeBackend(_all_fresh(), vmap), es_count=_es_ok, probe_ready=lambda s: True)
    assert h["verdict"] == "amber"
    hc = [c for c in h["checks"] if c["metric_id"] == "host_cpu"][0]
    assert hc["state"] == "degraded"


def test_partial_monitoring_is_amber_not_green():
    h = overview.build_health(FakeBackend(), es_count=_es_ok, probe_ready=lambda s: True)
    assert h["verdict"] == "amber"
    assert h["coverage"]["healthy"] < h["coverage"]["expected"]


def test_lag_is_not_treated_as_outage():
    # consumer_lag fresh with a big value stays ok (review item 4: lag>0 is not a failure rule)
    vmap = {"consumer_lag": [{"labels": {"group_id": "x"}, "v": 5000.0}]}
    h = overview.build_health(FakeBackend(_all_fresh(), vmap), es_count=_es_ok, probe_ready=lambda s: True)
    cl = [c for c in h["checks"] if c["metric_id"] == "consumer_lag"][0]
    assert cl["state"] == "ok" and h["verdict"] == "green"


def test_cernity_and_traffic_degrade_without_backend():
    b = FakeBackend()
    cer = overview.build_cernity(b)
    assert "stages" in cer and cer["metrics"]["consumer_lag"]["quality"] in ("unsupported", "error")
    tr = overview.build_traffic(b, window_s=900)
    assert tr["window_s"] == 900 and all(s["value"] is None for s in tr["series"].values())


if __name__ == "__main__":
    for _n, _f in sorted(globals().items()):
        if _n.startswith("test_") and callable(_f):
            _f(); print("ok  " + _n)
    print("\nall overview tests passed")
