"""U10 (C): disposition.v1 emit on a finding disposition AND on an allowlist-add, each matching
docs/disposition.schema.json. The bus is BEST-EFFORT — a broker outage must never fail the
analyst's write-back. Endpoint functions are called directly (no live ES/broker), following the
test_api_contract pattern; emits are captured via app._emit_sink."""
import json
import os
import sys
import tempfile

os.environ["SOC_DB"] = os.path.join(tempfile.mkdtemp(), "soc.db")  # isolate before import
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import app  # noqa: E402
import jsonschema  # noqa: E402

_SCHEMA = json.load(open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                      "docs", "disposition.schema.json"), encoding="utf-8"))


def _capture():
    """Redirect emits into a list; returns (events, restore)."""
    events = []
    prev = app._emit_sink
    app._emit_sink = events.append
    return events, (lambda: setattr(app, "_emit_sink", prev))


def _valid(ev):
    jsonschema.validate(ev, _SCHEMA)   # raises on any schema violation


def test_build_finding_disposition_is_schema_valid():
    ev = app.build_disposition(finding_id="f1", entity={"type": "ip", "value": "1.2.3.4"},
                               verdict="true_positive", reason="c2 beacon", analyst="me", scope="finding")
    _valid(ev)
    assert ev["finding_id"] == "f1" and ev["scope"] == "finding" and ev["entity"]["value"] == "1.2.3.4"


def test_build_allowlist_forces_entity_scope_and_nullable_id():
    ev = app.build_disposition(finding_id=None, entity={"type": "ip", "value": "9.9.9.9"},
                               verdict="allowlist", reason="DoH", analyst="me", scope="finding")
    _valid(ev)                                  # allowlist -> scope coerced to 'entity', null id allowed
    assert ev["scope"] == "entity" and ev["finding_id"] is None


def test_build_rejects_non_allowlist_without_finding_id():
    for bad in (None, "", "   "):
        try:
            app.build_disposition(finding_id=bad, entity={"type": "ip", "value": "1.1.1.1"},
                                   verdict="benign", reason="x", analyst="me", scope="finding")
            assert False, "expected ValueError for finding_id=%r" % bad
        except ValueError:
            pass


def test_build_coerces_bad_entity_to_asset_keyed_by_finding_id():
    ev = app.build_disposition(finding_id="f7", entity=None, verdict="benign",
                               reason="", analyst="", scope="finding")
    _valid(ev)                                  # blank reason/analyst filled; entity falls back to asset
    assert ev["entity"] == {"type": "asset", "value": "f7"}
    assert ev["reason"] and ev["analyst"]


def test_set_disposition_emits_valid_v1_on_verdict():
    events, restore = _capture()
    try:
        r = app.set_disposition("fd1", {"status": "investigating", "disposition": "confirmed",
                                         "owner": "amy", "entity": {"type": "ip", "value": "10.0.0.5"}})
        assert r.get("ok") is True
        assert len(events) == 1
        ev = events[0]
        _valid(ev)
        assert ev["verdict"] == "true_positive" and ev["finding_id"] == "fd1"
        assert ev["analyst"] == "amy" and ev["entity"]["value"] == "10.0.0.5"
    finally:
        restore()


def test_suspicious_does_not_emit_a_true_positive():
    # 'suspicious' is an UNCONFIRMED lead, not a confirmed threat — it must NOT be broadcast as a
    # true_positive (that would feed a suspicion into feedback-service as confirmed ground truth).
    events, restore = _capture()
    try:
        r = app.set_disposition("fs1", {"status": "investigating", "disposition": "suspicious",
                                         "owner": "amy"})
        assert r.get("ok") is True
        assert events == [], "suspicious must not emit any disposition.v1 (esp. not true_positive)"
    finally:
        restore()


def test_set_disposition_no_emit_without_verdict():
    events, restore = _capture()
    try:
        app.set_disposition("fd2", {"status": "investigating", "disposition": ""})   # no verdict chosen
        assert events == []
    finally:
        restore()


def test_allowlist_add_emits_valid_allowlist_v1():
    events, restore = _capture()
    try:
        r = app.allowlist_add({"field": "dst_ip", "value": "9.9.9.9", "reason": "known DoH",
                               "created_by": "amy"})
        assert r.get("ok") is True
        assert len(events) == 1
        ev = events[0]
        _valid(ev)
        assert ev["verdict"] == "allowlist" and ev["scope"] == "entity"
        assert ev["finding_id"] is None and ev["entity"] == {"type": "ip", "value": "9.9.9.9"}
        assert ev["reason"] == "known DoH" and ev["analyst"] == "amy"
    finally:
        restore()


def test_allowlist_category_rule_rides_as_asset():
    events, restore = _capture()
    try:
        app.allowlist_add({"field": "category", "value": "observation", "created_by": "amy"})
        ev = events[0]
        _valid(ev)                              # category isn't an endpoint -> entity type 'asset'
        assert ev["entity"] == {"type": "asset", "value": "observation"}
    finally:
        restore()


def test_bus_outage_does_not_raise_or_fail_writeback():
    # 1) a raising sink at the write path is swallowed -> the endpoint still returns ok.
    prev = app._emit_sink
    app._emit_sink = lambda ev: (_ for _ in ()).throw(RuntimeError("bus down"))
    try:
        assert app.set_disposition("fd3", {"status": "new", "disposition": "benign"}).get("ok") is True
        assert app.allowlist_add({"field": "src_ip", "value": "8.8.8.8"}).get("ok") is True
    finally:
        app._emit_sink = prev
    # 2) emit_disposition's own broker branch swallows a producer failure (no _emit_sink set).
    fake = type(sys)("kafka")
    def _boom(**kw):
        raise RuntimeError("NoBrokersAvailable")
    fake.KafkaProducer = _boom
    sys.modules["kafka"] = fake
    app._emit_sink = None
    try:
        app.emit_disposition({"finding_id": "x", "entity": {"type": "ip", "value": "1.1.1.1"},
                              "verdict": "benign", "reason": "r", "analyst": "a",
                              "ts": "2026-09-28T00:00:00Z", "scope": "finding"})  # must not raise
    finally:
        sys.modules.pop("kafka", None)
        app._emit_sink = prev


if __name__ == "__main__":
    for _n, _f in sorted(globals().items()):
        if _n.startswith("test_") and callable(_f):
            _f(); print("ok", _n)
    print("PASS test_disposition_emit")
