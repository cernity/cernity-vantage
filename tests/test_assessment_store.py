"""A-U2: append-only assessment store + server-side canonical digest (plan 010 KTD-A1..A3)."""
import os
import sqlite3
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import assessment as A  # noqa: E402


def _db():
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    A.init(c)
    return c


def test_digest_stable_under_key_order():
    a = {"b": 1, "a": {"y": 2, "x": 3}}
    b = {"a": {"x": 3, "y": 2}, "b": 1}          # same content, different insertion order
    assert A.source_digest(a) == A.source_digest(b)


def test_digest_array_order_matters():
    assert A.source_digest({"e": [1, 2, 3]}) != A.source_digest({"e": [3, 2, 1]})


def test_digest_absent_is_not_null():
    assert A.source_digest({"a": 1}) != A.source_digest({"a": 1, "b": None})


def test_digest_large_int_exact():
    big = 9007199254740993                          # 2^53 + 1 — loses precision in JS, exact in Python
    assert str(big).encode() in A.canonical_source({"finding_id": big})
    assert A.source_digest({"id": big}) == A.source_digest({"id": big})   # stable


def test_append_projects_and_keeps_history():
    c = _db()
    A.append_and_project(c, "", "f1", 2, "d2", status="investigating", disposition="benign")
    A.append_and_project(c, "", "f1", 3, "d3", status="closed", expected_version=1)
    proj = A.current(c, "", "f1")
    assert proj["status"] == "closed" and proj["disposition"] == "benign"   # threat carried forward
    assert proj["assessed_revision"] == 3 and proj["version"] == 2
    seqs = [h["seq"] for h in A.history(c, "", "f1")]
    assert seqs == sorted(seqs) and len(seqs) >= 3                          # monotonic, all retained


def test_optimistic_version_conflict():
    c = _db()
    A.append_and_project(c, "", "f1", 1, "d1", status="investigating")     # version -> 1
    try:
        A.append_and_project(c, "", "f1", 1, "d1", status="closed", expected_version=0)  # stale
        assert False, "stale expected_version must raise"
    except A.VersionConflict:
        pass
    assert A.current(c, "", "f1")["status"] == "investigating"             # not overwritten


def test_idempotency_key_is_no_op_on_retry():
    c = _db()
    A.append_and_project(c, "", "f1", 1, "d1", status="closed", idempotency_key="k1")
    A.append_and_project(c, "", "f1", 1, "d1", status="closed", idempotency_key="k1")  # retry
    assert A.current(c, "", "f1")["version"] == 1                          # single effect
    assert len(A.history(c, "", "f1")) == 1


def test_new_evidence_flag():
    assert A.new_evidence_since_assessment("dA", "dB") is True
    assert A.new_evidence_since_assessment("dA", "dA") is False
    assert A.new_evidence_since_assessment(None, "dB") is False            # legacy: no assessed digest


def test_append_records_all_axes_and_detector():
    c = _db()
    A.append_and_project(c, "", "f1", 2, "d2", detector_id="ndpi_risk", category="observation",
                         status="closed", disposition="benign", assertion="supported", value_judgment="useful")
    p = A.current(c, "", "f1")
    assert p["detector_id"] == "ndpi_risk" and p["category"] == "observation"
    assert p["disposition"] == "benign" and p["assertion"] == "supported" and p["value_judgment"] == "useful"
    assert {"workflow", "threat", "assertion", "value"} <= {h["kind"] for h in A.history(c, "", "f1")}


def test_detector_rollup_threat_mix_and_support():
    c = _db()
    A.append_and_project(c, "", "f1", 1, "d", detector_id="det1", disposition="confirmed", assertion="supported")
    A.append_and_project(c, "", "f2", 1, "d", detector_id="det1", disposition="benign", assertion="supported")
    A.append_and_project(c, "", "f3", 1, "d", detector_id="det1", assertion="unsupported", status="investigating")
    roll = A.detector_rollup(c)["det1"]
    assert roll["threat"].get("confirmed") == 1 and roll["threat"].get("benign") == 1
    assert roll["assertion"].get("supported") == 2 and roll["assertion"].get("unsupported") == 1
    assert roll["reviewed"] == 3


def test_benign_supported_is_reviewed_not_punished():
    c = _db()
    A.append_and_project(c, "", "f1", 1, "d", detector_id="det1", disposition="benign", assertion="supported")
    roll = A.detector_rollup(c)["det1"]
    # an accurate benign observation is REVIEWED with support recorded — not counted as non-signal
    assert roll["reviewed"] == 1 and roll["assertion"].get("supported") == 1


if __name__ == "__main__":
    for _n, _f in sorted(globals().items()):
        if _n.startswith("test_") and callable(_f):
            _f(); print("ok", _n)
    print("PASS test_assessment_store")
