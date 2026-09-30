"""A-U7: local mapping-review request backlog — never mutates findings, no outbound (plan 010)."""
import os
import sqlite3
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import assessment as A  # noqa: E402


def _db():
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    A.init_requests(c)
    return c


def test_create_is_submitted_and_listed():
    c = _db()
    rid = A.create_request(c, finding_id="f1", detector_id="ndpi_risk", risk_name="Susp Entropy",
                           explanation="unknown risk, needs a rule", proposed="observation")
    reqs = A.list_requests(c, "f1")
    assert len(reqs) == 1 and reqs[0]["id"] == rid
    assert reqs[0]["state"] == "submitted"                 # saved to the local queue
    assert reqs[0]["proposed"] == "observation"


def test_state_transitions_and_history():
    c = _db()
    rid = A.create_request(c, finding_id="f1", explanation="x")
    A.set_request_state(c, rid, "reviewing")
    A.set_request_state(c, rid, "resolved", note="mapped to observation")
    assert A.list_requests(c, "f1")[0]["state"] == "resolved"
    hist = [r["state"] for r in c.execute(
        "SELECT state FROM mapping_request_history WHERE request_id=? ORDER BY id", (rid,))]
    assert hist == ["submitted", "reviewing", "resolved"]


def test_invalid_state_rejected():
    c = _db()
    rid = A.create_request(c, finding_id="f1", explanation="x")
    try:
        A.set_request_state(c, rid, "malware"); assert False, "invalid state must raise"
    except ValueError:
        pass


def test_request_does_not_touch_the_finding():
    c = _db()
    A.init(c)
    A.append_and_project(c, "", "f1", 1, "d", detector_id="det", disposition="benign")
    before = A.current(c, "", "f1")
    A.create_request(c, finding_id="f1", explanation="reclassify?", proposed="malware")  # a proposal only
    assert A.current(c, "", "f1") == before, "a mapping request must never relabel the finding"


if __name__ == "__main__":
    for _n, _f in sorted(globals().items()):
        if _n.startswith("test_") and callable(_f):
            _f(); print("ok", _n)
    print("PASS test_mapping_requests")
