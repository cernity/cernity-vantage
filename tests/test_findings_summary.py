"""V3 proof-first: the classification summary must NOT inflate revision documents into unique
findings. 3 revision docs of one finding_id -> unique_findings=1, revision_docs=3."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import findings_summary as fs


def _es_three_revisions_one_finding(index, body):
    # simulates ES: 3 revision docs, cardinality(finding_id)=1, all category=observation
    return {"hits": {"total": {"value": 3}}, "aggregations": {
        "unique": {"value": 1},
        "by_cat": {"buckets": [{"key": "observation", "doc_count": 3}]},
        "observed": {"doc_count": 3, "u": {"value": 1}},
        "needs": {"doc_count": 0, "u": {"value": 0}},
        "with_ev": {"doc_count": 2},
    }}


def test_revisions_do_not_inflate_unique_findings():
    s = fs.classification_summary(_es_three_revisions_one_finding)
    assert s["revision_docs"] == 3, s
    assert s["unique_findings"] == 1, "3 revisions of one finding must count as 1 unique finding"
    assert s["observations_unique"] == 1
    assert s["categories"][0]["category"] == "observation"
    assert "REVISION DOCUMENTS" in s["note"]


def test_evidence_coverage_denominator():
    e = fs.evidence_coverage(_es_three_revisions_one_finding)
    assert e["total_docs"] == 3 and e["with_evidence_refs"] == 2 and e["without_evidence_refs"] == 1


def test_es_error_surfaces_not_zero():
    def _boom(i, b): raise RuntimeError("es down")
    s = fs.classification_summary(_boom)
    assert s["quality"] == "error" and "unique_findings" not in s


if __name__ == "__main__":
    for _n, _f in sorted(globals().items()):
        if _n.startswith("test_") and callable(_f):
            _f(); print("ok  " + _n)
    print("\nall findings_summary tests passed")
