"""Bounded finding analytics for the Overview (plan 012 V3). Pure — the caller injects an
`es_search(index, body)` callable (app.py's `_es`). Server-side aggregations only (never counting
a page of hits). The review's central trap: a finding has many REVISION documents; advertising a
per-revision count as "unique findings" inflates it. So `unique_findings` is a cardinality over
`finding_id.keyword` (revision-deduped), and the category mix is explicitly labeled as being over
revision documents until the latest-revision/assessment join is built. Severity is a basis signal,
classification is a lead — never a composite security score.
"""
_INDEX = "ndr-findings-*"


def classification_summary(es_search, index=_INDEX):
    body = {"size": 0, "track_total_hits": True, "aggs": {
        "unique": {"cardinality": {"field": "finding_id.keyword"}},
        "by_cat": {"terms": {"field": "category.keyword", "size": 20}},
        "observed": {"filter": {"term": {"observed": True}},
                     "aggs": {"u": {"cardinality": {"field": "finding_id.keyword"}}}},
        "needs": {"filter": {"term": {"category.keyword": "unclassified"}},
                  "aggs": {"u": {"cardinality": {"field": "finding_id.keyword"}}}},
    }}
    try:
        r = es_search(index, body)
    except Exception as e:                                        # noqa: BLE001
        return {"quality": "error", "reason": type(e).__name__, "note": "ES aggregation failed"}
    aggs = r.get("aggregations", {})
    total = _total(r)
    return {
        "quality": "fresh",
        "revision_docs": total,                                   # documents (all revisions)
        "unique_findings": aggs.get("unique", {}).get("value", 0), # deduped by finding_id
        "observations_unique": aggs.get("observed", {}).get("u", {}).get("value", 0),
        "needs_classification_unique": aggs.get("needs", {}).get("u", {}).get("value", 0),
        "categories": [{"category": b["key"], "revision_docs": b["doc_count"]}
                       for b in aggs.get("by_cat", {}).get("buckets", [])],
        "unique_approximate": True,   # ES cardinality is HyperLogLog (~1% error); ~= revision_docs when mostly single-revision
        "note": "category mix is over REVISION DOCUMENTS; unique_findings is an APPROXIMATE cardinality "
                "dedupe by finding_id (latest-revision-only mix is gated on the assessment join). Not a threat count.",
    }


def evidence_coverage(es_search, index=_INDEX):
    body = {"size": 0, "track_total_hits": True, "aggs": {"with_ev": {"filter": {"exists": {"field": "evidence_refs"}}}}}
    try:
        r = es_search(index, body)
    except Exception as e:                                        # noqa: BLE001
        return {"quality": "error", "reason": type(e).__name__}
    total = _total(r)
    present = r.get("aggregations", {}).get("with_ev", {}).get("doc_count", 0)
    return {
        "quality": "fresh",
        "total_docs": total, "with_evidence_refs": present, "without_evidence_refs": max(total - present, 0),
        "note": "evidence_refs PRESENCE over revision documents — a reference is not proof the capture "
                "is still retained/retrievable (denominator shown, not a coverage guarantee).",
    }


def _total(r):
    t = r.get("hits", {}).get("total", 0)
    return t.get("value", 0) if isinstance(t, dict) else t
