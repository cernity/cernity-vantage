"""A-U3b: capability-checked field resolution (KTD-A5) + search_after pagination.
Imports app -> runs in-container (fastapi). Pure _resolve_field is tested with fabricated
_field_caps shapes; pagination is tested with a fake _es."""
import os
import sys
import tempfile

os.environ.setdefault("SOC_DB", os.path.join(tempfile.mkdtemp(), "soc.db"))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import app  # noqa: E402


def test_resolve_uniform_keyword():
    fc = {"category": {"keyword": {"type": "keyword", "aggregatable": True, "searchable": True}}}
    assert app._resolve_field("category", fc) == "category"


def test_resolve_text_with_keyword_multifield():
    fc = {"category": {"text": {"type": "text", "aggregatable": False}},
          "category.keyword": {"keyword": {"type": "keyword", "aggregatable": True}}}
    assert app._resolve_field("category", fc) == "category.keyword"


def test_resolve_text_only_is_conflict():
    fc = {"category": {"text": {"type": "text", "aggregatable": False}}}
    try:
        app._resolve_field("category", fc); assert False, "text-only must conflict"
    except app.MappingConflict:
        pass


def test_resolve_mixed_types_no_clean_keyword_is_conflict():
    fc = {"category": {"keyword": {"type": "keyword", "aggregatable": True, "indices": ["a"],
                                   "non_aggregatable_indices": ["b"]},
                       "text": {"type": "text", "aggregatable": False, "indices": ["b"]}}}
    try:
        app._resolve_field("category", fc); assert False, "mixed types must conflict"
    except app.MappingConflict:
        pass


def test_resolve_keyword_multifield_not_uniform_is_conflict():
    fc = {"category": {"text": {"type": "text", "aggregatable": False}},
          "category.keyword": {"keyword": {"type": "keyword", "aggregatable": True,
                                           "non_aggregatable_indices": ["b"]}}}
    try:
        app._resolve_field("category", fc); assert False, ".keyword not uniform must conflict"
    except app.MappingConflict:
        pass


def _install_fake_es(total_relation, page_hits, page_size):
    app._agg_field = lambda name, index=None: name + ".keyword"        # stub capability lookup

    def fake_es(path, body):
        if body.get("size") == 0:                                      # facets call
            return {"aggregations": {"cat": {"buckets": []}, "det": {"buckets": []}}}
        hits = [{"_id": "d%d" % i, "_index": "ndr-findings-x",
                 "_source": {"finding_id": "f%d" % i, "@timestamp": "2026-09-25T00:00:00"},
                 "sort": [i, "f%d" % i]} for i in range(page_hits)]
        return {"hits": {"total": {"value": 10000, "relation": total_relation}, "hits": hits}}
    app._es = fake_es
    return page_size


def test_pagination_full_page_returns_cursor():
    _install_fake_es("gte", page_hits=5, page_size=5)
    out = app.findings(size=5)
    assert out["total"] == 10000 and out["total_relation"] == "gte"    # lower-bound total
    assert out["next_after"], "a full page must hand back a search_after cursor"


def test_pagination_partial_page_no_cursor():
    _install_fake_es("eq", page_hits=3, page_size=5)
    out = app.findings(size=5)
    assert out["total_relation"] == "eq"
    assert out["next_after"] == "", "a partial page must not hand back a cursor"


if __name__ == "__main__":
    for _n, _f in sorted(globals().items()):
        if _n.startswith("test_") and callable(_f):
            _f(); print("ok", _n)
    print("PASS test_agg_field")
