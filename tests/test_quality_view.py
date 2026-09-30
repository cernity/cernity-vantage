"""U6 (B): detection-quality proxy over U5's read-only quality API. The proxy must consume the REAL
contract — GET /quality?from=&to= with a bearer token (tenant is server-derived, never a query param),
the report shape with per-detector `precision`/`fp_rate` (finding-joined) kept SEPARATE from the
top-level `entity_allowlist_suggestion_rate` (entity-scoped, advisory) — and a degraded/unreachable
upstream must render 'unavailable', never a fake fresh-empty table. Endpoint fns called directly (no
live upstream); the network seam is monkeypatched. Run: .venv/bin/python -m pytest tests/test_quality_view.py"""
import os
import re
import sys
import tempfile

os.environ["SOC_DB"] = os.path.join(tempfile.mkdtemp(), "soc.db")  # isolate before import
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import app  # noqa: E402

_OVERVIEW_JS = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                 "static", "overview.js"), encoding="utf-8").read()


def _rate(num, den, low=False):  # the U5 quality.rate() envelope shape
    return {"numerator": num, "denominator": den, "value": (num / den) if den else None,
            "confidence_interval": {"lower": 0.1, "upper": 0.9} if den else None, "low_confidence": low}


# A real U5 /quality 200 body (feedback-quality.report): per-detector precision/fp + a SEPARATE
# entity-allowlist rate, each carrying its Wilson interval + low_confidence flag.
_REAL_QUALITY = {
    "schema_version": "quality.v1", "tenant": "acme",
    "window": {"from": "2026-09-01T00:00:00+00:00", "to": "2026-09-29T00:00:00+00:00",
               "time_basis": "disposition.ts", "bounds": "[from,to)"},
    "unit": "disposition_records", "interval_method": "wilson_95",
    "low_confidence_below": 30, "advisory_only": True,
    "total_dispositions": 120, "unattributed_dispositions": 4,
    "detectors": [
        {"detector_id": "ids_signature", "counts": {"true_positive": 40, "false_positive": 5, "benign": 5},
         "precision": _rate(40, 50), "fp_rate": _rate(10, 50)},
        {"detector_id": "slips_ml", "counts": {"true_positive": 2, "false_positive": 1, "benign": 0},
         "precision": _rate(2, 3, low=True), "fp_rate": _rate(1, 3, low=True)}],
    "entity_allowlist_suggestion_rate": _rate(16, 120)}


def test_quality_table_preserves_per_detector_and_allowlist_separately():
    out = app._normalize_quality(_REAL_QUALITY)
    assert out["quality"] == "fresh"
    by = {d["detector_id"]: d for d in out["detectors"]}
    # per-detector precision/fp finding-joined, verbatim (incl. counts + intervals + low_confidence)
    assert by["ids_signature"]["precision"]["value"] == 0.8
    assert by["ids_signature"]["counts"] == {"true_positive": 40, "false_positive": 5, "benign": 5}
    assert by["slips_ml"]["precision"]["low_confidence"] is True                 # thin data -> low-confidence
    # the advisory allowlist rate is SEPARATE — never folded into a detector's precision
    assert out["entity_allowlist_suggestion_rate"]["value"] == 16 / 120
    assert out["advisory_only"] is True and out["low_confidence_below"] == 30


def test_quality_degraded_payload_is_unavailable_not_fresh_empty():
    for bad in ({"error": "quality unavailable"}, {}, None, {"detectors": None}, {"detectors": "oops"},
                {"quality": "degraded", "detectors": []}, {"status": "degraded", "detectors": []},
                {"degraded": True, "detectors": []}):
        out = app._normalize_quality(bad)
        assert out["quality"] == "unavailable" and out["detectors"] == [], repr(bad)


def test_quality_genuine_empty_window_is_fresh_not_unavailable():
    # a real window with no dispositions: detectors [] but the allowlist rate is a measured unknown.
    out = app._normalize_quality({"detectors": [], "entity_allowlist_suggestion_rate": _rate(0, 0),
                                  "total_dispositions": 0})
    assert out["quality"] == "fresh" and out["detectors"] == []
    assert out["entity_allowlist_suggestion_rate"]["value"] is None              # unknown, never a fake 0%


def test_quality_endpoint_unreachable_upstream_is_unavailable(monkeypatch):
    def _boom(_p):
        raise OSError("connection refused")
    monkeypatch.setattr(app, "_quality_get", _boom)
    out = app.quality_view()
    assert out["quality"] == "unavailable" and out["reason"] == "OSError"


def test_quality_proxy_sends_window_bearer_token_and_hits_quality(monkeypatch):
    import json
    captured = {}

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self, *a):
            return json.dumps(_REAL_QUALITY).encode()

    def _fake_urlopen(req, timeout=None):
        captured["url"] = req.full_url
        captured["auth"] = req.headers.get("Authorization")
        return _Resp()

    monkeypatch.setattr(app, "QUALITY_API_URL", "http://feedback:8094")
    monkeypatch.setattr(app, "QUALITY_API_TOKEN", "tok-q")
    monkeypatch.setattr(app.urllib.request, "urlopen", _fake_urlopen)
    out = app.quality_view()
    assert out["quality"] == "fresh"
    assert captured["url"].startswith("http://feedback:8094/quality?")            # REAL U5 path
    assert "from=" in captured["url"] and "to=" in captured["url"]                # U5 requires a window
    assert "tenant" not in captured["url"].lower()                               # §21: never a tenant param
    assert captured["auth"] == "Bearer tok-q"                                     # server-derived tenant identity


def test_quality_defaults_a_timezone_aware_window(monkeypatch):
    # U5 400s without a tz-aware [from,to); the proxy must default one the upstream accepts.
    captured = {}
    from urllib.parse import parse_qs, urlsplit

    def _cap(path):
        captured["path"] = path
        return _REAL_QUALITY
    monkeypatch.setattr(app, "_quality_get", _cap)
    app.quality_view()
    qs = parse_qs(urlsplit(captured["path"]).query)
    assert set(qs) == {"from", "to"}                                             # exactly what U5 accepts
    for k in ("from", "to"):
        # timezone-aware ISO (offset present) — datetime.fromisoformat would accept it
        assert re.search(r"[+-]\d\d:\d\d$", qs[k][0]), qs[k][0]


def test_quality_render_has_no_inline_handler_with_untrusted_value():
    region = _OVERVIEW_JS[_OVERVIEW_JS.index("function _qpct"):_OVERVIEW_JS.index("async function loadQueue")]
    assert "onclick" not in region and "javascript:" not in region, "no inline handlers in the quality view"
    for raw in (r"'\+d\.detector_id\+'", r"'\+r\.numerator\+'", r"'\+r\.denominator\+'"):
        assert not re.search(raw, region), "untrusted value must be esc()'d, not raw-concatenated: " + raw


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
