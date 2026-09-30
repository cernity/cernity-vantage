"""U6 (B): ATT&CK coverage proxy over U4's read-only coverage API. The proxy must consume the REAL
contract — GET /coverage with a bearer token (tenant is server-derived, never a query param), the
`{"techniques":[...], "gaps":[...], "summary":{...}}` shape that distinguishes a mapped detector
(covered/exists) from an actually-fired technique (observed) — and a degraded/unreachable upstream
must render 'unavailable', never a fake fresh-empty grid. Endpoint fns called directly (no live
upstream); the network seam is monkeypatched. Run: .venv/bin/python -m pytest tests/test_coverage_view.py"""
import os
import re
import sys
import tempfile

os.environ["SOC_DB"] = os.path.join(tempfile.mkdtemp(), "soc.db")  # isolate before import
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import app  # noqa: E402

_OVERVIEW_JS = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                 "static", "overview.js"), encoding="utf-8").read()


def test_coverage_grid_distinguishes_gap_exists_and_observed():
    # REAL U4 shape: techniques carry the detectors mapped to them (fleet-global) + an observed flag
    # (tenant-scoped overlay); gaps list the uncovered technique ids.
    out = app._normalize_coverage({"techniques": [
        {"technique": "T1071", "name": "App Layer Protocol", "detectors": ["ids_signature"], "observed": True},
        {"technique": "T1046", "name": "Network Service Scan", "detectors": ["slips_ml"], "observed": False},
        {"technique": "T1090", "name": "Proxy", "detectors": [], "observed": False}],
        "gaps": ["T1090"], "summary": {"covered": 2, "gaps": 1, "observed": 1}})
    assert out["quality"] == "fresh"
    by = {t["technique"]: t for t in out["techniques"]}
    assert by["T1071"]["covered"] is True and by["T1071"]["observed"] is True     # detector fired
    assert by["T1046"]["covered"] is True and by["T1046"]["observed"] is False    # detector exists, not observed
    assert by["T1090"]["covered"] is False                                        # GAP — no detector
    assert out["gaps"] == ["T1090"] and out["summary"]["gaps"] == 1               # gap highlight + summary preserved


def test_coverage_covered_inferred_from_detectors_or_explicit_flag():
    # covered may be an explicit flag OR inferred from a non-empty detector list; both must land covered.
    out = app._normalize_coverage({"techniques": [
        {"technique_id": "T1", "covered": True, "detectors": []},        # explicit covered, empty detectors
        {"id": "T2", "exists": False, "detectors": ["d"]}]})             # explicit exists=False wins over detectors
    by = {t["technique"]: t for t in out["techniques"]}
    assert by["T1"]["covered"] is True                                  # honored explicit flag + id fallback
    assert by["T2"]["covered"] is False                                 # explicit exists=False, not inferred True


def test_coverage_degraded_payload_is_unavailable_not_fresh_empty():
    for bad in ({"error": "unauthorized"}, {}, None, {"techniques": None}, {"techniques": "oops"},
                {"quality": "unavailable", "techniques": []}, {"quality": "degraded", "techniques": []},
                {"status": "degraded", "techniques": []}, {"degraded": True, "techniques": []}):
        out = app._normalize_coverage(bad)
        assert out["quality"] == "unavailable" and out["techniques"] == [], repr(bad)


def test_coverage_genuine_empty_catalog_is_fresh_not_unavailable():
    out = app._normalize_coverage({"techniques": [], "gaps": [], "summary": {}})
    assert out["quality"] == "fresh" and out["techniques"] == []


def test_coverage_endpoint_unreachable_upstream_is_unavailable(monkeypatch):
    def _boom(_p):
        raise OSError("connection refused")
    monkeypatch.setattr(app, "_coverage_get", _boom)
    out = app.coverage_view()
    assert out["quality"] == "unavailable" and out["reason"] == "OSError"


def test_coverage_proxy_sends_bearer_token_and_hits_coverage(monkeypatch):
    captured = {}

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self, *a):
            return b'{"techniques": [], "gaps": [], "summary": {}}'

    def _fake_urlopen(req, timeout=None):
        captured["url"] = req.full_url
        captured["auth"] = req.headers.get("Authorization")
        return _Resp()

    monkeypatch.setattr(app, "COVERAGE_API_URL", "http://coverage:8095")
    monkeypatch.setattr(app, "COVERAGE_API_TOKEN", "tok-cov")
    monkeypatch.setattr(app.urllib.request, "urlopen", _fake_urlopen)
    out = app.coverage_view()
    assert out["quality"] == "fresh"
    assert captured["url"] == "http://coverage:8095/coverage"     # REAL U4 path
    assert captured["auth"] == "Bearer tok-cov"                   # server-derived tenant, never a query param


def test_no_tenant_query_param_leaks_into_upstream(monkeypatch):
    # §21: tenant is derived upstream from the bearer token; the proxy must never append a tenant= param.
    captured = {}

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self, *a):
            return b'{"techniques": []}'

    def _fake_urlopen(req, timeout=None):
        captured["url"] = req.full_url
        return _Resp()

    monkeypatch.setattr(app, "COVERAGE_API_URL", "http://coverage:8095")
    monkeypatch.setattr(app.urllib.request, "urlopen", _fake_urlopen)
    app.coverage_view()
    assert "tenant" not in captured["url"].lower()


def test_coverage_render_has_no_inline_handler_with_untrusted_value():
    # the coverage/quality render (loadCoverage..loadQueue) must never concatenate a server-supplied
    # value into an inline JS handler — every untrusted value goes through esc() into text/attr sinks.
    region = _OVERVIEW_JS[_OVERVIEW_JS.index("async function loadCoverage"):_OVERVIEW_JS.index("async function loadQueue")]
    assert "onclick" not in region and "javascript:" not in region, "no inline handlers in the coverage view"
    # a raw (un-esc()'d) interpolation of any untrusted field would be the bug — assert none exist.
    for raw in (r"'\+t\.technique\+'", r"'\+t\.name\+'", r"'\+d\.detector_id\+'"):
        assert not re.search(raw, region), "untrusted value must be esc()'d, not raw-concatenated: " + raw


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
