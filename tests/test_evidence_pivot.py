"""U10 (B): evidence-pivot proxy over U5's read-only evidence API. The proxy must call the REAL
endpoint — GET /observations?entity=&from=&to=&type= with a bearer token — and PRESERVE each
normalized observation.v1 whole (fields + per-observation capability flags), not flatten it to a
summary. A degraded/unreachable upstream renders 'unavailable', never a fresh empty result.
Run: .venv/bin/python -m pytest tests/test_evidence_pivot.py"""
import os
import sys
import tempfile
from urllib.parse import parse_qs, urlparse

os.environ["SOC_DB"] = os.path.join(tempfile.mkdtemp(), "soc.db")  # isolate before import
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import app  # noqa: E402

_OBS = {
    "obs_id": "o1", "type": "dns", "ts": "2026-09-28T00:00:00Z", "tenant": "t1",
    "entities": ["1.2.3.4", "evil.example"],
    "fields": {"query": "evil.example", "rcode": "NOERROR", "answers": ["9.9.9.9"]},
    "capabilities": ["dns.query", "dns.answer"], "source_ref": "zeek:conn:abc",
}


def test_evidence_preserves_full_observation_detail_and_caps():
    out = app._normalize_evidence({"observations": [_OBS],
                                   "capabilities": ["dns.query", "dns.answer"], "next": None})
    assert out["quality"] == "fresh"
    o = out["observations"][0]
    assert o["fields"]["query"] == "evil.example"              # detail preserved, not discarded
    assert o["capabilities"] == ["dns.query", "dns.answer"]    # per-observation capability flags kept
    assert o["source_ref"] == "zeek:conn:abc" and o["entities"] == ["1.2.3.4", "evil.example"]
    assert out["capabilities"] == ["dns.query", "dns.answer"]  # top-level union carried


def test_evidence_degraded_payload_is_unavailable_not_fresh_empty():
    # error body / missing key OR an EXPLICIT degraded/unavailable marker (even wrapping an empty
    # observation list) is a DEGRADED upstream — never relabeled as a fresh empty result.
    for bad in ({"error": "evidence backend unavailable"}, {}, None, {"observations": None},
                {"quality": "degraded", "observations": []}, {"quality": "unavailable", "observations": []},
                {"status": "error", "observations": []}, {"degraded": True, "observations": []}):
        out = app._normalize_evidence(bad)
        assert out["quality"] == "unavailable" and out["observations"] == [], repr(bad)


def test_evidence_genuine_empty_window_is_fresh():
    out = app._normalize_evidence({"observations": [], "capabilities": []})
    assert out["quality"] == "fresh" and out["observations"] == []


def test_evidence_pivot_requires_entity_and_window():
    # U5 is entity+window scoped; without them there is nothing to query -> measured unavailable
    assert app.evidence_pivot("f1")["quality"] == "unavailable"
    assert app.evidence_pivot("f1", entity="1.2.3.4")["quality"] == "unavailable"


def test_evidence_pivot_calls_real_observations_endpoint(monkeypatch):
    captured = {}

    def _fake_get(path):
        captured["path"] = path
        return {"observations": [_OBS], "capabilities": ["dns.query"]}

    monkeypatch.setattr(app, "_evidence_get", _fake_get)
    out = app.evidence_pivot("f1", entity="1.2.3.4", frm="2026-09-27T00:00:00Z",
                             to="2026-09-28T00:00:00Z", otype="dns")
    assert out["quality"] == "fresh" and out["observations"][0]["obs_id"] == "o1"
    u = urlparse(captured["path"])
    assert u.path == "/observations"                          # REAL U5 endpoint, not /findings/.../observations
    q = parse_qs(u.query)
    assert q["entity"] == ["1.2.3.4"] and q["from"] == ["2026-09-27T00:00:00Z"]
    assert q["to"] == ["2026-09-28T00:00:00Z"] and q["type"] == ["dns"]


def test_evidence_pivot_unreachable_upstream_is_unavailable(monkeypatch):
    def _boom(_p):
        raise OSError("connection refused")
    monkeypatch.setattr(app, "_evidence_get", _boom)
    out = app.evidence_pivot("f1", entity="1.2.3.4", frm="2026-09-27T00:00:00Z", to="2026-09-28T00:00:00Z")
    assert out["quality"] == "unavailable" and out["reason"] == "OSError"


def test_evidence_proxy_sends_bearer_token(monkeypatch):
    captured = {}

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self, *a):
            return b'{"observations": [], "capabilities": []}'

    def _fake_urlopen(req, timeout=None):
        captured["auth"] = req.headers.get("Authorization")
        captured["url"] = req.full_url
        return _Resp()

    monkeypatch.setattr(app, "EVIDENCE_API_URL", "http://evidence:8092")
    monkeypatch.setattr(app, "EVIDENCE_API_TOKEN", "tok-xyz")
    monkeypatch.setattr(app.urllib.request, "urlopen", _fake_urlopen)
    out = app.evidence_pivot("f1", entity="1.2.3.4", frm="2026-09-27T00:00:00Z", to="2026-09-28T00:00:00Z")
    assert out["quality"] == "fresh"
    assert captured["auth"] == "Bearer tok-xyz"               # authenticated reader (else upstream 401s)
    assert captured["url"].startswith("http://evidence:8092/observations?")


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
