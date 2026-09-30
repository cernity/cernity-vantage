"""U10 (A): fleet-health proxy over U3a's read-only fleet API. The proxy must consume the REAL
contract — GET /sensors with a bearer token (tenant is server-derived, never a query param), the
`{"sensors":[sensor_view(...)]}` shape keyed by sensor_uuid — and a degraded/unreachable upstream
must render 'unavailable', never a fresh empty list. Endpoint fns called directly (no live upstream);
the network seam is monkeypatched. Run: .venv/bin/python -m pytest tests/test_fleet_view.py"""
import os
import sys
import tempfile

os.environ["SOC_DB"] = os.path.join(tempfile.mkdtemp(), "soc.db")  # isolate before import
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import app  # noqa: E402


def test_fleet_normalizes_real_sensor_shape_keyed_by_uuid():
    # REAL U3a sensor_view fields: sensor_uuid, clock_offset_ms, skew_flag, staleness.
    out = app._normalize_fleet({"sensors": [
        {"sensor_uuid": "s-1", "status": "healthy", "stale": False,
         "clock_offset_ms": 50, "skew_flag": False, "last_seen": "2026-09-28T00:00:00Z"},
        {"sensor_uuid": "s-2", "status": "degraded", "stale": True,
         "clock_offset_ms": 5000, "skew_flag": True, "last_heartbeat_at": "2026-09-27T00:00:00Z"}]})
    assert out["quality"] == "fresh"
    assert [s["sensor_id"] for s in out["sensors"]] == ["s-1", "s-2"]     # sensor_uuid is the id
    assert out["sensors"][1]["clock_skew_flag"] is True and out["sensors"][1]["stale"] is True
    assert out["sensors"][0]["clock_skew_s"] == 0.05                       # ms -> s
    assert out["sensors"][0]["clock_offset_ms"] == 50                      # documented field carried through


def test_fleet_stale_offline_sensor_surfaces_as_stale():
    out = app._normalize_fleet({"sensors": [{"sensor_uuid": "s-9", "stale": True}]})
    s = out["sensors"][0]
    assert s["stale"] is True and s["health"] == "stale"


def test_fleet_trusts_registry_skew_flag_not_a_proxy_side_threshold():
    # The registry computes skew_flag server-side against SKEW_THRESHOLD_MS (default 100ms). The proxy
    # must TRUST it: an offset of 150ms with skew_flag=true is flagged (the earlier 2s fallback wrongly
    # returned false), and skew_flag=false is respected even above the proxy's fallback knob.
    on = app._normalize_fleet({"sensors": [{"sensor_uuid": "s-a", "clock_offset_ms": 150, "skew_flag": True}]})
    assert on["sensors"][0]["clock_skew_flag"] is True
    off = app._normalize_fleet({"sensors": [{"sensor_uuid": "s-b", "clock_offset_ms": 150, "skew_flag": False}]})
    assert off["sensors"][0]["clock_skew_flag"] is False
    # the panel's displayed threshold matches the registry default (100ms), not an inconsistent 2s.
    assert on["skew_warn_ms"] == 100 and "skew_warn_s" not in on


def test_fleet_derives_skew_flag_from_offset_when_registry_omits_it():
    # no server skew_flag -> derive from the documented clock_offset_ms against the fallback knob,
    # which defaults to the registry's own 100ms so a derived flag never contradicts a computed one.
    out = app._normalize_fleet({"sensors": [{"sensor_uuid": "s-3", "clock_offset_ms": 9000}]})
    assert out["sensors"][0]["clock_skew_flag"] is True
    quiet = app._normalize_fleet({"sensors": [{"sensor_uuid": "s-4", "clock_offset_ms": 50}]})
    assert quiet["sensors"][0]["clock_skew_flag"] is False


def test_fleet_reads_documented_clock_offset_ms_field():
    # sensor-health.v1 (PLAN §6.2/A7) names the offset clock_offset_ms; the proxy must consume it,
    # deriving seconds + (when the flag is absent) the skew flag.
    out = app._normalize_fleet({"sensors": [{"sensor_uuid": "s-off", "clock_offset_ms": 5000}]})
    s = out["sensors"][0]
    assert s["clock_skew_s"] == 5.0 and s["clock_skew_flag"] is True


def test_fleet_degraded_payload_is_unavailable_not_fresh_empty():
    # an error body / missing key OR an EXPLICIT degraded/unavailable marker (even wrapping an empty
    # list) is a DEGRADED upstream — never relabeled as a fresh empty result.
    for bad in ({"error": "unauthorized"}, {}, None, {"sensors": None}, {"sensors": "oops"},
                {"quality": "unavailable", "sensors": []}, {"quality": "degraded", "sensors": []},
                {"status": "degraded", "sensors": []}, {"degraded": True, "sensors": []}):
        out = app._normalize_fleet(bad)
        assert out["quality"] == "unavailable" and out["sensors"] == [], repr(bad)


def test_fleet_genuine_empty_is_fresh_not_unavailable():
    out = app._normalize_fleet({"sensors": []})
    assert out["quality"] == "fresh" and out["sensors"] == []


def test_fleet_endpoint_unreachable_upstream_is_unavailable(monkeypatch):
    def _boom(_p):
        raise OSError("connection refused")
    monkeypatch.setattr(app, "_fleet_get", _boom)
    out = app.fleet_health()
    assert out["quality"] == "unavailable" and out["reason"] == "OSError"


def test_fleet_proxy_sends_bearer_token_and_hits_sensors(monkeypatch):
    captured = {}

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self, *a):
            return b'{"sensors": []}'

    def _fake_urlopen(req, timeout=None):
        captured["url"] = req.full_url
        captured["auth"] = req.headers.get("Authorization")
        return _Resp()

    monkeypatch.setattr(app, "FLEET_API_URL", "http://fleet:8091")
    monkeypatch.setattr(app, "FLEET_API_TOKEN", "tok-abc")
    monkeypatch.setattr(app.urllib.request, "urlopen", _fake_urlopen)
    out = app.fleet_health()
    assert out["quality"] == "fresh"
    assert captured["url"] == "http://fleet:8091/sensors"     # REAL U3a path
    assert captured["auth"] == "Bearer tok-abc"               # authenticated reader (else upstream 401s)


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
