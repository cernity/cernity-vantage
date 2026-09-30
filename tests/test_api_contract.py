"""A-U1 backend contract: write-body validation + the error handler must not leak
exception detail. Plain-python asserts (no framework); run via tests/run.sh.

Uses an isolated temp SOC_DB and calls the endpoint functions directly (no live ES needed
for the write endpoints), following the review's reproduce.py pattern."""
import asyncio
import os
import sys
import tempfile

os.environ["SOC_DB"] = os.path.join(tempfile.mkdtemp(), "soc.db")  # isolate before import
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import app  # noqa: E402


def _status(r):
    return getattr(r, "status_code", 200)  # dict result -> 200; JSONResponse -> its code


def test_set_disposition_rejects_invalid_status():
    assert _status(app.set_disposition("f1", {"status": "bogus", "disposition": ""})) == 400


def test_set_disposition_rejects_invalid_disposition():
    assert _status(app.set_disposition("f1", {"status": "new", "disposition": "made-up"})) == 400


def test_set_disposition_accepts_valid():
    assert app.set_disposition("f1", {"status": "investigating", "disposition": "benign", "owner": "me"}).get("ok") is True


def test_set_disposition_rejects_invalid_assertion():
    assert _status(app.set_disposition("f1", {"status": "new", "assertion": "bogus"})) == 400


def test_set_disposition_conflict_returns_409():
    app.set_disposition("fc", {"status": "investigating", "expected_version": 0})   # -> version 1
    r = app.set_disposition("fc", {"status": "closed", "expected_version": 0})       # stale -> conflict
    assert _status(r) == 409


def test_add_note_rejects_empty():
    assert _status(app.add_note("f1", {"text": "   "})) == 400


def test_add_note_accepts_real_note():
    assert app.add_note("f1", {"text": "a real note"}) == {"ok": True}


def test_error_handler_hides_exception_detail():
    resp = asyncio.new_event_loop().run_until_complete(
        app._json_error_handler(None, RuntimeError("SECRET boom detail")))
    body = resp.body.decode()
    assert resp.status_code == 500
    assert "internal error" in body and "request_id" in body
    assert "SECRET boom detail" not in body, "raw exception message must not reach the client"
    assert "RuntimeError" not in body, "exception type must not reach the client"
    assert resp.headers.get("x-request-id"), "a correlatable request id must be returned"


if __name__ == "__main__":
    for _n, _f in sorted(globals().items()):
        if _n.startswith("test_") and callable(_f):
            _f(); print("ok", _n)
    print("PASS test_api_contract")
