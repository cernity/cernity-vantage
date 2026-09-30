"""A-U1 frontend guard (static): the SPA must render untrusted content inertly and must
not reintroduce the wrong-panel-save bug. No JS runtime — these are regression asserts on
static/index.html that fail if the unsafe patterns come back."""
import os

_HTML = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                          "static", "index.html"), encoding="utf-8").read()


def test_esc_escapes_quotes():
    # esc must map both quote characters, so attribute and JS-string sinks stay inert
    assert "&quot;" in _HTML, "esc must escape double quotes"
    assert "&#39;" in _HTML, "esc must escape single quotes"


def test_no_inline_onclick_for_save_or_note():
    # the wrong-panel-save + JS-string-injection vector was inline onclick="saveDisp(...)"/addNote(...)
    assert 'onclick="saveDisp(' not in _HTML, "Save must not use inline onclick"
    assert 'onclick="addNote(' not in _HTML, "Add note must not use inline onclick"


def test_no_duplicate_global_control_ids():
    # duplicate id="d-status"/"d-disp"/"d-owner" across the Findings + Search panels was the bug
    for bad in ('id="d-status"', 'id="d-disp"', 'id="d-owner"', 'id="n-text"'):
        assert bad not in _HTML, "detail controls must be panel-scoped (data-role), not global ids: " + bad


def test_controls_panel_scoped_and_wired():
    assert 'data-role="save"' in _HTML and 'data-role="status"' in _HTML
    assert "addEventListener('click'" in _HTML, "handlers must be wired via addEventListener"
    assert "setRowTriage(" in _HTML, "save must update the row in place (preserve selection)"


def test_shared_request_layer_present():
    assert "async function req(" in _HTML, "a shared request layer must exist"
    assert "res.ok" in _HTML, "callers must switch on the request result's ok flag"


if __name__ == "__main__":
    for _n, _f in sorted(globals().items()):
        if _n.startswith("test_") and callable(_f):
            _f(); print("ok", _n)
    print("PASS test_render_inert")
