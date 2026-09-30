"""A-U6 guard (static): split-pane Compare — finding fixed, candidate EVE alongside, never
exact lineage. Regression asserts on static/index.html."""
import os

_HTML = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                          "static", "index.html"), encoding="utf-8").read()


def test_compare_view_tab_and_show_wired():
    assert 'id="view-compare"' in _HTML and 'id="tab-compare"' in _HTML
    assert "'findings','suricata','search','detectors','compare'" in _HTML, "compare must be in show()"


def test_compare_functions_present_and_reuse_renderer():
    assert "function openCompare(" in _HTML and "function runCompareEve(" in _HTML
    assert "function renderEvents(" in _HTML, "EVE renderer must be shared with the Suricata tab"
    assert 'renderEvents(evs,' in _HTML


def test_compare_is_candidate_not_contributor():
    assert "not exact lineage" in _HTML
    assert "does NOT disprove the finding" in _HTML, "zero candidate matches must not read as disproven"


def test_compare_button_wired_from_detail():
    assert 'data-role="compare"' in _HTML and "openCompare(fid,s)" in _HTML


if __name__ == "__main__":
    for _n, _f in sorted(globals().items()):
        if _n.startswith("test_") and callable(_f):
            _f(); print("ok", _n)
    print("PASS test_compare")
