"""A-U8 guard (static): honest visual semantics — confidence != severity, neutral/unresolved
markers (text-labelled, not color-only), low severity never styled 'safe' green."""
import os
import re

_HTML = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                          "static", "index.html"), encoding="utf-8").read()


def test_category_markers_distinct_and_text_labelled():
    assert "function _catChip(" in _HTML
    assert ">unresolved<" in _HTML and ">obs<" in _HTML          # distinct markers, as text
    assert "unknown, NOT benign" in _HTML                        # unclassified != benign


def test_severity_labelled_priority_not_probability():
    assert "not a probability" in _HTML
    assert "(priority)" in _HTML


def test_confidence_uncalibrated_and_new_evidence_markers():
    assert ">uncalibrated<" in _HTML, "uncalibrated confidence must be labelled"
    assert "new evidence since your last assessment" in _HTML


def test_low_severity_not_styled_green_safe():
    m = re.search(r"\.sev-lo\{background:(#[0-9a-fA-F]{6})", _HTML)
    assert m, "sev-lo style not found"
    h = m.group(1)[1:]
    r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    assert not (g > r + 40 and g > b + 40 and g > 120), "low severity must not be green/'safe': " + m.group(1)


if __name__ == "__main__":
    for _n, _f in sorted(globals().items()):
        if _n.startswith("test_") and callable(_f):
            _f(); print("ok", _n)
    print("PASS test_visual_semantics")
