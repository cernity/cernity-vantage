"""A-U3a frontend guard (static): preset views + assertion-first "why this finding" render path.
Regression asserts on static/index.html (no JS runtime)."""
import os

_HTML = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                          "static", "index.html"), encoding="utf-8").read()


def test_preset_selector_present():
    assert 'id="f-preset"' in _HTML and "function applyPreset(" in _HTML
    for v in ('priority', 'observation', 'policy', 'unclassified'):
        assert 'value="' + v + '"' in _HTML, "missing preset: " + v


def test_priority_preset_is_severity_not_confirmed_sources():
    # KTD-A6: Priority must be a disclosed severity threshold, not CONFIRMED_THREAT_SOURCES
    assert "CONFIRMED_THREAT_SOURCES" not in _HTML
    assert "priority:{sev:'6'" in _HTML.replace(" ", "")


def test_why_panel_reads_nested_ndpi_evidence():
    # fixes R10: ndpi_evidence lives inside entities, reached via findEntity (not top-level fieldGuide)
    assert "function whyPanel(" in _HTML and "function findEntity(" in _HTML
    assert "findEntity(s.entities,'ndpi_evidence')" in _HTML
    assert 'panel(\'Why this finding\'' in _HTML, "assertion-first panel must be in the detail"


def test_why_renderer_keyed_by_version_with_fallback():
    assert "String(s.detector_version)==='2.0'" in _HTML, "renderer keyed by producer version"
    assert 'No structured "why" renderer' in _HTML, "unknown producer/version must degrade honestly"


def test_limits_never_asserts_benign_for_unknown():
    # unclassified limits must say unknown != benign
    assert "NOT the same as benign" in _HTML


def test_pagination_load_more_present():
    assert "function renderLoadMore(" in _HTML and "_findNext" in _HTML
    assert "total_relation" in _HTML, "UI must distinguish exact vs lower-bound totals"
    assert "p.set('after'" in _HTML, "Load more must page via the search_after cursor"


def test_related_eve_pivot_is_candidate_only():
    assert 'data-role="related"' in _HTML and "function relatedEve(" in _HTML
    assert "not exact lineage" in _HTML, "the EVE pivot must not claim exact lineage"
    assert "s.community_id||dst||src" in _HTML, "pivot prefers community_id then endpoints"


def test_evidence_status_strip_no_composite_or_delivery_badge():
    assert "function evidenceStrip(" in _HTML and 'class="evstrip"' in _HTML
    assert "NOT proof of delivery" in _HTML, "receiver presence must not claim delivery elsewhere"
    assert "partial (capped at 16)" in _HTML, "a capped evidence list must read as partial"
    assert "'present in '+d.index" in _HTML, "receiver chip says 'present in', never 'delivered'"


def test_assessment_axes_are_prompted_not_mandatory():
    # A-U4: threat drops noise; assertion/value are optional-but-prompted separate selects
    assert "'noise','Noise" not in _HTML, "noise must be off the threat axis"
    assert 'data-role="assertion"' in _HTML and 'data-role="value"' in _HTML
    assert "reviewed_threat_mix" in _HTML and "support%" in _HTML


if __name__ == "__main__":
    for _n, _f in sorted(globals().items()):
        if _n.startswith("test_") and callable(_f):
            _f(); print("ok", _n)
    print("PASS test_ui_au3")
