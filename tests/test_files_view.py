"""Inc3 U6: file-observation / YARA-hit view over U5's read-only evidence API. The proxy must call the
REAL endpoint — GET /observations?type=file&entity=&from=&to= with a bearer token (tenant is
server-derived, NEVER a query param) — enforce KTD2 (a YARA verdict is surfaced ONLY for a
bytes_available/scanned file; a metadata_only file has no verdict), and render 'unavailable' for a
degraded/unreachable upstream, never a fake fresh-empty. A node DOM smoke check executes the actual
render (badges, YARA rule+version, intel chip, transfer/PCAP pivots) and asserts inert output.
Run: .venv/bin/python -m pytest tests/test_files_view.py -q"""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.parse import parse_qs, urlparse

os.environ["SOC_DB"] = os.path.join(tempfile.mkdtemp(), "soc.db")   # isolate before import
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import app  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]

# observation.v1, type=file — SHIPPED shape: file attrs under fields.file, verdict under
# fields.file.scan_verdict (contracts/file_observation.schema.json). A scanned (bytes_available) file
# with a YARA match + an intel hash hit.
_FILE_HIT = {
    "obs_id": "f-hit", "type": "file", "ts": "2026-09-28T00:00:00Z", "tenant": "t1",
    "entities": ["1.2.3.4", "sha256:abc"],
    "fields": {"file": {
        "state": "bytes_available", "mime": "application/x-dosexec", "size": 40960,
        "bytes_scanned": 40960, "sha256": "abc123", "md5": "def456",
        "intel_hash_hit": {"finding_id": "finding-42", "indicator": "abc123"},
        "conn_uid": "cid-1", "pcap_ref": "pcap-1",
        "scan_verdict": {"engine": "yara-python 4.5.4", "scanned_at": "2026-09-28T00:00:05Z",
                         "ruleset_version": "2.1", "ruleset_sha256": "r" * 64,
                         "matched_rules": [{"rule": "EvilPacker"}]}}},
    "capabilities": ["file.hash", "file.yara"], "source_ref": "zeek:files:1",
}
# metadata-only: never scanned. KTD2 — no verdict, even if the upstream tried to attach a scan_verdict.
_FILE_META = {
    "obs_id": "f-meta", "type": "file", "ts": "2026-09-28T00:01:00Z", "tenant": "t1",
    "entities": ["5.6.7.8"],
    "fields": {"file": {"state": "metadata_only", "mime": "application/octet-stream", "size": 1024,
                        "scan_verdict": {"matched_rules": [{"rule": "ShouldNotAppear"}]}}},  # hostile on unscanned
}


# ---- server contract ---------------------------------------------------------------------------
def test_normalize_preserves_scanned_file_detail_and_yara():
    out = app._normalize_files({"observations": [_FILE_HIT], "capabilities": ["file.yara"], "next": None})
    assert out["quality"] == "fresh"
    f = out["files"][0]
    assert f["state"] == "bytes_available" and f["bytes_available"] and f["scanned"]
    assert f["scan"] == "completed"                                       # explicit scan completion
    assert f["yara"] == [{"rule": "EvilPacker", "version": "2.1"}]         # rule name + version kept
    assert f["intel_hash_hit"]["finding_id"] == "finding-42"              # intel-hit finding pivot kept
    assert f["transfer_ref"] == "cid-1" and f["pcap_ref"] == "pcap-1"     # transfer + PCAP pivots kept
    # reference-aware pivot: each ref carries WHICH allowlisted field resolves it (never a full-text search)
    assert f["transfer_field"] == "conn_uid" and f["pcap_field"] == "pcap_filename"
    assert f["sha256"] == "abc123" and f["mime"] == "application/x-dosexec"


def test_ktd2_metadata_only_file_never_carries_a_verdict():
    # KTD2 enforced at the trust boundary: a non-bytes_available file has NO verdict, even when the
    # upstream payload attached one — the browser must never receive a verdict for an unscanned file.
    out = app._normalize_files({"observations": [_FILE_META]})
    f = out["files"][0]
    assert f["state"] == "metadata_only" and not f["bytes_available"] and not f["scanned"]
    assert f["yara"] == []                                                # verdict stripped


def test_hashes_only_file_also_has_no_verdict():
    obs = {"obs_id": "h", "fields": {"file": {"state": "hashes_only", "sha256": "z",
                                              "scan_verdict": {"matched_rules": [{"rule": "X"}]}}}}
    assert app._normalize_files({"observations": [obs]})["files"][0]["yara"] == []


def test_bytes_available_scan_is_completed_only_with_a_scan_verdict():
    # bytes_available != scanned: completion is the PRESENCE of fields.file.scan_verdict (engine/scanned_at).
    # An empty matched_rules on a completed scan = NO MATCH; bytes with no scan_verdict = unknown.
    def obs(**file):
        return {"obs_id": "s", "fields": {"file": {"state": "bytes_available", **file}}}
    done = app._normalize_files({"observations": [
        obs(scan_verdict={"scanned_at": "2026-09-28T00:00:05Z", "matched_rules": []})]})["files"][0]
    assert done["scan"] == "completed" and done["scanned"] and done["yara"] == []   # completed, no match
    unk = app._normalize_files({"observations": [obs()]})["files"][0]
    assert unk["scan"] == "unknown" and not unk["scanned"]                          # never fabricated 'completed'


def test_transfer_pivot_prefers_community_id_and_records_the_field():
    obs = {"obs_id": "c", "fields": {"file": {"state": "metadata_only",
                                              "community_id": "1:abc", "conn_uid": "cid-9",
                                              "pcap_filename": "cap.pcap"}}}
    f = app._normalize_files({"observations": [obs]})["files"][0]
    assert f["transfer_ref"] == "1:abc" and f["transfer_field"] == "community_id"
    assert f["pcap_ref"] == "cap.pcap" and f["pcap_field"] == "pcap_filename"


def test_degraded_payload_is_unavailable_not_fresh_empty():
    for bad in ({"error": "evidence backend unavailable"}, {}, None, {"observations": None},
                {"quality": "degraded", "observations": []}, {"quality": "unavailable", "observations": []},
                {"status": "error", "observations": []}, {"degraded": True, "observations": []}):
        out = app._normalize_files(bad)
        assert out["quality"] == "unavailable" and out["files"] == [], repr(bad)


def test_genuine_empty_window_is_fresh():
    out = app._normalize_files({"observations": [], "capabilities": []})
    assert out["quality"] == "fresh" and out["files"] == []


def test_files_view_requires_entity_and_window():
    assert app.files_view()["quality"] == "unavailable"
    assert app.files_view(entity="1.2.3.4")["quality"] == "unavailable"
    assert app.files_view(entity="1.2.3.4", frm="2026-09-27T00:00:00Z")["quality"] == "unavailable"


def test_files_view_calls_real_observations_endpoint_with_type_file(monkeypatch):
    captured = {}

    def _fake_get(path):
        captured["path"] = path
        return {"observations": [_FILE_HIT], "capabilities": ["file.yara"]}

    monkeypatch.setattr(app, "_evidence_get", _fake_get)
    out = app.files_view(entity="1.2.3.4", frm="2026-09-27T00:00:00Z", to="2026-09-28T00:00:00Z")
    assert out["quality"] == "fresh" and out["files"][0]["obs_id"] == "f-hit"
    u = urlparse(captured["path"])
    assert u.path == "/observations"                                     # REAL U5 endpoint
    q = parse_qs(u.query)
    assert q["type"] == ["file"] and q["entity"] == ["1.2.3.4"]
    assert q["from"] == ["2026-09-27T00:00:00Z"] and q["to"] == ["2026-09-28T00:00:00Z"]


def test_files_view_unreachable_upstream_is_unavailable(monkeypatch):
    def _boom(_p):
        raise OSError("connection refused")
    monkeypatch.setattr(app, "_evidence_get", _boom)
    out = app.files_view(entity="1.2.3.4", frm="2026-09-27T00:00:00Z", to="2026-09-28T00:00:00Z")
    assert out["quality"] == "unavailable" and out["reason"] == "OSError"


def test_tenant_is_server_derived_bearer_token_never_a_query_param(monkeypatch):
    # scenario 5: only the caller's tenant(s), never merged — tenant rides the bearer token upstream,
    # never as a query param, and the token stays inside the one proxy->upstream request.
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
    out = app.files_view(entity="1.2.3.4", frm="2026-09-27T00:00:00Z", to="2026-09-28T00:00:00Z")
    assert out["quality"] == "fresh"
    assert captured["auth"] == "Bearer tok-xyz"                          # authenticated reader
    assert captured["url"].startswith("http://evidence:8092/observations?")
    assert "tenant" not in captured["url"].lower()                       # §21: never a query param


# ---- render (node DOM smoke check) -------------------------------------------------------------
# A real-enough DOM: innerHTML is stored and querySelectorAll re-parses it into STABLE nodes (so a
# handler bound during render survives to a later click), with each node's dataset carrying every data-*
# attribute on its tag and click()/keydown() dispatching the bound handler. That lets the test actually
# CLICK the rendered pivots and open the detail view, not just eyeball the markup string.
_DOM = r"""
const assert=require('assert');
global.window=global;
const nodes={};
global.esc=v=>String(v==null?'':v).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function childNode(ds){return {dataset:ds,onclick:null,onkeydown:null,style:{},setAttribute(){},focus(){},
  classList:{toggle(){},add(){},remove(){},contains(){return false;}},
  click(){if(this.onclick)this.onclick({stopPropagation(){},preventDefault(){}});},
  key(k){if(this.onkeydown)this.onkeydown({key:k,stopPropagation(){},preventDefault(){}});}};}
function makeEl(){const el={_html:'',_cache:{},textContent:'',value:'',onclick:null,onkeydown:null,
  dataset:{},style:{},setAttribute(){},focus(){},
  classList:{toggle(){},add(){},remove(){},contains(){return false;}},
  querySelector(sel){return this.querySelectorAll(sel)[0]||null;},
  querySelectorAll(sel){const m=sel.match(/\[data-([a-z-]+)\]/i);if(!m)return [];
    const want='data-'+m[1];const tags=this._html.match(/<[a-z][^>]*>/gi)||[];const out=[];
    for(const tag of tags){if(tag.indexOf(want+'=')<0)continue;
      if(!this._cache[tag]){const ds={};let a;const re=/data-([a-z-]+)="([^"]*)"/gi;
        while((a=re.exec(tag)))ds[a[1].replace(/-([a-z])/g,(_,c)=>c.toUpperCase())]=a[2];
        this._cache[tag]=childNode(ds);}
      out.push(this._cache[tag]);}
    return out;}};
  Object.defineProperty(el,'innerHTML',{get(){return this._html;},set(v){this._html=String(v);this._cache={};}});
  return el;}
global.$=id=>nodes[id]||(nodes[id]=makeEl());
let SHOWN=null; global.show=t=>{SHOWN=t;};
let SURICATA_LOADS=0; global.loadSuricata=()=>{SURICATA_LOADS++;};
"""


def _node(files, checks):
    source = (ROOT / "static/files.js").read_text()
    assert " onclick=" not in source and "javascript:" not in source, "no inline handlers in files.js"
    script = _DOM + source + "\nconst FILES=JSON.parse(process.argv[1]);\n" + checks
    subprocess.run(["node", "-e", script, json.dumps(files)], check=True, capture_output=True, text=True)


def test_files_render_badges_verdict_intel_pivots_and_inert():
    # a hostile YARA rule name must be escaped, never break out into markup/handlers.
    files = [
        {"obs_id": "o1", "sha256": "abc123", "mime": "application/x-dosexec", "size": 40960,
         "state": "bytes_available", "bytes_available": True, "scanned": True, "scan": "completed",
         "yara": [{"rule": "<img src=x onerror=bad()>", "version": "2.1"}],
         "intel_hash_hit": {"finding_id": "finding-42", "indicator": "abc123"},
         "transfer_ref": "cid-1", "transfer_field": "conn_uid",
         "pcap_ref": "pcap-1", "pcap_field": "pcap_filename"},
        {"obs_id": "o2", "sha256": "def456", "state": "metadata_only",
         "bytes_available": False, "scanned": False, "scan": "unscanned", "yara": [],
         "intel_hash_hit": None, "transfer_ref": None, "pcap_ref": None},
    ]
    _node(files, r"""
_renderFiles(FILES);
const html=$('files-list').innerHTML;
// scenario 1: scanned file renders YARA rule name + version + a hit badge, plus bytes/scanned badges.
assert(html.includes('YARA hit:')&&html.includes('v2.1'),'yara rule+version');
assert(html.includes('bytes available')&&html.includes('scanned'),'bytes-available/scanned badges');
// scenario 2: metadata_only shows the honest line and NO verdict.
assert(html.includes('metadata only'),'metadata-only line');
assert((html.match(/YARA hit:/g)||[]).length===1,'metadata-only file must carry no verdict');
// scenario 3: intel hash hit chip + link to the finding.
assert(html.includes('intel hash hit')&&html.includes('data-finding="finding-42"'),'intel chip + finding pivot');
// scenario 4: transfer + PCAP pivots present in the list markup.
assert(html.includes('data-transfer="cid-1"')&&html.includes('data-pcap="pcap-1"'),'transfer + pcap pivots');
// inert: hostile rule name escaped, no live handlers/markup.
assert(html.includes('&lt;img')&&!html.includes('<img src=x'),'hostile value must be esc()d');
assert(!/<[^>]*\son\w+=/i.test(html),'no inline event handlers in rendered output');
""")


def test_files_scan_states_render_no_verdict_and_no_fabricated_no_hit():
    # regression: a bytes_available file whose scan is NOT completed must show an explicit no-verdict
    # line and NEVER a 'no YARA hit' result. Only a completed scan may report 'no YARA hit'.
    files = [
        {"obs_id": "p", "state": "bytes_available", "bytes_available": True, "scan": "pending", "yara": []},
        {"obs_id": "f", "state": "bytes_available", "bytes_available": True, "scan": "failed", "yara": []},
        {"obs_id": "u", "state": "bytes_available", "bytes_available": True, "scan": "unknown", "yara": []},
        {"obs_id": "d", "state": "bytes_available", "bytes_available": True, "scan": "completed", "yara": []},
        {"obs_id": "m", "state": "metadata_only", "bytes_available": False, "scan": "unscanned", "yara": []},
    ]
    _node(files, r"""
_renderFiles(FILES);
const html=$('files-list').innerHTML;
assert(html.includes('scan pending'),'pending state surfaced');
assert(html.includes('scan failed'),'failed state surfaced');
assert(html.includes('scan status unknown'),'unknown state surfaced');
assert(html.includes('metadata only'),'unscanned state surfaced');
// exactly ONE 'no YARA hit' — the completed scan; pending/failed/unknown/unscanned never fabricate it.
assert((html.match(/no YARA hit/g)||[]).length===1,'only a completed scan reports no-hit');
assert(!html.includes('YARA hit:'),'no verdict chips when nothing matched');
""")


def test_files_transfer_and_pcap_pivots_are_reference_aware():
    # clicking the transfer / PCAP button must open the raw-EVE tab configured for an EXACT field match
    # (mode=all, alert-only + narrowing filters cleared), preserving the reference TYPE per button.
    files = [
        {"obs_id": "o1", "sha256": "abc", "state": "bytes_available", "bytes_available": True,
         "scan": "completed", "yara": [], "intel_hash_hit": None,
         "transfer_ref": "cid-1", "transfer_field": "conn_uid",
         "pcap_ref": "cap.pcap", "pcap_field": "pcap_filename"},
    ]
    _node(files, r"""
_renderFiles(FILES);
// pre-set stale/incompatible filters that would exclude an alertless transfer flow.
$('s-mode').value='alerts'; $('s-sev').value='1'; $('s-type').value='alert'; $('s-since').value='24h';
$('files-list').querySelectorAll('[data-transfer]')[0].click();
assert(SHOWN==='suricata','pivot switches to the suricata tab');
assert($('s-q').value==='cid-1','transfer ref carried into the query');
assert($('s-field').value==='conn_uid','transfer resolves on its exact field, not full-text');
assert($('s-mode').value==='all','alert-only mode cleared (a transfer flow carries no alert)');
assert($('s-sev').value===''&&$('s-type').value===''&&$('s-since').value==='','incompatible filters cleared');
assert(SURICATA_LOADS>=1,'the pivot actually runs the query');
$('files-list').querySelectorAll('[data-pcap]')[0].click();
assert($('s-q').value==='cap.pcap','pcap ref carried into the query');
assert($('s-field').value==='pcap_filename','pcap resolves on pcap_filename — reference type preserved');
""")


def test_files_detail_view_opens_with_context_and_linked_evidence():
    # the detail view must expose observation context (ts, source, entities, capabilities) + linked
    # evidence (transfer/PCAP pivots) — none of which is reachable from the list row alone.
    files = [
        {"obs_id": "o1", "sha256": "abc123", "md5": "def456", "mime": "application/x-dosexec",
         "size": 40960, "ts": "2026-09-28T00:00:00Z", "state": "bytes_available",
         "bytes_available": True, "scan": "completed",
         "yara": [{"rule": "EvilPacker", "version": "2.1"}],
         "intel_hash_hit": {"finding_id": "finding-42", "indicator": "abc123"},
         "entities": ["1.2.3.4", "sha256:abc"], "capabilities": ["file.hash", "file.yara"],
         "source_ref": "zeek:files:1", "transfer_ref": "cid-1", "transfer_field": "conn_uid",
         "pcap_ref": "pcap-1", "pcap_field": "pcap_filename"},
    ]
    _node(files, r"""
_renderFiles(FILES);
// open the detail by CLICKING the file row (data-obs), the way an analyst would.
$('files-list').querySelectorAll('[data-obs]')[0].click();
const d=$('files-detail').innerHTML;
assert(d.includes('2026-09-28T00:00:00Z'),'detail shows the observation timestamp');
assert(d.includes('zeek:files:1'),'detail shows the source reference');
assert(d.includes('1.2.3.4')&&d.includes('sha256:abc'),'detail lists the entities');
assert(d.includes('file.hash')&&d.includes('file.yara'),'detail lists the capabilities');
assert(d.includes('YARA hit:')&&d.includes('EvilPacker'),'detail carries the KTD2-safe verdict');
assert(d.includes('data-transfer="cid-1"')&&d.includes('data-pcap="pcap-1"'),'detail links its evidence');
assert(!/<[^>]*\son\w+=/i.test(d),'no inline event handlers in the detail view');
""")


def test_index_html_forwards_the_exact_field_param_to_the_suricata_endpoint():
    # the reference-aware pivot only works if the client actually SENDS the field param and cannot leak
    # it into a later plain-text search.
    html = (ROOT / "static/index.html").read_text()
    assert 'id="s-field"' in html, "hidden s-field input must exist"
    assert "field:$('s-field').value" in html, "loadSuricata must forward the exact-field param"
    assert "$('s-field').value=''" in html, "a manual text query must clear the pivot field"


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
