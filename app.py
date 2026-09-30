"""Cernity Vantage — a purpose-built dark analyst workspace over the
live SIEM. Two independent surfaces + disposition write-back:

  - Cernity Findings  <- Elasticsearch  ndr-findings-*   (real findings)
  - Suricata (raw)     <- Redpanda bus   suricata.*.v1    (full-fidelity EVE)
  - Triage state       -> SQLite         (findings are immutable; triage lives here)

Design rules baked in (from the brainstorm): dark only; full-fidelity floor —
every record expands to its complete captured form, nothing dropped; Cernity and
Suricata are separate tabs, no correlation. Personal use now.
"""
import base64
import json
import logging
import os
import re
import sqlite3
import ssl
import urllib.request
import urllib.error
import uuid
from contextlib import closing
from urllib.parse import urlencode

import assessment  # A-U2: append-only, revision/digest-anchored assessment store
import overview     # 011 U2: overview dashboard assembly (honest verdict/collection/cernity/traffic)
import metrics_backend  # 011 U1: store-agnostic metrics seam
import findings_summary  # 012 V3: bounded revision-deduped finding analytics
import triage_tier    # 012 C: triage tiering (threat/lead/low_signal/observation/benign)
import allowlist      # 012 B: analyst benign/allowlist rules (retained, not hidden)

from fastapi import FastAPI, Body, Request
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles

ES_URL = os.environ.get("ES_URL", "https://192.168.222.141:9200").rstrip("/")
ES_USER = os.environ.get("ES_USER", "elastic")
ES_PASS = os.environ.get("ES_PASS", "")
ES_INDEX = os.environ.get("ES_INDEX", "ndr-findings-*")
BUS = os.environ.get("REDPANDA_BOOTSTRAP", "redpanda:9092")
DB_PATH = os.environ.get("SOC_DB", "/data/soc.db")
# U10: config-driven upstreams for the read-only fleet/evidence APIs. No baked-in host — a blank
# value means "not wired", which the proxies surface as a measured 'unavailable', never a crash.
FLEET_API_URL = os.environ.get("FLEET_API_URL", "").rstrip("/")
EVIDENCE_API_URL = os.environ.get("EVIDENCE_API_URL", "").rstrip("/")
# U3a/U5 derive the reader's tenant grant server-side from a bearer token; without it both APIs 401.
# The Vantage proxy is that authenticated reader — a blank token means "not wired" (surfaced as
# 'unavailable', never a crash). The token value never leaves the proxy->upstream request.
FLEET_API_TOKEN = os.environ.get("FLEET_API_TOKEN", "")
EVIDENCE_API_TOKEN = os.environ.get("EVIDENCE_API_TOKEN", "")
# U6: config-driven upstreams for the read-only coverage (U4) + quality (U5) APIs. No baked-in host —
# a blank value means "not wired", surfaced by the proxies as a measured 'unavailable', never a crash
# or a fake fresh-empty. The reader token is the server-derived tenant identity (§21): tenant is NEVER
# a query param, and the token value never leaves the one proxy->upstream request.
COVERAGE_API_URL = os.environ.get("COVERAGE_API_URL", "").rstrip("/")
QUALITY_API_URL = os.environ.get("QUALITY_API_URL", "").rstrip("/")
COVERAGE_API_TOKEN = os.environ.get("COVERAGE_API_TOKEN", "")
QUALITY_API_TOKEN = os.environ.get("QUALITY_API_TOKEN", "")
# U3a's registry computes skew_flag SERVER-SIDE against its own SKEW_THRESHOLD_MS (default 100ms) and
# the proxy TRUSTS that flag. This knob is only a fallback for a payload that omits skew_flag; it
# defaults to the registry's own 100ms so a derived flag never contradicts a registry-computed one,
# and the panel never displays a threshold inconsistent with the registry. Real clocks drift — kept
# tunable, but in the registry's units (ms), not a baked 2-second guess.
_FLEET_SKEW_WARN_MS = float(os.environ.get("FLEET_SKEW_WARN_MS", "100"))
DISPOSITION_TOPIC = "disposition.v1"

_ES_AUTH = "Basic " + base64.b64encode(f"{ES_USER}:{ES_PASS}".encode()).decode()
_CTX = ssl._create_unverified_context()

# event_type -> bus topic (full EVE lives on the bus). Note: suricata.flow.v1 carries BOTH
# "flow" (bidirectional) and "netflow" (per-direction) EVE records, so both map to it and we
# filter by the exact event_type below to keep the selections clean.
TOPICS = {"flow": "suricata.flow.v1", "netflow": "suricata.flow.v1", "tls": "suricata.tls.v1",
          "dns": "suricata.dns.v1", "http": "suricata.http.v1", "ssh": "suricata.ssh.v1",
          "anomaly": "suricata.anomaly.v1", "raw": "suricata.raw.v1"}
# "raw" is a catch-all topic (mixed event_types) — don't filter it; every other selection maps
# to a single event_type and is filtered to exactly that.
_NO_FILTER = {"raw"}

app = FastAPI(title="Cernity Vantage")


_log = logging.getLogger("vantage")


# ---- U10 (C): disposition.v1 emit to the bus (docs/disposition.schema.json) ------------------
# Additive to the SIEM export, no raw-log storage. The write-back (SQLite) is the source of truth;
# the emit is BEST-EFFORT — a bus outage must never fail an analyst's disposition or allowlist add.
import datetime as _dt

_ENTITY_TYPES = {"ip", "hostname", "domain", "asset"}
# triage disposition -> disposition.v1 verdict vocab. Only SETTLED verdicts emit. "suspicious" is an
# UNCONFIRMED lead, not a confirmed threat — it has no disposition.v1 verdict and MUST NOT be broadcast
# as a true_positive (that would feed a suspicion into feedback-service as confirmed ground truth). It
# emits nothing, exactly like "" (no verdict chosen); only confirmed/benign are settled dispositions.
_EMIT_VERDICT = {"confirmed": "true_positive", "benign": "benign"}
# allowlist rule field -> entity type (dst_asn/category aren't endpoints, so they ride as 'asset').
_ALLOWLIST_ENTITY_TYPE = {"dst_ip": "ip", "src_ip": "ip", "any_ip": "ip",
                          "dst_asn": "asset", "category": "asset"}
_emit_sink = None  # tests set this to capture events instead of dialing the broker


def _coerce_entity(entity, fallback_value):
    e = entity if isinstance(entity, dict) else {}
    t = e.get("type") if e.get("type") in _ENTITY_TYPES else "asset"
    v = (str(e.get("value") or "").strip() or str(fallback_value or "").strip() or "unknown")[:512]
    return {"type": t, "value": v}


def build_disposition(finding_id, entity, verdict, reason, analyst, scope, tenant=None, ts=None):
    """Assemble a disposition.v1 event. Applies the schema's conditional invariants so the output
    always validates: allowlist -> scope 'entity' (finding_id may be null); any other verdict ->
    scope 'finding' with a non-blank finding_id."""
    ev = {"finding_id": finding_id, "entity": _coerce_entity(entity, finding_id), "verdict": verdict,
          "reason": (str(reason or "").strip() or "(no reason given)")[:4096],
          "analyst": (str(analyst or "").strip() or "analyst")[:256],
          "ts": ts or _dt.datetime.now(_dt.timezone.utc).isoformat(),
          "scope": "entity" if verdict == "allowlist" else (scope or "finding")}
    if verdict != "allowlist" and not (isinstance(finding_id, str) and finding_id.strip()):
        raise ValueError("finding_id is required for a non-allowlist disposition")
    if tenant and str(tenant).strip():
        ev["tenant"] = str(tenant)[:256]
    return ev


def emit_disposition(event):
    """Publish one disposition.v1 to the bus (REDPANDA_BOOTSTRAP). Best-effort: bus errors are
    logged, never raised. Tests set _emit_sink to capture without a broker."""
    if _emit_sink is not None:
        _emit_sink(event)
        return
    try:
        from kafka import KafkaProducer
        p = KafkaProducer(bootstrap_servers=BUS.split(","),
                          value_serializer=lambda v: json.dumps(v).encode())
        p.send(DISPOSITION_TOPIC, event)
        p.flush(timeout=5)
        p.close(timeout=5)
    except Exception:                                        # noqa: BLE001
        _log.exception("disposition emit to bus failed (write-back persisted; emit is best-effort)")


def _emit_allowlist_disposition(rule):
    """allowlist.add_rule's emit hook — turns a persisted rule into an allowlist disposition.v1."""
    emit_disposition(build_disposition(
        finding_id=None,
        entity={"type": _ALLOWLIST_ENTITY_TYPE.get(rule.get("field"), "asset"), "value": rule.get("value")},
        verdict="allowlist",
        reason=(rule.get("reason") or "allowlist %s=%s" % (rule.get("field"), rule.get("value"))),
        analyst=rule.get("created_by"), scope="entity"))


@app.exception_handler(Exception)
async def _json_error_handler(request, exc):  # A-U1: JSON, never a raw exception detail to the client
    rid = uuid.uuid4().hex[:12]
    _log.exception("request %s failed: %s", rid, exc)   # full detail stays server-side, correlatable by rid
    return JSONResponse({"error": "internal error", "request_id": rid, "rows": [], "detectors": []},
                        status_code=500, headers={"x-request-id": rid})


@app.on_event("startup")
def _migrate_assessments():  # A-U2: fold legacy triage/notes into the append-only store (idempotent)
    try:
        with closing(_db()) as c:
            assessment.init(c)
            allowlist.init(c)                       # 012 B: benign/allowlist rules table
            migrated = assessment.migrate_legacy(c)
            if migrated:
                _log.info("assessment store: migrated %s legacy triage rows", migrated)
    except Exception:
        _log.exception("assessment migration at startup failed")


# ---- storage: triage write-back (findings stay immutable in ES) --------------
def _db():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    c.execute("""CREATE TABLE IF NOT EXISTS triage(
        finding_id TEXT PRIMARY KEY, status TEXT, disposition TEXT, owner TEXT, updated TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS notes(
        id INTEGER PRIMARY KEY AUTOINCREMENT, finding_id TEXT, text TEXT, ts TEXT)""")
    try:  # denormalize detector for the per-detector quality rollup (idempotent)
        c.execute("ALTER TABLE triage ADD COLUMN detector_id TEXT")
    except sqlite3.OperationalError:
        pass
    return c


def _triage(fid):
    with closing(_db()) as c:
        row = c.execute("SELECT status,disposition,owner,updated FROM triage WHERE finding_id=?", (fid,)).fetchone()
        notes = c.execute("SELECT text,ts FROM notes WHERE finding_id=? ORDER BY id", (fid,)).fetchall()
        return (dict(row) if row else {"status": "new", "disposition": "", "owner": "", "updated": ""},
                [dict(n) for n in notes])


# ---- Elasticsearch (findings) ------------------------------------------------
def _es(path, body):
    req = urllib.request.Request(ES_URL + path, data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "Authorization": _ES_AUTH})
    with urllib.request.urlopen(req, context=_CTX, timeout=20) as r:
        return json.load(r)


def _es_get(path):
    req = urllib.request.Request(ES_URL + path, headers={"Authorization": _ES_AUTH})
    with urllib.request.urlopen(req, context=_CTX, timeout=20) as r:
        return json.load(r)


_FIELD_CACHE = {}
_FIELD_TTL = 300  # seconds


class MappingConflict(Exception):
    """No single field is uniformly aggregatable/sortable across the resolved index set (KTD-A5).
    Callers surface this as a visible compatibility error rather than silently picking a wrong field."""

    def __init__(self, field):
        super().__init__("field '%s' has no uniformly aggregatable mapping across the current indices "
                         "(narrow the time range to a consistent index, or reindex/alias to fix)" % field)
        self.field = field


def _agg_ok(entry):
    return bool(entry.get("aggregatable")) and not entry.get("non_aggregatable_indices")


def _resolve_field(name, fc):
    """Pure capability decision over a _field_caps `fields` dict (unit-tested). Returns the field to
    use, or raises MappingConflict — never guesses a suffix when nothing is uniformly usable."""
    base = fc.get(name, {})
    kw = fc.get(name + ".keyword", {})
    if list(base.keys()) == ["keyword"] and _agg_ok(base["keyword"]):
        return name                                             # uniformly keyword
    if kw:
        kmeta = kw.get("keyword") or next(iter(kw.values()), {})
        if _agg_ok(kmeta):
            return name + ".keyword"                            # uniform keyword multifield
        raise MappingConflict(name)                             # .keyword not aggregatable everywhere
    if name in fc and len(base) == 1 and _agg_ok(next(iter(base.values()), {})):
        return name
    raise MappingConflict(name)                                 # text-only, or mixed types, no clean .keyword


def _agg_field(name, index=None):
    """Aggregatable/sortable form of `name`, capability-checked across `index` (KTD-A5). Raises
    MappingConflict when no single field is uniformly usable. Cached per (name, index)."""
    import time
    index = index or ES_INDEX
    key = (name, index)
    now = time.time()
    hit = _FIELD_CACHE.get(key)
    if hit and hit[1] > now:
        if isinstance(hit[0], MappingConflict):
            raise hit[0]
        return hit[0]
    try:
        fc = _es_get(f"/{index}/_field_caps?fields={name},{name}.keyword").get("fields", {})
    except Exception:
        return f"{name}.keyword"                                # field_caps unreachable: best-effort, don't cache
    try:
        resolved = _resolve_field(name, fc)
    except MappingConflict as mc:
        _FIELD_CACHE[key] = (mc, now + _FIELD_TTL)
        raise
    _FIELD_CACHE[key] = (resolved, now + _FIELD_TTL)
    return resolved


def _as_entities(v):
    """Normalize an ES `entities` field to a list. ndr-findings store it as a nested
    array, but suricata-derived findings (idsig-*) store it as a JSON string — handing a
    string to the UI made the queue's row-expand render throw (`.filter` on a str), so the
    whole queue silently stopped responding to clicks. Coerce here so every consumer
    (queue, Findings tab, related-EVE) gets the same list shape."""
    if isinstance(v, str):
        try:
            v = json.loads(v)
        except (ValueError, TypeError):
            return []
    if isinstance(v, list):
        return v
    return [] if v is None else [v]


@app.get("/api/findings")
def findings(severity_min: int = 0, category: str = "", detector: str = "", q: str = "", size: int = 100,
             since: str = "", frm: str = "", to: str = "", source: str = "", after: str = ""):
    size = max(1, min(int(size), 200))                          # A-U3: bound page size
    try:
        must, filt = [], [{"range": {"severity": {"gte": severity_min}}}]
        if frm or to:  # explicit wall-clock range (naive both sides -> ES compares as UTC, self-consistent)
            rng = {}
            if frm:
                rng["gte"] = frm
            if to:
                rng["lte"] = to
            filt.append({"range": {"@timestamp": rng}})
        elif since:  # relative quick-pick, ES date math e.g. since="24h" -> now-24h
            filt.append({"range": {"@timestamp": {"gte": f"now-{since}"}}})
        if category:
            filt.append({"term": {_agg_field("category"): category}})
        if detector:
            filt.append({"term": {_agg_field("detector_id"): detector}})
        if source:  # provenance class -> detector_id pattern (§6.7.5: slips_ml = genuine ML/behavioral)
            _df = _agg_field("detector_id")
            _SRC = {"ml": {"prefix": {_df: "slips_ml"}},
                    "slips": {"prefix": {_df: "slips_"}},
                    "signature": {"term": {_df: "ids_signature"}},
                    "intel": {"terms": {_df: ["threat_intel", "slips_intel"]}},
                    "ndpi": {"term": {_df: "ndpi_risk"}}}
            if source in _SRC:
                filt.append(_SRC[source])
        if q:
            must.append({"simple_query_string": {"query": q}})
        # A-U3: deterministic sort (time desc + finding_id tiebreak) enables search_after paging;
        # track_total_hits bounded so the total's relation distinguishes exact from lower-bound.
        tiebreak = _agg_field("finding_id")
        body = {"size": size, "track_total_hits": 10000,
                "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}, {tiebreak: "asc"}],
                "query": {"bool": {"must": must or [{"match_all": {}}], "filter": filt}}}
        if after:
            try:
                body["search_after"] = json.loads(after)
            except Exception:
                return JSONResponse({"error": "bad cursor"}, status_code=400)
        res = _es(f"/{ES_INDEX}/_search", body)
        cat_field, det_field = _agg_field("category"), _agg_field("detector_id")
        facets = _es(f"/{ES_INDEX}/_search", {"size": 0, "aggs": {
            "cat": {"terms": {"field": cat_field, "size": 20}},
            "det": {"terms": {"field": det_field, "size": 30}}}})
    except MappingConflict as mc:                               # KTD-A5: visible error, never a wrong-field pick
        return JSONResponse({"error": str(mc), "field": mc.field, "rows": []}, status_code=400)
    hits = res.get("hits", {}).get("hits", [])
    with closing(_db()) as c:
        tri = {r["finding_id"]: dict(r) for r in c.execute("SELECT * FROM triage").fetchall()}
    rows = []
    for h in hits:
        s = h["_source"]
        fid = s.get("finding_id", h["_id"])
        rows.append({"finding_id": fid, "detector_id": s.get("detector_id"), "category": s.get("category"),
                     "severity": s.get("severity"), "confidence": s.get("confidence"), "state": s.get("state"),
                     "mitre": s.get("mitre", []), "entities": _as_entities(s.get("entities")), "geo": s.get("geo"),
                     "intel": s.get("intel"), "ts": s.get("@timestamp"),
                     "status": (tri.get(fid) or {}).get("status", "new"),
                     "disposition": (tri.get(fid) or {}).get("disposition", "")})
    total = res.get("hits", {}).get("total", {}) or {}
    # a full page implies more may exist -> hand back the cursor to reach the next page
    next_after = json.dumps(hits[-1]["sort"]) if (hits and len(hits) == size and "sort" in hits[-1]) else ""
    aggs = facets.get("aggregations", {})
    return {"total": total.get("value", 0), "total_relation": total.get("relation", "eq"),
            "rows": rows, "next_after": next_after,
            "categories": [b["key"] for b in aggs.get("cat", {}).get("buckets", [])],
            "detectors": [b["key"] for b in aggs.get("det", {}).get("buckets", [])]}


@app.get("/api/findings/{fid}")
def finding_detail(fid: str):
    # A-U2: select the latest revision deterministically (revision desc, missing last, then time)
    # so a rollover or duplicate doc can't return an arbitrary older revision; return the received
    # identity + a server-computed source digest + any prior assessment with a new-evidence flag.
    res = _es(f"/{ES_INDEX}/_search", {
        "size": 1,
        "query": {"term": {_agg_field("finding_id"): fid}},
        "sort": [{"revision": {"order": "desc", "missing": "_last", "unmapped_type": "long"}},
                 {"@timestamp": {"order": "desc", "unmapped_type": "date"}}]})
    hits = res.get("hits", {}).get("hits", [])
    if not hits:
        return JSONResponse({"error": "not found"}, status_code=404)
    src = hits[0]["_source"]
    tenant = src.get("tenant_id", "") or ""
    digest = assessment.source_digest(src)
    with closing(_db()) as c:                        # A-U4: triage/notes from the store; A-U7: mapping requests
        assessment.init(c)
        prior = assessment.current(c, tenant, fid)
        notes = assessment.notes(c, tenant, fid)
        assessment.init_requests(c)
        requests = assessment.list_requests(c, fid)
    tri = {"status": prior["status"], "disposition": prior["disposition"], "assertion": prior["assertion"],
           "value_judgment": prior["value_judgment"], "owner": prior["owner"]}
    return {"index": hits[0]["_index"], "id": hits[0]["_id"], "source": src, "requests": requests,
            "revision": src.get("revision"), "source_digest": digest,
            "assessment": {"assessed_revision": prior.get("assessed_revision"),
                           "assessed_digest": prior.get("assessed_digest"),
                           "version": prior.get("version", 0),
                           "new_evidence_since_assessment":
                               assessment.new_evidence_since_assessment(prior.get("assessed_digest"), digest)},
            "triage": tri, "notes": notes}


@app.get("/api/findings/{fid}/assessments")
def finding_assessments(fid: str, tenant_id: str = ""):
    with closing(_db()) as c:
        assessment.init(c)
        return {"finding_id": fid, "tenant_id": tenant_id,
                "history": assessment.history(c, tenant_id, fid)}


# ---- A-U7: mapping-review requests (local backlog; no outbound automation) -------------------
@app.post("/api/mapping_requests")
def create_mapping_request(body: dict = Body(...)):
    if not (body.get("explanation") or "").strip():
        return JSONResponse({"error": "explanation required"}, status_code=400)
    with closing(_db()) as c:
        assessment.init_requests(c)
        rid = assessment.create_request(
            c, tenant_id=body.get("tenant_id", ""), finding_id=body.get("finding_id"),
            revision=body.get("revision"), detector_id=(body.get("detector_id") or "")[:200],
            policy_version=body.get("policy_version"), risk_id=body.get("risk_id"),
            risk_name=body.get("risk_name"), resolution_reason=body.get("resolution_reason"),
            evidence_available=body.get("evidence_available"),
            explanation=(body.get("explanation") or "")[:4000], proposed=(body.get("proposed") or "")[:1000])
    return {"ok": True, "id": rid}


@app.get("/api/mapping_requests")
def list_mapping_requests(finding_id: str = ""):
    with closing(_db()) as c:
        assessment.init_requests(c)
        return {"requests": assessment.list_requests(c, finding_id or None)}


@app.post("/api/mapping_requests/{rid}/state")
def set_mapping_request_state(rid: int, body: dict = Body(...)):
    try:
        with closing(_db()) as c:
            assessment.init_requests(c)
            assessment.set_request_state(c, rid, body.get("state", ""), note=(body.get("note") or "")[:1000])
    except ValueError:
        return JSONResponse({"error": "invalid state"}, status_code=400)
    return {"ok": True}


# A-U4: judgment axes. Threat is confirmed/suspicious/benign; 'noise' is retired to the value axis.
# Assertion support is optional-but-prompted; value is optional.
_TRIAGE_STATUS = {"new", "investigating", "escalated", "closed"}
_TRIAGE_DISP = {"", "confirmed", "suspicious", "benign"}
_ASSERTION = {"", "supported", "unsupported", "insufficient_evidence"}
_VALUE = {"", "useful", "low_value"}


@app.post("/api/findings/{fid}/disposition")
def set_disposition(fid: str, body: dict = Body(...)):   # A-U4: writes through the append-only store
    status = body.get("status", "new")
    disposition = body.get("disposition", "")
    assertion = body.get("assertion", "")
    value_judgment = body.get("value_judgment", "")
    if (status not in _TRIAGE_STATUS or disposition not in _TRIAGE_DISP
            or assertion not in _ASSERTION or value_judgment not in _VALUE):
        return JSONResponse({"error": "invalid judgment value"}, status_code=400)
    tenant = body.get("tenant_id") or ""
    owner = (body.get("owner") or "")[:120]
    detector_id = (body.get("detector_id") or "")[:200]
    category = (body.get("category") or "")[:64]
    try:
        with closing(_db()) as c:
            assessment.init(c)
            proj = assessment.append_and_project(
                c, tenant, fid, body.get("revision"), body.get("source_digest"),
                detector_id=detector_id, category=category, status=status, disposition=disposition,
                assertion=(assertion or None), value_judgment=(value_judgment or None), owner=owner,
                expected_version=body.get("expected_version"),
                idempotency_key=(body.get("idempotency_key") or None))
    except assessment.VersionConflict as vc:
        return JSONResponse({"error": "version conflict — reload the finding and reapply",
                             "detail": str(vc)}, status_code=409)
    # U10 (C): emit disposition.v1 only once the write-back committed, and only for a real verdict.
    verdict = _EMIT_VERDICT.get(disposition)
    if verdict:
        try:
            emit_disposition(build_disposition(
                finding_id=fid, entity=body.get("entity"), verdict=verdict,
                reason=(body.get("reason") or disposition), analyst=(owner or "analyst"),
                scope="finding", tenant=tenant))
        except Exception:                                    # noqa: BLE001
            _log.exception("disposition.v1 emit skipped (write-back persisted)")
    return {"ok": True, "version": proj["version"]}


@app.post("/api/findings/{fid}/notes")
def add_note(fid: str, body: dict = Body(...)):
    text = (body.get("text") or "").strip()
    if not text:                                    # reject empty notes at the boundary
        return JSONResponse({"error": "empty note"}, status_code=400)
    text = text[:4000]
    tenant = body.get("tenant_id") or ""
    with closing(_db()) as c:                       # A-U4: notes are append-only store events
        assessment.init(c)
        assessment.add_note(c, tenant, fid, body.get("revision"), body.get("source_digest"), text,
                            idempotency_key=(body.get("idempotency_key") or None))
    return {"ok": True}


@app.get("/api/detectors")
def detectors():
    """Per-detector quality rollup: ES `fired` volume joined with the verdicts you assign in triage.
    Lowest signal% at the highest volume = the detectors to tune. signal% = (confirmed+suspicious)/triaged."""
    try:
        det_field = _agg_field("detector_id")                  # KTD-A5: visible error on conflict
    except MappingConflict as mc:
        return JSONResponse({"error": str(mc), "field": mc.field, "detectors": []}, status_code=400)
    agg = _es(f"/{ES_INDEX}/_search", {"size": 0, "aggs": {
        "det": {"terms": {"field": det_field, "size": 200}}}})
    fired = {b["key"]: b["doc_count"] for b in agg.get("aggregations", {}).get("det", {}).get("buckets", [])}
    with closing(_db()) as c:                                  # A-U4: rollup from the assessment store
        assessment.init(c)
        roll = assessment.detector_rollup(c)
    out, total_reviewed = [], 0
    for d in set(fired) | set(roll):
        r = roll.get(d, {"threat": {}, "assertion": {}, "reviewed": 0})
        th, asr = r["threat"], r["assertion"]
        conf, susp, ben = th.get("confirmed", 0), th.get("suspicious", 0), th.get("benign", 0)
        reviewed = r["reviewed"]
        total_reviewed += reviewed
        sup, unsup, insuf = asr.get("supported", 0), asr.get("unsupported", 0), asr.get("insufficient_evidence", 0)
        out.append({"detector": d, "fired": fired.get(d, 0),
                    "reviewed": reviewed, "unreviewed": max(0, fired.get(d, 0) - reviewed),
                    "confirmed": conf, "suspicious": susp, "benign": ben,
                    # reviewed threat mix, NOT detector accuracy — labeled as such in the UI
                    "reviewed_threat_mix": round(100 * (conf + susp) / reviewed) if reviewed else None,
                    "supported": sup, "unsupported": unsup, "insufficient": insuf,
                    "support_rate": round(100 * sup / (sup + unsup)) if (sup + unsup) else None})
    out.sort(key=lambda r: (r["reviewed_threat_mix"] is None, r["reviewed_threat_mix"] or 0, -r["fired"]))
    return {"detectors": out, "reviewed": total_reviewed}


# ---- Suricata raw EVE (bus tail — full fidelity) -----------------------------
# Exact-field pivot targets for the U6 file view's reference-aware transfer/PCAP pivots. A `field` pivot
# is a TERM match on the exact aggregatable field (never a tokenized full-text guess), so a Community-ID
# / conn / pcap reference resolves to the RIGHT EVE record — allowlisted so an arbitrary field name can
# never be injected into the query.
_PIVOT_FIELDS = {"community_id", "pcap_filename", "flow_id", "conn_uid"}


@app.get("/api/suricata")
def suricata(mode: str = "alerts", event_type: str = "", severity_max: str = "", q: str = "",
             size: int = 150, since: str = "", frm: str = "", to: str = "", field: str = ""):
    """Raw Suricata EVE from the SIEM (suricata-eve-*, shipped by filebeat). Default mode=alerts surfaces
    signature-triggered events (the real findings, most-severe first); mode=all drills down to every EVE
    record. Suricata alert.severity is inverted: 1=High, 2=Medium, 3=Low; severity_max narrows to 1..N.
    `field` (allowlisted) resolves a reference EXACTLY on that field — the U6 transfer/PCAP pivot, which
    must resolve a transfer flow that carries NO alert (so it is always used with mode=all)."""
    IDX = "suricata-eve-*"
    et_field = _agg_field("event_type", IDX)
    filt = []
    if mode != "all":                       # default: only signature-triggered alerts
        filt.append({"term": {et_field: "alert"}})
    if event_type:
        filt.append({"term": {et_field: event_type}})
    smax = int(severity_max) if str(severity_max).strip().isdigit() else 0  # tolerate empty/blank
    if smax:                                # 1=High only, 2=High+Med, 3=all alerts
        filt.append({"range": {"alert.severity": {"lte": smax}}})
    if frm or to:
        rng = {}
        if frm:
            rng["gte"] = frm
        if to:
            rng["lte"] = to
        filt.append({"range": {"@timestamp": rng}})
    elif since:
        filt.append({"range": {"@timestamp": {"gte": f"now-{since}"}}})
    if field and q and field in _PIVOT_FIELDS:
        # reference-aware pivot: exact term match on the resolved (aggregatable) field, NOT a full-text
        # search. A transfer flow / pcap capture resolves reliably and needs no preceding alert.
        try:
            resolved = _agg_field(field, IDX)
        except MappingConflict:
            resolved = f"{field}.keyword"
        filt.append({"term": {resolved: q}})
        must = [{"match_all": {}}]
    else:
        must = [{"simple_query_string": {"query": q}}] if q else [{"match_all": {}}]
    sort = ([{"alert.severity": {"order": "asc", "missing": "_last"}}, {"@timestamp": {"order": "desc"}}]
            if mode != "all" else [{"@timestamp": {"order": "desc"}}])
    try:
        res = _es(f"/{IDX}/_search", {"size": size, "sort": sort,
                                      "query": {"bool": {"must": must, "filter": filt}}})
    except urllib.error.HTTPError as e:
        if e.code == 404:                   # index not created yet (no EVE shipped)
            return {"index": IDX, "count": 0, "events": [], "event_types": [],
                    "note": "suricata-eve-* not created yet — no EVE in the SIEM"}
        raise
    hits = res.get("hits", {}).get("hits", [])
    et = _es(f"/{IDX}/_search", {"size": 0, "aggs": {
        "t": {"terms": {"field": et_field, "size": 25}}}})
    types = [b["key"] for b in et.get("aggregations", {}).get("t", {}).get("buckets", [])]
    return {"index": IDX, "count": res.get("hits", {}).get("total", {}).get("value", 0),
            "events": [h["_source"] for h in hits], "event_types": types}


@app.get("/api/search")
def search(q: str = "", size: int = 100):
    if not q:
        return {"rows": []}
    return findings(q=q, size=size)


# ---- overview dashboard (011) ------------------------------------------------
_metrics = metrics_backend.get_backend()


def _es_day_count(index, day):   # UTC-day document count over @timestamp (A2: collection is ES-specific)
    # review item 7: half-open [start, next_start) — the old `lt ...23:59:59.999Z` dropped the last
    # sub-second of the day. _count is a server-side aggregation (not a first-page count).
    from datetime import datetime, timedelta
    start = day + "T00:00:00.000Z"
    nxt = (datetime.strptime(day, "%Y-%m-%d") + timedelta(days=1)).strftime("%Y-%m-%d") + "T00:00:00.000Z"
    body = {"query": {"range": {"@timestamp": {"gte": start, "lt": nxt}}}}
    return _es(f"/{index}/_count", body).get("count", 0)


def _probe_ready(service):       # direct /readyz probe on the ndr network (:9108)
    # returns True (ready) / False (MEASURED not-ready) / raises (unreachable or malformed = unknown).
    port = os.environ.get("NDR_METRICS_PORT", "9108")
    req = urllib.request.Request(f"http://{service}:{port}/readyz")
    try:
        with urllib.request.urlopen(req, timeout=3) as r:
            return r.status == 200 and r.read().decode().strip().lower().startswith("ready")
    except urllib.error.HTTPError as e:
        if e.code == 503:        # review item 3: 503 is a measured not-ready, not an unreachable target
            return False
        raise


@app.get("/api/overview/health")
def overview_health():
    return overview.build_health(_metrics, es_count=_es_day_count, probe_ready=_probe_ready)


@app.get("/api/overview/collection")
def overview_collection():
    return overview.build_collection(_es_day_count)


@app.get("/api/overview/cernity")
def overview_cernity():
    return overview.build_cernity(_metrics)


@app.get("/api/overview/traffic")
def overview_traffic(window_s: int = 900, step_s: int = 60):
    return overview.build_traffic(_metrics, window_s=window_s, step_s=step_s)


# 012 V2: one coordinated, briefly-cached response so the browser makes a single call and panels
# share one resolution. Partial sections still render independently (each build_* is self-contained).
_SNAP = {"at": 0.0, "key": None, "data": None}
_SNAP_TTL = float(os.environ.get("OVERVIEW_SNAPSHOT_TTL", "10"))


@app.get("/api/overview/snapshot")
def overview_snapshot(window_s: int = 900, step_s: int = 60):
    import time as _t
    key = (window_s, step_s)
    if _SNAP["data"] is not None and _SNAP["key"] == key and _t.time() - _SNAP["at"] < _SNAP_TTL:
        return {**_SNAP["data"], "cached": True, "age_s": round(_t.time() - _SNAP["at"], 1)}
    data = {"health": overview.build_health(_metrics, es_count=_es_day_count, probe_ready=_probe_ready),
            "cernity": overview.build_cernity(_metrics),
            "traffic": overview.build_traffic(_metrics, window_s=window_s, step_s=step_s),
            "window_s": window_s, "step_s": step_s}
    _SNAP.update(at=_t.time(), key=key, data=data)
    return {**data, "cached": False, "age_s": 0.0}


def _es_agg(index, body):   # findings_summary expects es_search(index, body); _es takes a full path
    return _es(f"/{index}/_search", body)


@app.get("/api/overview/analytics")
def overview_analytics():   # 012 V3: revision-deduped classification mix + evidence coverage
    return {"classification": findings_summary.classification_summary(_es_agg),
            "evidence": findings_summary.evidence_coverage(_es_agg)}


def _allowlist_rules():
    with closing(_db()) as c:
        allowlist.init(c)
        return allowlist.list_rules(c)


@app.get("/api/overview/queue")
def overview_queue(tier: str = "priority", size: int = 250, severity_min: int = 4):
    # 012 C+B: tiered investigation queue over the triage-worthy universe (sev>=4 by default) — the
    # low-severity observation flood stays in the Findings tab, not the queue. Tier then ranks these.
    rows = findings(severity_min=severity_min, size=size).get("rows", [])
    # ES holds multiple revision docs per finding_id (and index patterns can echo the same doc),
    # but the queue is a per-finding worklist — collapse to one row per finding_id, keeping the
    # first (latest; findings come back @timestamp desc). Undeduped rows rendered a duplicate
    # card (two severity spines) per finding. Deduped here so rows + counts agree.
    seen, deduped = set(), []
    for r in rows:
        fid = r.get("finding_id")
        if fid in seen:
            continue
        seen.add(fid)
        deduped.append(r)
    rows = deduped
    rules = _allowlist_rules()
    counts, tiered = {}, []
    for r in rows:
        hit = allowlist.match(r, rules)
        t, why = triage_tier.tier_of(r, allowlisted=hit is not None)
        counts[t] = counts.get(t, 0) + 1
        tiered.append({**r, "tier": t, "tier_reason": why, "allowlisted_by": (hit or {}).get("reason")})
    want = set(triage_tier.FILTER_TIERS.get(tier, triage_tier.FILTER_TIERS["all"]))
    shown = [r for r in tiered if r["tier"] in want]
    return {"tier": tier, "rows": shown, "counts": counts, "total_scanned": len(rows),
            "note": "tier is a lead-ordering aid, not a verdict; nothing is hidden — use 'all' or 'allowlisted' to see every finding."}


@app.get("/api/allowlist")
def allowlist_list():
    with closing(_db()) as c:
        allowlist.init(c)
        return {"rules": allowlist.list_rules(c), "fields": list(allowlist.FIELDS)}


@app.post("/api/allowlist")
def allowlist_add(body: dict = Body(...)):
    with closing(_db()) as c:
        allowlist.init(c)
        try:
            rid = allowlist.add_rule(c, body.get("field"), body.get("value"),
                                     body.get("reason", ""), body.get("created_by", "analyst"),
                                     emit=_emit_allowlist_disposition)   # U10 (C): allowlist -> disposition.v1
        except ValueError as e:
            return JSONResponse({"error": str(e)}, status_code=400)
        return {"id": rid, "ok": True}


@app.post("/api/allowlist/{rid}/delete")
def allowlist_delete(rid: int):
    with closing(_db()) as c:
        allowlist.init(c)
        allowlist.delete_rule(c, rid)
        return {"ok": True}


# ---- U10 (A): FLEET-HEALTH — read-only proxy to the fleet API (config-driven FLEET_API_URL) ----
# A2 guardrail: additive to the SIEM export, NO raw-log storage here. A degraded/unreachable
# upstream renders a measured 'unavailable', never a crash.
def _http_get_json(base, path, token="", timeout=5):
    if not base:
        raise RuntimeError("upstream not configured")
    # U3a/U5 authz the caller by bearer token (tenant is NEVER a query param); send it, or the
    # upstream 401s and the proxy would never see data. Absent token -> no header -> a 401 the
    # caller surfaces as 'unavailable'. The token stays inside this one request.
    headers = {"Authorization": "Bearer " + token} if token else {}
    with urllib.request.urlopen(urllib.request.Request(base + path, headers=headers), timeout=timeout) as r:
        return json.load(r)


def _fleet_get(path):
    return _http_get_json(FLEET_API_URL, path, FLEET_API_TOKEN)


# A collection wrapped in {"quality"/"status": ...} or carrying an error is a THIRD outcome —
# upstream-declared-degraded — distinct from healthy-with-data and healthy-empty. It must win over an
# (often empty) list: never relabel a self-declared-degraded/unavailable payload as a fresh result.
_HEALTHY_QUALITY = {"", "fresh", "ok", "healthy", "live", "current", "available", "success"}


def _upstream_degraded(payload):
    """Return a reason string if `payload` EXPLICITLY signals failure/degradation, else None. The real
    U3a/U5 200 bodies carry no such marker (so healthy reads return None here), but an error body or
    any explicit quality/status/degraded/unavailable flag is honored before the collection is read."""
    if not isinstance(payload, dict):
        return "degraded_upstream"
    if payload.get("error"):
        return "degraded_upstream"
    for key in ("quality", "status"):
        v = payload.get(key)
        if isinstance(v, str) and v.strip().lower() not in _HEALTHY_QUALITY:
            return v.strip().lower()
    if payload.get("degraded") or payload.get("unavailable"):
        return "degraded_upstream"
    return None


def _normalize_fleet(payload):
    """Shape U3a's `{"sensors": [sensor_view(...)]}` into the panel contract. sensor_view keys the
    sensor by `sensor_uuid` and carries the registry's server-computed `skew_flag` (offset vs the
    registry's own SKEW_THRESHOLD_MS) + staleness (§6.2–6.4); TRUST skew_flag, only derive one from
    the documented `clock_offset_ms` if the registry omits it (against the same-default knob, so a
    derived flag never contradicts a registry-computed one). An explicit degraded/unavailable marker,
    an error body, or a non-list `sensors` is a degraded upstream -> 'unavailable', never fresh-empty."""
    reason = _upstream_degraded(payload)
    if reason or not isinstance(payload.get("sensors"), list):
        return {"quality": "unavailable", "sensors": [], "reason": reason or "degraded_upstream",
                "skew_warn_ms": _FLEET_SKEW_WARN_MS}
    sensors = []
    for s in payload["sensors"]:
        offset_ms = s.get("clock_offset_ms")                 # sensor-health.v1 / sensor_view (PLAN §6.2/A7)
        skew_s = offset_ms / 1000.0 if isinstance(offset_ms, (int, float)) else None
        flag = s.get("skew_flag")                            # registry-computed flag wins when present
        if flag is None:
            flag = isinstance(offset_ms, (int, float)) and abs(offset_ms) > _FLEET_SKEW_WARN_MS
        stale = bool(s["stale"]) if s.get("stale") is not None else (s.get("online") is False)
        sensors.append({"sensor_id": s.get("sensor_uuid") or s.get("sensor_id") or "?",
                        "health": s.get("status") or s.get("health") or ("stale" if stale else "unknown"),
                        "stale": stale, "clock_offset_ms": offset_ms, "clock_skew_s": skew_s,
                        "clock_skew_flag": bool(flag),
                        "last_seen": s.get("last_seen") or s.get("last_heartbeat_at")})
    return {"quality": "fresh", "sensors": sensors, "skew_warn_ms": _FLEET_SKEW_WARN_MS}


@app.get("/api/fleet/health")
def fleet_health():
    try:
        return _normalize_fleet(_fleet_get("/sensors"))
    except Exception as e:                                   # noqa: BLE001
        return {"quality": "unavailable", "sensors": [], "reason": e.__class__.__name__}


# ---- U10 (B): EVIDENCE-PIVOT — read-only proxy to the evidence API (config-driven EVIDENCE_API_URL)
def _evidence_get(path):
    return _http_get_json(EVIDENCE_API_URL, path, EVIDENCE_API_TOKEN)


def _normalize_evidence(payload):
    """Pass U5's `{"observations":[observation.v1...], "capabilities":[...], "next":...}` through with
    each normalized observation PRESERVED WHOLE — obs_id/ts/tenant/entities/type/fields/capabilities/
    source_ref (the earlier proxy flattened these to id/kind/summary and dropped the fields + the
    per-observation capability set, defeating the whole point of the evidence pivot). U5's top-level
    `capabilities` is the union across the page. An explicit degraded/unavailable marker, an error
    body, or a non-list `observations` is a degraded upstream -> 'unavailable', never fresh-empty."""
    reason = _upstream_degraded(payload)
    if reason or not isinstance(payload.get("observations"), list):
        return {"quality": "unavailable", "observations": [], "capabilities": [],
                "reason": reason or "degraded_upstream"}
    return {"quality": "fresh", "observations": payload["observations"],
            "capabilities": payload.get("capabilities") or [],
            "next": payload.get("next"), "next_after": payload.get("next_after")}


@app.get("/api/evidence/{fid}")
def evidence_pivot(fid: str, entity: str = "", frm: str = "", to: str = "", otype: str = ""):
    # U5 is entity+window scoped (GET /observations?entity=&from=&to=&type=), NOT keyed by finding_id —
    # the finding supplies the entity + time window (passed by the caller). No entity/window -> nothing
    # to query -> a measured 'unavailable', not a fake empty result. tenant is server-derived upstream.
    if not entity or not frm or not to:
        return {"quality": "unavailable", "observations": [], "capabilities": [],
                "reason": "entity_and_window_required"}
    try:
        from urllib.parse import urlencode
        params = {"entity": entity, "from": frm, "to": to}
        if otype:
            params["type"] = otype
        return _normalize_evidence(_evidence_get("/observations?" + urlencode(params)))
    except Exception as e:                                   # noqa: BLE001
        return {"quality": "unavailable", "observations": [], "capabilities": [],
                "reason": e.__class__.__name__}


# ---- Inc3 U6: FILES — read-only file-observation / YARA-hit view over the evidence API ----------
# Mirrors the evidence-pivot proxy (config-driven EVIDENCE_API_URL/_TOKEN). U5 is entity+window scoped
# (GET /observations?type=file&entity=&from=&to=); tenant is server-derived upstream from the bearer
# token (§21), NEVER a query param, and the token never leaves this one request. KTD2 is enforced HERE
# at the trust boundary: a YARA verdict is surfaced ONLY for a bytes_available (scanned) file — a
# metadata_only/hashes_only file NEVER carries a verdict, even if a buggy/hostile upstream attached one.
# A degraded/unreachable upstream renders 'unavailable', never a fake fresh-empty.
_FILE_STATES = {"metadata_only", "hashes_only", "bytes_available"}


def _file_field(o, *names, default=None):
    """Read a file attribute from the shipped observation.v1 shape: attributes live under
    `fields.file` (contracts/file_observation.schema.json), NOT flat in `fields` or at top level."""
    fields = o.get("fields") if isinstance(o.get("fields"), dict) else {}
    f = fields.get("file") if isinstance(fields.get("file"), dict) else {}
    for n in names:
        if f.get(n) is not None:
            return f[n]
    return default


def _scan_verdict(o):
    """The rule-stamped scan result at `fields.file.scan_verdict` (engine, scanned_at, ruleset_sha256,
    matched_rules[]). Present ONLY for a scanned bytes_available file; None otherwise."""
    fields = o.get("fields") if isinstance(o.get("fields"), dict) else {}
    f = fields.get("file") if isinstance(fields.get("file"), dict) else {}
    sv = f.get("scan_verdict")
    return sv if isinstance(sv, dict) else None


_SCAN_DONE = {"completed", "complete", "done", "scanned", "ok", "success", "finished", "matched", "clean"}
_SCAN_PENDING = {"pending", "queued", "in_progress", "in-progress", "scanning", "running", "requested"}
_SCAN_FAILED = {"failed", "error", "timeout", "timed_out", "aborted", "cancelled", "canceled"}
_SCAN_NONE = {"unscanned", "not_scanned", "not-scanned", "skipped", "none", "n/a", "na"}


def _scan_outcome(o, state):
    """Scan completion is EXPLICIT upstream evidence, NOT merely 'bytes are available'. The presence of
    a `fields.file.scan_verdict` (engine/scanned_at) IS proof a scan ran — an EMPTY matched_rules then
    means NO MATCH (a completed scan), never 'unscanned'. A bytes_available file with no scan_verdict is
    'unknown' (never a silent clean scan); a non-bytes_available file is 'unscanned'."""
    if state != "bytes_available":
        return "unscanned"                              # no bytes captured -> nothing could be scanned
    sv = _scan_verdict(o)
    if sv is None:
        return "unknown"                                # bytes present but no scan evidence yet
    if sv.get("scanned_at") or sv.get("engine") or ("matched_rules" in sv):
        return "completed"                              # a verdict ran to completion (empty hits = no match)
    return "unknown"


# A file transfer flow carries NO alert, so the Suricata pivot must resolve it by an EXACT match on an
# allowlisted reference field (see _PIVOT_FIELDS / GET /api/suricata?field=), not a full-text search that
# would drown it. Each alias maps to the field the browser hands back to that endpoint; order = priority.
_TRANSFER_REFS = (("community_id", "community_id"), ("conn_uid", "conn_uid"),
                  ("flow_id", "flow_id"), ("transfer_ref", "conn_uid"))
_PCAP_REFS = (("pcap_filename", "pcap_filename"), ("pcap_ref", "pcap_filename"), ("pcap", "pcap_filename"))


def _pivot_ref(o, aliases):
    """Return (ref_value, pivot_field) for the first present alias, else (None, None) — preserving WHICH
    reference type resolved so the browser pivots on the matching allowlisted field."""
    for key, field in aliases:
        v = _file_field(o, key)
        if v is not None:
            return v, field
    return None, None


def _normalize_files(payload):
    """Shape U5's `{"observations":[observation.v1 type=file ...]}` into the files panel contract,
    enforcing KTD2: the YARA verdict (rule name + version + hit) is kept ONLY for a bytes_available
    file; for any other state it is dropped here so the browser can never render a verdict on an
    unscanned file. An explicit degraded/unavailable marker, an error body, or a non-list
    `observations` is a degraded upstream -> 'unavailable', never a fresh-empty."""
    reason = _upstream_degraded(payload)
    if reason or not isinstance(payload.get("observations"), list):
        return {"quality": "unavailable", "files": [], "capabilities": [],
                "reason": reason or "degraded_upstream"}
    files = []
    for o in payload["observations"]:
        o = o if isinstance(o, dict) else {}
        state = _file_field(o, "state", "file_state", default="metadata_only")
        if state not in _FILE_STATES:
            state = "metadata_only"
        bytes_available = state == "bytes_available"
        # KTD2: only a scanned file has a verdict. Strip any verdict the upstream attached to an
        # unscanned file — the UI must show 'metadata only — not scanned', never an implied clean/dirty.
        # KTD2: the verdict lives at fields.file.scan_verdict and only for a bytes_available file.
        sv = _scan_verdict(o) if bytes_available else None
        raw_hits = sv.get("matched_rules") if (sv and isinstance(sv.get("matched_rules"), list)) else []
        rs_ver = (sv or {}).get("ruleset_version") or ""
        yara = []
        for h in raw_hits:
            h = h if isinstance(h, dict) else {"rule": h}
            yara.append({"rule": h.get("rule") or h.get("name") or "?",
                         "version": h.get("version") or h.get("ruleset_version") or rs_ver or ""})
        intel = _file_field(o, "intel_hash_hit", "intel_hit")
        scan = _scan_outcome(o, state)
        transfer_ref, transfer_field = _pivot_ref(o, _TRANSFER_REFS)
        pcap_ref, pcap_field = _pivot_ref(o, _PCAP_REFS)
        files.append({
            "obs_id": o.get("obs_id") or o.get("id") or "?",
            "ts": o.get("ts"),
            "entities": o.get("entities") if isinstance(o.get("entities"), list) else [],
            "state": state, "bytes_available": bytes_available,
            "scan": scan, "scanned": scan == "completed",
            "mime": _file_field(o, "mime", "mime_type"),
            "size": _file_field(o, "size", "bytes_total"),
            "bytes_scanned": _file_field(o, "bytes_scanned"),
            "sha256": _file_field(o, "sha256"), "md5": _file_field(o, "md5"),
            "yara": yara,
            "intel_hash_hit": intel if isinstance(intel, dict) else None,
            "transfer_ref": transfer_ref, "transfer_field": transfer_field,
            "pcap_ref": pcap_ref, "pcap_field": pcap_field,
            "source_ref": o.get("source_ref"),
            "capabilities": o.get("capabilities") if isinstance(o.get("capabilities"), list) else []})
    return {"quality": "fresh", "files": files,
            "capabilities": payload.get("capabilities") or [],
            "next": payload.get("next"), "next_after": payload.get("next_after")}


@app.get("/api/files")
def files_view(entity: str = "", frm: str = "", to: str = ""):
    # U5 is entity+window scoped; without entity+window there is nothing to query -> measured
    # 'unavailable', not a fake empty result. tenant is server-derived upstream from the bearer token.
    if not entity or not frm or not to:
        return {"quality": "unavailable", "files": [], "capabilities": [],
                "reason": "entity_and_window_required"}
    try:
        params = {"entity": entity, "from": frm, "to": to, "type": "file"}
        return _normalize_files(_evidence_get("/observations?" + urlencode(params)))
    except Exception as e:                                     # noqa: BLE001
        return {"quality": "unavailable", "files": [], "capabilities": [],
                "reason": e.__class__.__name__}


# ---- U6 (B): COVERAGE — read-only proxy to the ATT&CK coverage API (config-driven COVERAGE_API_URL)
# A2 guardrail: additive, no raw-log storage. tenant is server-derived upstream from the bearer token
# (§21), NEVER a query param. A degraded/unreachable upstream renders 'unavailable', never fresh-empty.
def _coverage_get(path):
    return _http_get_json(COVERAGE_API_URL, path, COVERAGE_API_TOKEN)


def _normalize_coverage(payload):
    """Shape U4's `{"techniques":[...], "gaps":[...], "summary":{...}}` into the panel contract, keeping
    the exists-vs-observed distinction the coverage API draws: a technique is `covered` when a detector
    maps to it (fleet-global) and `observed` when it actually fired (tenant-scoped observed overlay); a
    `gap` is neither. An explicit degraded/unavailable marker, an error body, or a non-list `techniques`
    is a degraded upstream -> 'unavailable', never a fake fresh-empty grid."""
    reason = _upstream_degraded(payload)
    if reason or not isinstance(payload.get("techniques"), list):
        return {"quality": "unavailable", "techniques": [], "gaps": [], "summary": {},
                "reason": reason or "degraded_upstream"}
    techniques = []
    for t in payload["techniques"]:
        t = t if isinstance(t, dict) else {}
        dets = t.get("detectors") if isinstance(t.get("detectors"), list) else []
        covered = t.get("covered")
        if covered is None:
            covered = t.get("exists")
        if covered is None:
            covered = bool(dets)                              # no explicit flag -> a mapped detector means covered
        techniques.append({
            "technique": t.get("technique") or t.get("technique_id") or t.get("id") or "?",
            "name": t.get("name") or t.get("technique_name") or "",
            "tactic": t.get("tactic") or t.get("tactic_id") or "",
            "detectors": dets, "covered": bool(covered), "observed": bool(t.get("observed"))})
    gaps = payload.get("gaps") if isinstance(payload.get("gaps"), list) else []
    summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
    return {"quality": "fresh", "techniques": techniques, "gaps": gaps, "summary": summary}


@app.get("/api/coverage")
def coverage_view():
    try:
        return _normalize_coverage(_coverage_get("/coverage"))
    except Exception as e:                                    # noqa: BLE001
        return {"quality": "unavailable", "techniques": [], "gaps": [], "summary": {},
                "reason": e.__class__.__name__}


# ---- U6 (B): QUALITY — read-only proxy to the per-detector quality API (config-driven QUALITY_API_URL)
def _quality_get(path):
    return _http_get_json(QUALITY_API_URL, path, QUALITY_API_TOKEN)


def _normalize_quality(payload):
    """Pass U5's per-detector quality report through, PRESERVING the two rates it deliberately keeps
    separate: each detector's `precision`/`fp_rate` (finding-joined, from confirmed vs benign/FP
    dispositions) and the top-level `entity_allowlist_suggestion_rate` (entity-scoped, advisory — NOT
    folded into any detector's precision). Each rate carries its Wilson interval + low_confidence flag
    verbatim. A degraded/unreachable upstream or a non-list `detectors` -> 'unavailable', never
    fresh-empty."""
    reason = _upstream_degraded(payload)
    if reason or not isinstance(payload.get("detectors"), list):
        return {"quality": "unavailable", "detectors": [], "reason": reason or "degraded_upstream"}
    return {"quality": "fresh", "detectors": payload["detectors"],
            "entity_allowlist_suggestion_rate": payload.get("entity_allowlist_suggestion_rate"),
            "total_dispositions": payload.get("total_dispositions"),
            "unattributed_dispositions": payload.get("unattributed_dispositions"),
            "window": payload.get("window"), "advisory_only": payload.get("advisory_only"),
            "low_confidence_below": payload.get("low_confidence_below")}


@app.get("/api/quality")
def quality_view(frm: str = "", to: str = ""):
    # U5's /quality REQUIRES a timezone-aware [from,to) window (it 400s without one and rejects any
    # other param). Default to a trailing 30-day window so the panel loads without the caller supplying
    # one; the caller may still pass frm/to. tenant is server-derived upstream from the bearer token.
    if not frm or not to:
        now = _dt.datetime.now(_dt.timezone.utc)
        to = to or now.isoformat()
        frm = frm or (now - _dt.timedelta(days=30)).isoformat()
    try:
        from urllib.parse import urlencode
        return _normalize_quality(_quality_get("/quality?" + urlencode({"from": frm, "to": to})))
    except Exception as e:                                    # noqa: BLE001
        return {"quality": "unavailable", "detectors": [], "reason": e.__class__.__name__}


# ---- static SPA --------------------------------------------------------------
@app.get("/")
def index():
    # no-cache so the HTML always revalidates and picks up new ?v= asset versions immediately
    # (prevents a stale cached page from pinning old JS/CSS).
    return FileResponse(os.path.join(os.path.dirname(__file__), "static", "index.html"),
                        headers={"Cache-Control": "no-cache, must-revalidate"})


app.mount("/static", StaticFiles(directory=os.path.join(os.path.dirname(__file__), "static")), name="static")

# U9: the upstream session selects one tenant and audit actor. Browser identity claims
# are rejected; no case data or logs are persisted by this proxy.
CASE_API_URL = os.environ.get("CASE_API_URL", "").rstrip("/")
CASE_API_TOKEN = os.environ.get("CASE_API_TOKEN", "")


def _case_request(path, method="GET", body=None):
    if not CASE_API_URL or not CASE_API_TOKEN:
        raise RuntimeError("case upstream not configured")
    headers = {"Authorization": "Bearer " + CASE_API_TOKEN}
    data = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body).encode()
    request = urllib.request.Request(CASE_API_URL + path, data=data, headers=headers, method=method)
    with urllib.request.urlopen(request, timeout=5) as response:
        return json.load(response)


def _case_valid(doc):
    # A case's `status` is workflow state, NOT an upstream health marker.
    return (isinstance(doc, dict) and not doc.get("error")
            and not doc.get("degraded") and not doc.get("unavailable")
            and doc.get("quality", "fresh") in _HEALTHY_QUALITY
            and all(isinstance(doc.get(k), str) for k in ("case_id", "tenant", "title", "created", "updated"))
            and (doc.get("owner") is None or isinstance(doc["owner"], str))
            and doc.get("status") in ("new", "investigating", "resolved", "closed")
            and all(isinstance(doc.get(k), list) for k in ("assignees", "notes", "linked_findings", "linked_entities", "audit"))
            and all(isinstance(v, str) for k in ("assignees", "linked_findings") for v in doc[k])
            and all(isinstance(n, dict) and all(isinstance(n.get(k), str) for k in ("author", "text", "ts")) for n in doc["notes"])
            and all(isinstance(e, dict) and e.get("type") in _ENTITY_TYPES and isinstance(e.get("value"), str) for e in doc["linked_entities"]))


def _case_proxy(path, method="GET", body=None, collection=False):
    try:
        result = _case_request(path, method, body)
        if collection:
            valid = (not _upstream_degraded(result) and isinstance(result.get("cases"), list)
                     and all(_case_valid(c) for c in result["cases"])
                     and type(result.get("limit")) is int and 1 <= result["limit"] <= 200
                     and type(result.get("offset")) is int and result["offset"] >= 0
                     and "next_offset" in result and (result["next_offset"] is None or
                         (type(result["next_offset"]) is int and result["next_offset"] > result["offset"])))
        else:
            valid = _case_valid(result)
        if not valid:
            raise ValueError("invalid case response")
        return result
    except urllib.error.HTTPError as exc:
        if exc.code in (400, 403, 404, 409, 422):
            return JSONResponse({"error": {400: "Invalid case request or status transition", 403: "Case session is read only",
                404: "Case not found", 409: "Case conflict", 422: "Invalid case request"}[exc.code]}, status_code=exc.code)
    except Exception:
        pass
    return JSONResponse({"quality": "unavailable", "error": "Case API unavailable"}, status_code=503)


@app.get("/api/cases")
def case_list(request: Request):
    pairs = list(request.query_params.multi_items())
    if any(k not in {"owner", "status", "limit", "offset"} for k, _ in pairs) or len(dict(pairs)) != len(pairs):
        return JSONResponse({"error": "Invalid case query"}, status_code=400)
    return _case_proxy("/cases" + ("?" + urlencode(pairs) if pairs else ""), collection=True)


@app.get("/api/cases/{case_id}")
def case_detail(case_id: str, request: Request):
    if request.query_params or not re.fullmatch(r"[A-Za-z0-9_-]{1,256}", case_id):
        return JSONResponse({"error": "Invalid case request"}, status_code=400)
    return _case_proxy("/cases/" + case_id)


@app.post("/api/cases/{case_id}/{action}")
def case_action(case_id: str, action: str, request: Request, body: dict = Body(...)):
    fields = {"owner": "owner", "assign": "assignee", "notes": "text", "status": "status",
              "findings": "finding_id", "entities": "entity"}
    field = fields.get(action)
    if (request.query_params or not re.fullmatch(r"[A-Za-z0-9_-]{1,256}", case_id)
            or field is None or set(body) != {field}):
        return JSONResponse({"error": "Invalid case mutation"}, status_code=400)
    # Exact body fields only: never pass caller tenant/actor/auth claims upstream.
    return _case_proxy("/cases/" + case_id + "/" + action, "POST", body)
