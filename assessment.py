"""A-U2: append-only, revision/digest-anchored assessment store (plan 010 Track A, KTD-A1..A3).

Three identities:
  logical    (tenant_id, finding_id)          -- workflow attaches here
  received   (index, doc_id)                  -- what ES actually returned
  assessed   (tenant_id, finding_id, revision, source_digest)  -- judgments/notes attach here

Storage lives in the existing soc.db: an append-only `assessment_events` log + a derived
`assessment_current` projection for fast queue reads. A write (enabled in A-U4) is a single
transaction: append event(s) + upsert the projection, guarded by an optimistic expected-version
check and an idempotency key. The source digest is computed HERE, in Python, over a pinned
canonicalization of the received _source -- never in the browser (JS loses precision above 2^53;
Python preserves int precision exactly, so the digest of a large-id _source stays exact)."""
import datetime
import hashlib
import json
import sqlite3

CANON_VERSION = "vantage-canon-1"   # pinned; bump if the canonicalization rule below changes


def _now():
    return datetime.datetime.utcnow().isoformat(timespec="seconds")


def canonical_source(src):
    """Deterministic bytes for a received _source: stable key order, preserved array order,
    UTF-8. Absent != null -- an absent key simply doesn't appear; an explicit null serializes
    as null. Python parsed the ES response, so ints keep full precision here."""
    return json.dumps(src, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def source_digest(src):
    return CANON_VERSION + ":" + hashlib.sha256(canonical_source(src)).hexdigest()


class VersionConflict(Exception):
    """Raised when a write's expected_version does not match the stored projection version."""


def init(conn):
    conn.execute("""CREATE TABLE IF NOT EXISTS assessment_events(
        seq INTEGER PRIMARY KEY AUTOINCREMENT,
        tenant_id TEXT NOT NULL DEFAULT '',
        finding_id TEXT NOT NULL,
        detector_id TEXT,                 -- carried so the rollup can group by (detector, class)
        category TEXT,                    -- assertion-class proxy (A-U4)
        revision INTEGER,                 -- assessed revision; NULL = revision-unknown (legacy)
        source_digest TEXT,               -- digest of the assessed received _source; NULL for legacy
        kind TEXT NOT NULL,               -- workflow|threat|assertion|value|note|migrated
        value TEXT,
        actor TEXT NOT NULL DEFAULT 'analyst',
        reason TEXT,
        renderer_version TEXT,            -- view provenance (A-U3); NOT part of the digest
        ts TEXT NOT NULL,
        idempotency_key TEXT UNIQUE       -- repeated key => no-op (retry-safe)
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS assessment_current(
        tenant_id TEXT NOT NULL DEFAULT '',
        finding_id TEXT NOT NULL,
        detector_id TEXT,
        category TEXT,
        status TEXT DEFAULT 'new',
        disposition TEXT DEFAULT '',      -- threat judgment (confirmed/suspicious/benign)
        assertion TEXT DEFAULT '',        -- A-U4: supported/unsupported/insufficient_evidence
        value_judgment TEXT DEFAULT '',   -- A-U4: useful/low_value
        owner TEXT DEFAULT '',
        assessed_revision INTEGER,
        assessed_digest TEXT,             -- digest of the revision the current judgment assessed
        version INTEGER NOT NULL DEFAULT 0,   -- optimistic-concurrency counter
        updated TEXT,
        PRIMARY KEY (tenant_id, finding_id)
    )""")
    # idempotent column adds so a store created by an earlier version gains the newer columns
    for tbl, col in (("assessment_current", "detector_id"), ("assessment_current", "category"),
                     ("assessment_current", "assertion"), ("assessment_current", "value_judgment"),
                     ("assessment_events", "detector_id"), ("assessment_events", "category")):
        try:
            conn.execute("ALTER TABLE %s ADD COLUMN %s TEXT" % (tbl, col))
        except sqlite3.OperationalError:
            pass


def current(conn, tenant_id, finding_id):
    row = conn.execute("""SELECT detector_id,category,status,disposition,assertion,value_judgment,owner,
        assessed_revision,assessed_digest,version,updated
        FROM assessment_current WHERE tenant_id=? AND finding_id=?""", (tenant_id, finding_id)).fetchone()
    if row:
        return dict(row)
    return {"detector_id": None, "category": None, "status": "new", "disposition": "", "assertion": "",
            "value_judgment": "", "owner": "", "assessed_revision": None, "assessed_digest": None,
            "version": 0, "updated": ""}


def detector_rollup(conn):
    """Per-detector: reviewed threat mix (from the projection) + assertion support. This is NOT
    detector accuracy — the caller must label it 'reviewed threat mix' with its denominator."""
    out = {}

    def slot(d):
        return out.setdefault(d or "(unattributed)", {"threat": {}, "assertion": {}, "reviewed": 0})
    for r in conn.execute("""SELECT detector_id d, disposition, COUNT(*) n FROM assessment_current
                             WHERE disposition!='' GROUP BY detector_id, disposition"""):
        slot(r["d"])["threat"][r["disposition"]] = r["n"]
    for r in conn.execute("""SELECT detector_id d, assertion, COUNT(*) n FROM assessment_current
                             WHERE assertion!='' GROUP BY detector_id, assertion"""):
        slot(r["d"])["assertion"][r["assertion"]] = r["n"]
    for r in conn.execute("""SELECT detector_id d, COUNT(*) n FROM assessment_current
                             WHERE status!='new' OR disposition!='' OR assertion!='' GROUP BY detector_id"""):
        slot(r["d"])["reviewed"] = r["n"]
    return out


def history(conn, tenant_id, finding_id):
    return [dict(r) for r in conn.execute(
        """SELECT seq,revision,source_digest,kind,value,actor,reason,renderer_version,ts
           FROM assessment_events WHERE tenant_id=? AND finding_id=? ORDER BY seq""",
        (tenant_id, finding_id))]


def notes(conn, tenant_id, finding_id):
    return [{"text": r["value"], "ts": r["ts"]} for r in conn.execute(
        "SELECT value,ts FROM assessment_events WHERE tenant_id=? AND finding_id=? AND kind='note' ORDER BY seq",
        (tenant_id, finding_id))]


def new_evidence_since_assessment(assessed_digest, current_digest):
    """True only when a judgment exists against a digest that differs from the current one."""
    return bool(assessed_digest and current_digest and assessed_digest != current_digest)


def append_and_project(conn, tenant_id, finding_id, revision, source_digest_val, *,
                       detector_id=None, category=None,
                       status=None, disposition=None, assertion=None, value_judgment=None, owner=None,
                       actor="analyst", reason=None, renderer_version=None,
                       expected_version=None, idempotency_key=None):
    """Append one event per provided judgment field (workflow/threat/assertion/value/owner) + upsert
    the projection, atomically. Guarded by expected_version (optimistic; raises VersionConflict) and
    idempotency_key (retry-safe no-op). Returns the resulting projection dict."""
    ts = _now()
    with conn:  # BEGIN..COMMIT, ROLLBACK on exception
        if idempotency_key and conn.execute(
                "SELECT 1 FROM assessment_events WHERE idempotency_key=?", (idempotency_key,)).fetchone():
            return current(conn, tenant_id, finding_id)                 # replay: no-op
        cur = conn.execute("SELECT version FROM assessment_current WHERE tenant_id=? AND finding_id=?",
                           (tenant_id, finding_id)).fetchone()
        have = cur["version"] if cur else 0
        if expected_version is not None and expected_version != have:
            raise VersionConflict("expected %s, have %s" % (expected_version, have))
        first_key = idempotency_key
        for kind, value in (("workflow", status), ("threat", disposition), ("assertion", assertion),
                            ("value", value_judgment), ("owner", owner)):
            if value is None:
                continue
            conn.execute("""INSERT INTO assessment_events
                (tenant_id,finding_id,detector_id,category,revision,source_digest,kind,value,actor,reason,renderer_version,ts,idempotency_key)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (tenant_id, finding_id, detector_id, category, revision, source_digest_val, kind, value,
                 actor, reason, renderer_version, ts, first_key))
            first_key = None
        b = current(conn, tenant_id, finding_id)
        vals = {"status": status, "disposition": disposition, "assertion": assertion,
                "value_judgment": value_judgment, "owner": owner, "detector_id": detector_id,
                "category": category}
        merged = {k: (v if v is not None else b[k]) for k, v in vals.items()}
        conn.execute("""INSERT INTO assessment_current
            (tenant_id,finding_id,detector_id,category,status,disposition,assertion,value_judgment,owner,assessed_revision,assessed_digest,version,updated)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(tenant_id,finding_id) DO UPDATE SET
              detector_id=excluded.detector_id, category=excluded.category, status=excluded.status,
              disposition=excluded.disposition, assertion=excluded.assertion, value_judgment=excluded.value_judgment,
              owner=excluded.owner, assessed_revision=excluded.assessed_revision, assessed_digest=excluded.assessed_digest,
              version=assessment_current.version+1, updated=excluded.updated""",
            (tenant_id, finding_id, merged["detector_id"], merged["category"], merged["status"],
             merged["disposition"], merged["assertion"], merged["value_judgment"], merged["owner"],
             revision, source_digest_val, have + 1, ts))
        return current(conn, tenant_id, finding_id)


def add_note(conn, tenant_id, finding_id, revision, source_digest_val, text, *,
             actor="analyst", idempotency_key=None):
    ts = _now()
    with conn:
        if idempotency_key and conn.execute(
                "SELECT 1 FROM assessment_events WHERE idempotency_key=?", (idempotency_key,)).fetchone():
            return
        conn.execute("""INSERT INTO assessment_events
            (tenant_id,finding_id,revision,source_digest,kind,value,actor,ts,idempotency_key)
            VALUES(?,?,?,?, 'note', ?, ?, ?, ?)""",
            (tenant_id, finding_id, revision, source_digest_val, text, actor, ts, idempotency_key))


# A-U7: local mapping-review request backlog. A request NEVER mutates a finding, relabels history,
# or marks other examples benign — it is analyst evidence for the engineering mapping process, saved
# to a LOCAL queue. No outbound automation here; a connector may publish 'submitted' requests later.
_REQ_STATES = {"draft", "submitted", "reviewing", "resolved", "declined"}


def init_requests(conn):
    conn.execute("""CREATE TABLE IF NOT EXISTS mapping_requests(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tenant_id TEXT DEFAULT '', finding_id TEXT, revision INTEGER, detector_id TEXT, policy_version TEXT,
        risk_id TEXT, risk_name TEXT, resolution_reason TEXT, evidence_available TEXT,
        explanation TEXT, proposed TEXT, state TEXT DEFAULT 'submitted',
        actor TEXT DEFAULT 'analyst', created TEXT, updated TEXT)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS mapping_request_history(
        id INTEGER PRIMARY KEY AUTOINCREMENT, request_id INTEGER, state TEXT, actor TEXT, note TEXT, ts TEXT)""")


def create_request(conn, **f):
    ts = _now()
    with conn:
        cur = conn.execute("""INSERT INTO mapping_requests
            (tenant_id,finding_id,revision,detector_id,policy_version,risk_id,risk_name,resolution_reason,
             evidence_available,explanation,proposed,state,actor,created,updated)
            VALUES(?,?,?,?,?,?,?,?,?,?,?, 'submitted', ?, ?, ?)""",
            (f.get("tenant_id", ""), f.get("finding_id"), f.get("revision"), f.get("detector_id"),
             f.get("policy_version"), f.get("risk_id"), f.get("risk_name"), f.get("resolution_reason"),
             f.get("evidence_available"), f.get("explanation"), f.get("proposed"),
             f.get("actor", "analyst"), ts, ts))
        rid = cur.lastrowid
        conn.execute("INSERT INTO mapping_request_history(request_id,state,actor,note,ts) VALUES(?,?,?,?,?)",
                     (rid, "submitted", f.get("actor", "analyst"), "created", ts))
    return rid


def list_requests(conn, finding_id=None):
    if finding_id:
        rows = conn.execute("SELECT * FROM mapping_requests WHERE finding_id=? ORDER BY id DESC", (finding_id,))
    else:
        rows = conn.execute("SELECT * FROM mapping_requests ORDER BY id DESC")
    return [dict(r) for r in rows]


def set_request_state(conn, rid, state, actor="analyst", note=""):
    if state not in _REQ_STATES:
        raise ValueError("invalid state: %s" % state)
    ts = _now()
    with conn:
        conn.execute("UPDATE mapping_requests SET state=?, updated=? WHERE id=?", (state, ts, rid))
        conn.execute("INSERT INTO mapping_request_history(request_id,state,actor,note,ts) VALUES(?,?,?,?,?)",
                     (rid, state, actor, note, ts))


def _table_exists(conn, name):
    return conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone() is not None


def migrate_legacy(conn):
    """One-time, idempotent: fold existing `triage` rows + `notes` into the event store as
    revision-unknown. disposition maps to the threat judgment EXCEPT 'noise', which migrates as a
    legacy tuning/value event and NOT as benign (KTD-A2). Returns count of triage rows migrated."""
    init(conn)
    if conn.execute("SELECT 1 FROM assessment_events WHERE kind='migrated' LIMIT 1").fetchone():
        return 0                                                        # already migrated
    n = 0
    if _table_exists(conn, "triage"):
        for row in conn.execute("SELECT * FROM triage").fetchall():
            keys = row.keys()
            fid = row["finding_id"]
            disp = (row["disposition"] or "")
            st = row["status"] or "new"
            ow = row["owner"] or ""
            det = (row["detector_id"] if "detector_id" in keys else None) or None
            when = row["updated"] or _now()
            threat = "" if disp == "noise" else disp                    # noise is NOT benign
            with conn:
                conn.execute("""INSERT INTO assessment_events
                    (tenant_id,finding_id,detector_id,revision,source_digest,kind,value,actor,reason,ts,idempotency_key)
                    VALUES('',?,?,NULL,NULL,'migrated',?, 'migration', 'legacy triage (revision-unknown)', ?, ?)""",
                    (fid, det, json.dumps({"status": st, "disposition": disp, "owner": ow}), when, "migrate:" + fid))
                if disp == "noise":
                    conn.execute("""INSERT INTO assessment_events
                        (tenant_id,finding_id,detector_id,revision,source_digest,kind,value,actor,reason,ts,idempotency_key)
                        VALUES('',?,?,NULL,NULL,'value','noise (retune)','migration','legacy noise verdict', ?, ?)""",
                        (fid, det, when, "migrate-noise:" + fid))
                conn.execute("""INSERT OR REPLACE INTO assessment_current
                    (tenant_id,finding_id,detector_id,category,status,disposition,assertion,value_judgment,owner,assessed_revision,assessed_digest,version,updated)
                    VALUES('',?,?,NULL,?,?,'','',?,NULL,NULL,1,?)""", (fid, det, st, threat, ow, when))
            n += 1
    if _table_exists(conn, "notes"):
        for row in conn.execute("SELECT finding_id,text,ts FROM notes ORDER BY id").fetchall():
            with conn:
                conn.execute("""INSERT INTO assessment_events
                    (tenant_id,finding_id,revision,source_digest,kind,value,actor,ts)
                    VALUES('',?,NULL,NULL,'note',?, 'migration', ?)""",
                    (row["finding_id"], row["text"], row["ts"] or _now()))
    return n
