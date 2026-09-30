"""Benign / allowlist rules (plan 012 · option B). Analyst-owned, persistent rules that mark a
KNOWN-benign pattern (e.g. DoH to 1.1.1.1, or a whole ASN) so matching findings are tiered to
'benign' — retained, indexed and fully searchable, just not surfaced as needing attention. This is
a triage disposition, never a delete or a bus-level drop; the detector and the SIEM are unchanged.

Rules match on one field: dst_ip | src_ip | any_ip | dst_asn (as_org substring) | category.
`match()` is pure (takes rules + a finding) so it unit-tests without a DB.
"""
FIELDS = ("dst_ip", "src_ip", "any_ip", "dst_asn", "category")


def init(c):
    c.execute("""CREATE TABLE IF NOT EXISTS allowlist(
        id INTEGER PRIMARY KEY AUTOINCREMENT, field TEXT, value TEXT, reason TEXT,
        created_by TEXT, ts TEXT)""")
    return c


def list_rules(c):
    return [dict(r) for r in c.execute(
        "SELECT id,field,value,reason,created_by,ts FROM allowlist ORDER BY id DESC").fetchall()]


def add_rule(c, field, value, reason="", created_by="analyst", emit=None):
    if field not in FIELDS:
        raise ValueError("unknown allowlist field: %s" % field)
    if not value:
        raise ValueError("allowlist rule needs a value")
    import datetime
    cur = c.execute("INSERT INTO allowlist(field,value,reason,created_by,ts) VALUES (?,?,?,?,?)",
                    (field, str(value), reason, created_by,
                     datetime.datetime.now(datetime.timezone.utc).isoformat()))
    c.commit()
    # 012 U10 (C): emit hook — fires only after the rule is persisted. Best-effort: an emit failure
    # must never undo an allowlist add, so it's swallowed (the caller's emitter logs its own errors).
    if emit is not None:
        try:
            emit({"id": cur.lastrowid, "field": field, "value": str(value),
                  "reason": reason, "created_by": created_by})
        except Exception:
            pass
    return cur.lastrowid


def delete_rule(c, rule_id):
    c.execute("DELETE FROM allowlist WHERE id=?", (rule_id,))
    c.commit()


def _ips(finding, role=None):
    out = []
    for e in (finding.get("entities") or []):
        if isinstance(e, dict) and e.get("type") == "ip" and (role is None or e.get("role") == role):
            out.append(e.get("value"))
    return [x for x in out if x]


def match(finding, rules):
    """Return the first matching rule dict, or None. Pure — no DB."""
    dst = set(_ips(finding, "dst")); src = set(_ips(finding, "src")); allip = set(_ips(finding))
    orgs = []
    for ip, g in (finding.get("geo") or {}).items():
        if isinstance(g, dict) and g.get("as_org"):
            orgs.append(g["as_org"].lower())
    cat = (finding.get("category") or "").lower()
    for r in rules:
        f, v = r.get("field"), str(r.get("value", ""))
        if f == "dst_ip" and v in dst:
            return r
        if f == "src_ip" and v in src:
            return r
        if f == "any_ip" and v in allip:
            return r
        if f == "dst_asn" and any(v.lower() in o for o in orgs):
            return r
        if f == "category" and v.lower() == cat:
            return r
    return None
