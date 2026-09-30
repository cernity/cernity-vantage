"""A-U2: legacy triage/notes migration into the event store (plan 010 KTD-A2) + restore."""
import os
import shutil
import sqlite3
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import assessment as A  # noqa: E402


def _legacy_db(path):
    c = sqlite3.connect(path)
    c.row_factory = sqlite3.Row
    c.execute("CREATE TABLE triage(finding_id TEXT PRIMARY KEY, status TEXT, disposition TEXT, owner TEXT, updated TEXT, detector_id TEXT)")
    c.execute("CREATE TABLE notes(id INTEGER PRIMARY KEY AUTOINCREMENT, finding_id TEXT, text TEXT, ts TEXT)")
    c.executemany("INSERT INTO triage(finding_id,status,disposition,owner,updated) VALUES(?,?,?,?,?)", [
        ("f-conf", "closed", "confirmed", "ana", "2026-09-24T10:00:00"),
        ("f-noise", "closed", "noise", "ana", "2026-09-24T11:00:00"),
        ("f-open", "investigating", "", "", "2026-09-24T12:00:00"),
    ])
    c.executemany("INSERT INTO notes(finding_id,text,ts) VALUES(?,?,?)", [
        ("f-conf", "looks like a real beacon", "2026-09-24T10:05:00"),
    ])
    c.commit()
    return c


def test_migration_folds_legacy_and_maps_verdicts():
    d = tempfile.mkdtemp()
    c = _legacy_db(os.path.join(d, "soc.db"))
    n = A.migrate_legacy(c)
    assert n == 3, n
    # confirmed carries to threat; open stays; noise is NOT benign
    assert A.current(c, "", "f-conf")["disposition"] == "confirmed"
    assert A.current(c, "", "f-noise")["disposition"] == "", "noise must not migrate as a threat verdict"
    assert A.current(c, "", "f-open")["status"] == "investigating"
    # noise recorded as a value event, not lost
    kinds = [h["kind"] for h in A.history(c, "", "f-noise")]
    assert "value" in kinds and "migrated" in kinds
    # legacy rows are revision-unknown
    assert A.current(c, "", "f-conf")["assessed_revision"] is None
    # note migrated
    assert any(nt["text"].startswith("looks like") for nt in A.notes(c, "", "f-conf"))


def test_migration_is_idempotent():
    d = tempfile.mkdtemp()
    c = _legacy_db(os.path.join(d, "soc.db"))
    A.migrate_legacy(c)
    before = c.execute("SELECT COUNT(*) FROM assessment_events").fetchone()[0]
    assert A.migrate_legacy(c) == 0                      # second run is a no-op
    after = c.execute("SELECT COUNT(*) FROM assessment_events").fetchone()[0]
    assert before == after, "re-migration must not duplicate events"


def test_backup_restore_recovers_history():
    d = tempfile.mkdtemp()
    src = os.path.join(d, "soc.db")
    c = _legacy_db(src)
    A.migrate_legacy(c)
    c.close()
    backup = os.path.join(d, "soc.db.bak")
    shutil.copy(src, backup)                              # simulate a backup
    restored = sqlite3.connect(backup)
    restored.row_factory = sqlite3.Row
    assert A.current(restored, "", "f-conf")["disposition"] == "confirmed"
    assert any(nt["text"].startswith("looks like") for nt in A.notes(restored, "", "f-conf"))


if __name__ == "__main__":
    for _n, _f in sorted(globals().items()):
        if _n.startswith("test_") and callable(_f):
            _f(); print("ok", _n)
    print("PASS test_migration")
