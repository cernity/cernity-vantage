"""U10 (B): evidence-pivot WINDOW boundary. U5 caps [from,to) to [from, from+MAX_WINDOW) and its
upper bound is EXCLUSIVE (`normalized_time < until`). The drawer's window must keep the finding
instant t INSIDE that capped half-open window — an earlier [t-24h, t+1s) was capped to [t-24h, t),
silently dropping the observation at exactly t. This runs the REAL static/overview.js window builder
in node and applies U5's ACTUAL cap (MAX_WINDOW loaded from the evidence-service contract), so a
regression to the old lookback fails deterministically. Run: .venv/bin/python -m pytest tests/test_evidence_window.py"""
import importlib.util
import os
import shutil
import subprocess
from datetime import datetime, timezone

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_OVERVIEW_JS = os.path.join(_ROOT, "static", "overview.js")


def _u5_max_window_ms():
    """MAX_WINDOW from the U5 contract itself, not a hand-copied constant (so this test tracks the
    real cap). The contract file has a hyphenated name -> load it by path."""
    path = os.path.join(_ROOT, "docs", "backend-contracts", "evidence-service-query.py")
    if not os.path.exists(path):
        pytest.skip(
            "evidence-service query contract not vendored in this repo "
            "(private cross-repo backend-contract check; drop the file into "
            "docs/backend-contracts/ to enable it)"
        )
    spec = importlib.util.spec_from_file_location("u5_query_contract", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.MAX_WINDOW.total_seconds() * 1000.0


def _run_evidence_query(finding_ts_iso):
    """Load the real overview.js in node (only `window` is touched at import — `show` is guarded by a
    typeof check, so no DOM stubs are needed) and call its private evidenceQuery via the test seam."""
    node = shutil.which("node")
    if not node:                                    # gate stays green where node is absent; ran wherever it exists
        pytest.skip("node not available to exercise the browser window builder")
    script = (
        "const fs=require('fs'); var window={};"
        "eval(fs.readFileSync(%r,'utf8'));"
        "window._ovFindings=[{finding_id:'f1',entities:[{value:'1.2.3.4'}],ts:%r}];"
        "process.stdout.write(window._evidenceQuery('f1')||'');" % (_OVERVIEW_JS, finding_ts_iso))
    out = subprocess.run([node, "-e", script], capture_output=True, text=True, timeout=30)
    assert out.returncode == 0, out.stderr
    return out.stdout


def _ms(iso):
    return datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp() * 1000.0


def test_window_keeps_finding_instant_inside_u5_cap():
    from urllib.parse import parse_qs
    t_iso = "2026-09-28T12:00:00.000Z"
    t = _ms(t_iso)
    qs = parse_qs(_run_evidence_query(t_iso))
    frm, to = _ms(qs["frm"][0]), _ms(qs["to"][0])
    max_win = _u5_max_window_ms()
    capped_upper = min(to, frm + max_win)           # U5's actual cap
    assert to - frm <= max_win, "requested window exceeds U5's cap and will be truncated"
    # half-open, upper EXCLUSIVE: the finding instant must satisfy frm <= t < capped_upper
    assert frm <= t < capped_upper, "finding instant t is excluded by U5's window cap"
