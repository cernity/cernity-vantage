"""C+B: triage tiering + allowlist. dns_tunnel-shape leads must fall to low_signal (off Priority),
threats with confidence surface, and an allowlist rule (or disposition) tiers a finding to benign
without hiding it."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import triage_tier as tt
import allowlist as al

def f(**k): return k

def test_dns_tunnel_low_confidence_is_low_signal_not_priority():
    t,_ = tt.tier_of(f(category="dns_tunnel", severity=6, confidence=0.62))
    assert t == "low_signal", t
    assert "low_signal" not in tt.FILTER_TIERS["priority"]   # not surfaced as needing attention

def test_high_confidence_threat_is_priority():
    assert tt.tier_of(f(category="c2", severity=8, confidence=0.82))[0] == "threat"
    assert tt.tier_of(f(category="c2", severity=7, confidence=0.6))[0] == "lead"
    assert tt.tier_of(f(category="malware", severity=8, confidence=0.4))[0] == "low_signal"

def test_exfil_is_heuristic_noisy_not_threat_class():
    # exfil (icmp_exfil/dns_exploded shapes) -> low_signal unless strong confidence, like dns_tunnel
    assert tt.tier_of(f(category="exfil", severity=6, confidence=0.6))[0] == "low_signal"
    assert tt.tier_of(f(category="exfil", severity=6, confidence=0.8))[0] == "lead"

def test_observation_and_unclassified_tiers():
    assert tt.tier_of(f(category="observation", severity=6, confidence=0.9))[0] == "observation"
    assert tt.tier_of(f(category="unclassified", severity=6, confidence=0.9))[0] == "needs_classification"

def test_disposition_or_allowlist_makes_benign():
    assert tt.tier_of(f(category="c2", severity=9, confidence=0.99), allowlisted=True)[0] == "benign"
    assert tt.tier_of(f(category="c2", confidence=0.9, disposition="benign"))[0] == "benign"

def test_allowlist_match_dst_ip_and_asn():
    finding = {"category":"dns_tunnel","entities":[{"type":"ip","role":"src","value":"192.0.2.24"},
               {"type":"ip","role":"dst","value":"1.1.1.1"}], "geo":{"1.1.1.1":{"as_org":"Cloudflare, Inc."}}}
    assert al.match(finding, [{"field":"dst_ip","value":"1.1.1.1"}]) is not None
    assert al.match(finding, [{"field":"dst_asn","value":"cloudflare"}]) is not None   # substring, case-insensitive
    assert al.match(finding, [{"field":"dst_ip","value":"8.8.8.8"}]) is None
    assert al.match(finding, [{"field":"src_ip","value":"1.1.1.1"}]) is None            # 1.1.1.1 is dst, not src

def test_allowlist_crud_roundtrip():
    import sqlite3
    c = sqlite3.connect(":memory:"); c.row_factory = sqlite3.Row; al.init(c)
    rid = al.add_rule(c, "dst_ip", "1.1.1.1", "Cloudflare DoH", "carter")
    rules = al.list_rules(c); assert len(rules) == 1 and rules[0]["value"] == "1.1.1.1"
    al.delete_rule(c, rid); assert al.list_rules(c) == []

if __name__ == "__main__":
    for _n,_f in sorted(globals().items()):
        if _n.startswith("test_") and callable(_f): _f(); print("ok  "+_n)
    print("\nall triage_tier + allowlist tests passed")
