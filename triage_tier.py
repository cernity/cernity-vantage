"""Triage tiering for the investigation queue (plan 012 V3 · option C+B). A tier is a TRIAGE AID,
never a verdict: it ranks a finding by (category class × confidence × analyst disposition) so
high-signal threats surface for immediate attention while heuristic/low-confidence leads (e.g. a
dns_tunnel-shaped flow to a DoH resolver) drop to a low-signal tier — visible and searchable, not
front-and-center. Severity stays the detector's nominal category weight; confidence + disposition
are what the analyst plane ranks on (severity ≠ confidence ≠ verdict).

Nothing is hidden or dropped here — every finding still gets a tier and is returnable by 'all'.
"""

TIERS = ("threat", "lead", "low_signal", "needs_classification", "observation", "benign")

# threat-class categories: a match here with strong confidence is worth immediate attention
_THREAT = {"c2", "malware", "credential_access", "recon", "lateral_movement"}
# heuristic / structurally-noisy categories: fire on shape (entropy/volume/duration), high false-positive.
# `exfil` lives here (not _THREAT): its detectors (icmp_exfil, dns_exploded, dns_tunnel) are structural
# heuristics that fire benignly a lot, so it is low_signal unless confidence is strong.
_NOISY = {"exfil", "dns_tunnel", "dns_exploded", "strobe", "icmp_exfil", "beacon", "long_connection", "long_connection_cumulative"}
# categories that are explicitly the low-priority tiers by design
_OBSERVATION = {"observation", "hygiene", "policy"}

CONF_THREAT = 0.75      # threat-class at/above this confidence -> immediate attention
CONF_LEAD = 0.50        # threat-class between LEAD and THREAT -> a lead


def tier_of(finding, allowlisted=False):
    """Return (tier, reason). `allowlisted` is decided by the caller (allowlist rule match, option B)."""
    if allowlisted:
        return "benign", "allowlisted by analyst decision (retained, searchable)"
    cat = (finding.get("category") or "").lower()
    conf = finding.get("confidence")
    conf = float(conf) if isinstance(conf, (int, float)) else 0.0
    sev = finding.get("severity")
    sev = float(sev) if isinstance(sev, (int, float)) else 0.0
    disp = (finding.get("disposition") or "").lower()

    if disp in ("benign", "false_positive", "allowlisted"):
        return "benign", "analyst disposition: " + disp
    if cat == "unclassified":
        return "needs_classification", "unclassified — needs an analyst call"
    if cat in _OBSERVATION:
        return "observation", cat + " tier"
    if cat in _THREAT:
        if conf >= CONF_THREAT:
            return "threat", "high-confidence %s (conf %.2f)" % (cat, conf)
        if conf >= CONF_LEAD:
            return "lead", "%s, moderate confidence (%.2f)" % (cat, conf)
        return "low_signal", "%s but low confidence (%.2f)" % (cat, conf)
    if cat in _NOISY:
        # structural heuristic — a lead only when confidence is strong, else low-signal
        if conf >= CONF_THREAT:
            return "lead", "%s, strong signal (%.2f) — still a heuristic lead, not a verdict" % (cat, conf)
        return "low_signal", "%s is a structural heuristic (conf %.2f) — often benign (DoH/CDN)" % (cat, conf)
    if sev >= 6 and conf >= 0.6:
        return "lead", "sev %g, conf %.2f" % (sev, conf)
    return "low_signal", "sev %g, conf %.2f" % (sev, conf)


# which tiers each queue filter shows
FILTER_TIERS = {
    "priority": ("threat", "lead"),
    "low_signal": ("low_signal",),
    "needs": ("needs_classification",),
    "allowlisted": ("benign",),
    "observations": ("observation",),
    "all": TIERS,
}
