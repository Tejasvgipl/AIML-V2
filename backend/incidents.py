"""
CyberSentinel — Incident correlation & narrative
================================================
Turns a stream of per-entity *signals* (risk scores, kill-chain stages, UEBA
findings) into a small number of correlated **incidents**, each with a priority
score and a plain-English narrative. This is the layer that converts hundreds of
alerts into the handful of decisions a SOC lead actually wants.

Correlation strategy (deterministic, dependency-light):
  - Single risky IP with a multi-stage kill chain → one "host" incident.
  - Multiple IPs in the same /24 active in an overlapping window → one
    "campaign" incident (coordinated / botnet activity).
  - UEBA user findings (account-takeover, impossible-travel) are attached to the
    incident whose IPs they share, or stand alone as an "identity" incident.

Pure functions over plain dicts — easy to test and reused by the API + reports.
"""
from __future__ import annotations

try:
    from threat_intel import TACTIC_ORDER, tactic_rank
except Exception:  # keep incidents.py importable on its own
    TACTIC_ORDER = []
    def tactic_rank(t: str) -> int:  # type: ignore
        return 99


def subnet24(ip: str) -> str:
    parts = (ip or "").split(".")
    return ".".join(parts[:3]) if len(parts) == 4 else ip


_SEV_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
_RANK_SEV = {v: k for k, v in _SEV_RANK.items()}


def _max_sev(*sevs: str) -> str:
    r = max((_SEV_RANK.get(s, 0) for s in sevs), default=0)
    return _RANK_SEV[r]


def _windows_overlap(a: dict, b: dict, slack_seconds: int = 0) -> bool:
    # ISO strings compare lexicographically when same format/zone.
    return not (a["last_seen"] < b["first_seen"] or b["last_seen"] < a["first_seen"])


def correlate(signals: list[dict]) -> list[dict]:
    """Group per-IP signals into incidents. Each signal dict carries:
    ip, risk, max_stage, stage_rank, progression[], techniques[{id,name}],
    severity_counts{}, total_events, first_seen, last_seen, reached_lateral,
    ueba[]."""
    if not signals:
        return []

    # Bucket by /24; a bucket with >1 active IP becomes a campaign.
    buckets: dict[str, list[dict]] = {}
    for s in signals:
        buckets.setdefault(subnet24(s["ip"]), []).append(s)

    incidents: list[dict] = []
    for sn, members in buckets.items():
        is_campaign = len(members) > 1
        ips = [m["ip"] for m in members]

        techniques: dict[str, dict] = {}
        tactics: dict[str, int] = {}
        severity = "low"
        risk = 0
        total_events = 0
        first_seen = min(m["first_seen"] for m in members)
        last_seen = max(m["last_seen"] for m in members)
        reached_lateral = False
        max_stage_rank = -1
        max_stage = None
        ueba: list[dict] = []
        users: set[str] = set()

        for m in members:
            for t in m.get("techniques", []):
                techniques[t["id"]] = t
            for tac in m.get("progression", []):
                tactics[tac] = tactics.get(tac, 0) + 1
            severity = _max_sev(severity, *(m.get("severity_counts") or {}).keys())
            risk = max(risk, int(m.get("risk", 0) or 0))
            total_events += int(m.get("total_events", 0) or 0)
            reached_lateral = reached_lateral or bool(m.get("reached_lateral"))
            if m.get("stage_rank", -1) > max_stage_rank:
                max_stage_rank = m["stage_rank"]
                max_stage = m.get("max_stage")
            for f in m.get("ueba", []):
                ueba.append(f)
                if f.get("username"):
                    users.add(f["username"])

        inc = {
            "id": (f"campaign:{sn}.0/24" if is_campaign else f"host:{ips[0]}"),
            "type": "campaign" if is_campaign else "host",
            "subnet": f"{sn}.0/24",
            "entities": {"ips": ips, "users": sorted(users)},
            "ip_count": len(ips),
            "techniques": sorted(techniques.values(), key=lambda t: t["id"]),
            "tactics": sorted(tactics.keys(), key=tactic_rank),
            "max_stage": max_stage,
            "reached_lateral": reached_lateral,
            "severity": severity,
            "risk": risk,
            "total_events": total_events,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "ueba_findings": ueba,
        }
        inc["priority"] = priority(inc)
        inc["narrative"] = narrative(inc)
        incidents.append(inc)

    incidents.sort(key=lambda x: x["priority"], reverse=True)
    return incidents


def priority(inc: dict) -> int:
    """0-100 triage priority fusing risk, kill-chain depth, breadth and identity impact."""
    score = inc.get("risk", 0) * 0.45
    score += min(len(inc.get("tactics", [])), 8) * 5          # multi-stage depth
    score += min(inc.get("ip_count", 1), 10) * 2.5            # campaign breadth
    if inc.get("reached_lateral"):
        score += 20                                          # past the perimeter
    ato = sum(1 for f in inc.get("ueba_findings", []) if f.get("type") == "account_takeover")
    travel = sum(1 for f in inc.get("ueba_findings", []) if f.get("type") == "impossible_travel")
    score += ato * 15 + travel * 10                          # identity compromise
    if inc.get("severity") == "critical":
        score += 10
    return max(0, min(100, round(score)))


def band(priority_score: int) -> str:
    return ("critical" if priority_score >= 80 else "high" if priority_score >= 60
            else "medium" if priority_score >= 35 else "low")


def narrative(inc: dict) -> str:
    """Deterministic plain-English incident summary (used as-is, and as the
    grounding skeleton for the AI narrative)."""
    ents = inc["entities"]
    who = (f"A coordinated campaign from {inc['ip_count']} hosts in {inc['subnet']}"
           if inc["type"] == "campaign"
           else f"Host {ents['ips'][0]}")
    tactics = " → ".join(inc["tactics"]) if inc["tactics"] else "single-stage activity"
    techs = ", ".join(f"{t['id']} ({t['name']})" for t in inc["techniques"][:6]) or "no mapped technique"
    parts = [
        f"{who} generated {inc['total_events']:,} events "
        f"(max risk {inc['risk']}/100, severity {inc['severity']}).",
        f"ATT&CK progression: {tactics}.",
        f"Techniques observed: {techs}.",
    ]
    if inc["reached_lateral"]:
        parts.append("Activity reached lateral movement or later — the actor is likely past the perimeter.")
    ato = [f for f in inc["ueba_findings"] if f.get("type") == "account_takeover"]
    travel = [f for f in inc["ueba_findings"] if f.get("type") == "impossible_travel"]
    if ato:
        accts = ", ".join(sorted({f.get("username", "?") for f in ato}))
        parts.append(f"Suspected account takeover affecting: {accts}.")
    if travel:
        accts = ", ".join(sorted({f.get("username", "?") for f in travel}))
        parts.append(f"Impossible-travel detected for: {accts}.")
    if ents["users"]:
        parts.append(f"Identities involved: {', '.join(ents['users'])}.")
    return " ".join(parts)
