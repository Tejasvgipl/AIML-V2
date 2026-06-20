"""
CyberSentinel — UEBA (User & Entity Behaviour Analytics)
========================================================
Pure, dependency-light detection logic over event lists pulled from ClickHouse.
Treats **user** and **host** as first-class entities (not just src_ip):

  - account_takeover : a successful login that follows a brute-force burst from
                       the same source, or arrives from a never-before-seen
                       country/geo for that account.
  - impossible_travel: the same entity seen in two places too far apart for the
                       time elapsed (geo-velocity faster than air travel).
  - peer_outlier     : an entity whose behaviour deviates sharply from the
                       population (z-score across aggregate features).

All functions are side-effect free so they're trivially testable and reused by
the API layer.
"""
from __future__ import annotations

import math
from datetime import datetime

# Tunables (overridable by callers / env via the API layer)
ATO_FAIL_THRESHOLD = 5          # failures from one IP before a success = suspicious
ATO_WINDOW_SECONDS = 3600       # look-back window for preceding failures
TRAVEL_MAX_KMH = 900.0          # faster than this between two geos = impossible
TRAVEL_MIN_KM = 400.0           # ignore short hops (geo noise)
PEER_Z_THRESHOLD = 2.5          # max per-feature z-score to flag a peer outlier

_FAILURE_TYPES = {"brute_force", "ssh_bruteforce", "vpn_bruteforce", "rdp_relay"}
_SUCCESS_TYPES = {"login_success"}


def _parse_ts(value) -> float:
    """ISO string / datetime → epoch seconds (0.0 on failure)."""
    if isinstance(value, datetime):
        return value.timestamp()
    if not value:
        return 0.0
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except Exception:
        return 0.0


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance between two lat/lon points in kilometres."""
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlmb = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dlmb / 2) ** 2
    return r * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


def _has_geo(ev: dict) -> bool:
    try:
        return abs(float(ev.get("geo_lat", 0))) > 0.01 or abs(float(ev.get("geo_lon", 0))) > 0.01
    except (ValueError, TypeError):
        return False


def detect_account_takeover(events: list[dict],
                            historical_countries: set[str] | None = None) -> list[dict]:
    """Given an entity's events (any order), flag successful logins that follow a
    failure burst from the same IP, or that originate from a new country.
    Returns a list of finding dicts."""
    evs = sorted(events, key=lambda e: _parse_ts(e.get("@timestamp")))
    hist = set(historical_countries or set())
    # Seed history from the entity's own earlier successes so 'new country' is
    # relative to where the account normally logs in from.
    fails_by_ip: dict[str, list[float]] = {}
    findings: list[dict] = []

    for ev in evs:
        tt = ev.get("threat_type", "")
        ip = ev.get("src_ip", "")
        ts = _parse_ts(ev.get("@timestamp"))
        country = (ev.get("country") or "").strip()

        if tt in _FAILURE_TYPES and ip:
            fails_by_ip.setdefault(ip, []).append(ts)

        elif tt in _SUCCESS_TYPES:
            recent_fails = [t for t in fails_by_ip.get(ip, []) if 0 <= ts - t <= ATO_WINDOW_SECONDS]
            new_country = bool(country and hist and country not in hist)
            reasons = []
            if len(recent_fails) >= ATO_FAIL_THRESHOLD:
                reasons.append(f"{len(recent_fails)} failed logins from {ip} in the prior "
                               f"{ATO_WINDOW_SECONDS // 60}m before this success")
            if new_country:
                reasons.append(f"login from new country '{country}' (usual: {', '.join(sorted(hist)) or 'unknown'})")
            if reasons:
                sev = "critical" if (len(recent_fails) >= ATO_FAIL_THRESHOLD and new_country) else "high"
                findings.append({
                    "type": "account_takeover",
                    "severity": sev,
                    "src_ip": ip,
                    "country": country,
                    "username": ev.get("username", ""),
                    "ts": ev.get("@timestamp"),
                    "message": "Suspected account takeover: " + "; ".join(reasons),
                    "evidence": {"preceding_failures": len(recent_fails),
                                 "new_country": new_country, "usual_countries": sorted(hist)},
                })
            # The account now legitimately knows this country going forward.
            if country:
                hist.add(country)

    return findings


def detect_impossible_travel(events: list[dict]) -> list[dict]:
    """Flag consecutive events for one entity whose geo separation requires a
    speed above TRAVEL_MAX_KMH (faster than air travel)."""
    geo_evs = sorted((e for e in events if _has_geo(e)),
                     key=lambda e: _parse_ts(e.get("@timestamp")))
    findings: list[dict] = []
    prev = None
    for ev in geo_evs:
        if prev is not None:
            t1, t2 = _parse_ts(prev.get("@timestamp")), _parse_ts(ev.get("@timestamp"))
            dt_h = (t2 - t1) / 3600.0
            if dt_h > 0:
                dist = haversine_km(float(prev["geo_lat"]), float(prev["geo_lon"]),
                                    float(ev["geo_lat"]), float(ev["geo_lon"]))
                speed = dist / dt_h if dt_h > 0 else float("inf")
                if dist >= TRAVEL_MIN_KM and speed > TRAVEL_MAX_KMH:
                    findings.append({
                        "type": "impossible_travel",
                        "severity": "high",
                        "ts": ev.get("@timestamp"),
                        "username": ev.get("username", ""),
                        "from": {"country": prev.get("country", ""), "ip": prev.get("src_ip", ""),
                                 "lat": prev["geo_lat"], "lon": prev["geo_lon"], "ts": prev.get("@timestamp")},
                        "to": {"country": ev.get("country", ""), "ip": ev.get("src_ip", ""),
                               "lat": ev["geo_lat"], "lon": ev["geo_lon"], "ts": ev.get("@timestamp")},
                        "message": (f"Impossible travel: {dist:,.0f} km in {dt_h:.2f} h "
                                    f"(~{speed:,.0f} km/h) between {prev.get('country','?')} and "
                                    f"{ev.get('country','?')}"),
                        "evidence": {"distance_km": round(dist, 1), "hours": round(dt_h, 3),
                                     "speed_kmh": round(speed, 1)},
                    })
        prev = ev
    return findings


# ── peer-group anomaly ─────────────────────────────────────────────────────────

PEER_FEATURES = ["events", "crit", "dsts", "ports", "countries", "srcs"]


def peer_outliers(rows: list[dict], z_threshold: float = PEER_Z_THRESHOLD) -> list[dict]:
    """Given per-entity aggregate rows, z-score each feature against the population
    and flag entities deviating sharply from their peers. `rows` items must carry
    an 'entity' key plus the PEER_FEATURES numeric keys."""
    if len(rows) < 5:
        return []  # population too small to define "normal"

    # population mean/std per feature
    stats = {}
    for f in PEER_FEATURES:
        vals = [float(r.get(f, 0) or 0) for r in rows]
        mean = sum(vals) / len(vals)
        var = sum((v - mean) ** 2 for v in vals) / len(vals)
        stats[f] = (mean, math.sqrt(var))

    out = []
    for r in rows:
        zmax = 0.0
        drivers = []
        for f in PEER_FEATURES:
            mean, std = stats[f]
            if std <= 1e-9:
                continue
            z = (float(r.get(f, 0) or 0) - mean) / std
            if z > zmax:
                zmax = z
            if z >= z_threshold:
                drivers.append({"feature": f, "value": r.get(f, 0),
                                "z": round(z, 2), "peer_mean": round(mean, 2)})
        if drivers:
            out.append({
                "entity": r.get("entity", ""),
                "type": "peer_outlier",
                "severity": "high" if zmax >= z_threshold * 1.6 else "medium",
                "max_z": round(zmax, 2),
                "drivers": sorted(drivers, key=lambda d: d["z"], reverse=True),
                "message": (f"{r.get('entity','entity')} deviates from its peer group on "
                            + ", ".join(f"{d['feature']} (z={d['z']})" for d in drivers[:3])),
            })
    out.sort(key=lambda x: x["max_z"], reverse=True)
    return out
