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

# Representative lat/lon per country (GeoIP gives country-level location far more
# often than exact coordinates). Used as a fallback so impossible-travel works on
# the `country` field even when geo_lat/geo_lon are absent. Names match the
# `country` values produced by the watcher (data.srccountry / GeoLocation).
COUNTRY_CENTROIDS = {
    "Brazil": (-14.2, -51.9), "Nigeria": (9.1, 8.7), "Russia": (61.5, 105.3),
    "China": (35.9, 104.2), "Iran": (32.4, 53.7), "India": (22.4, 78.7),
    "United States": (39.8, -98.6), "United States of America": (39.8, -98.6),
    "USA": (39.8, -98.6), "Germany": (51.2, 10.4), "France": (46.2, 2.2),
    "United Kingdom": (55.4, -3.4), "UK": (55.4, -3.4), "Netherlands": (52.1, 5.3),
    "Ukraine": (48.4, 31.2), "Romania": (45.9, 24.9), "Turkey": (39.0, 35.2),
    "Vietnam": (14.1, 108.3), "Indonesia": (-0.8, 113.9), "Pakistan": (30.4, 69.3),
    "North Korea": (40.3, 127.5), "South Korea": (35.9, 127.8), "Japan": (36.2, 138.3),
    "Canada": (56.1, -106.3), "Mexico": (23.6, -102.6), "Spain": (40.5, -3.7),
    "Italy": (41.9, 12.6), "Poland": (51.9, 19.1), "Singapore": (1.35, 103.8),
    "Hong Kong": (22.3, 114.2), "Taiwan": (23.7, 121.0), "Thailand": (15.9, 100.99),
    "South Africa": (-30.6, 22.9), "Egypt": (26.8, 30.8), "Saudi Arabia": (23.9, 45.1),
    "Bangladesh": (23.7, 90.4), "Australia": (-25.3, 133.8), "Argentina": (-38.4, -63.6),
    "Colombia": (4.6, -74.3), "Bulgaria": (42.7, 25.5), "Czech Republic": (49.8, 15.5),
    "Sweden": (60.1, 18.6), "Switzerland": (46.8, 8.2), "Israel": (31.0, 34.9),
    "Kenya": (-0.02, 37.9), "Belarus": (53.7, 27.95), "Kazakhstan": (48.0, 66.9),
}


def _country_geo(country: str):
    """Representative (lat, lon) for a country name, or None if unknown."""
    if not country:
        return None
    return COUNTRY_CENTROIDS.get(country.strip())


def _geo_of(ev: dict):
    """Best available (lat, lon) for an event: exact coords if present, else the
    country centroid. Returns None when neither is available."""
    try:
        lat, lon = float(ev.get("geo_lat", 0) or 0), float(ev.get("geo_lon", 0) or 0)
        if abs(lat) > 0.01 or abs(lon) > 0.01:
            return (lat, lon)
    except (ValueError, TypeError):
        pass
    return _country_geo((ev.get("country") or "").strip())


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
    """Flag the same entity appearing in two locations too far apart for the time
    elapsed (geo-velocity faster than air travel). Works on exact coordinates when
    present, otherwise on country centroids (country is far more often populated).
    Same-instant appearances in different countries are treated as impossible
    (infinite velocity) -- the strongest signal of a distributed/shared account.

    To keep output readable we collapse runs of the same country and emit at most
    one finding per distinct ordered country pair (worst case kept)."""
    # Attach resolved geo + country; drop events we cannot place at all.
    placed = []
    for e in events:
        geo = _geo_of(e)
        if geo is None:
            continue
        placed.append((e, geo, (e.get("country") or "").strip()))
    placed.sort(key=lambda x: _parse_ts(x[0].get("@timestamp")))

    SIMUL_WINDOW_S = 5.0   # appearances within 5s are "simultaneous"
    findings: list[dict] = []

    # --- 1) Simultaneous multi-country: cluster events into short time windows;
    #         a cluster spanning >=2 distinct far-apart countries is impossible. ---
    handled = [False] * len(placed)
    i = 0
    while i < len(placed):
        t0 = _parse_ts(placed[i][0].get("@timestamp"))
        j = i
        members = []
        while j < len(placed) and _parse_ts(placed[j][0].get("@timestamp")) - t0 <= SIMUL_WINDOW_S:
            members.append(placed[j]); j += 1
        by_country = {}
        for ev, geo, country in members:
            by_country.setdefault(country, (ev, geo))
        if len(by_country) >= 2:
            cs = list(by_country.items())
            max_d, pair = 0.0, None
            for a in range(len(cs)):
                for b in range(a + 1, len(cs)):
                    d = haversine_km(cs[a][1][1][0], cs[a][1][1][1],
                                     cs[b][1][1][0], cs[b][1][1][1])
                    if d > max_d:
                        max_d, pair = d, (cs[a], cs[b])
            if max_d >= TRAVEL_MIN_KM and pair:
                for k in range(i, j):
                    handled[k] = True
                clist = sorted(by_country.keys())
                (fc, (fev, fgeo)), (tc, (tev, tgeo)) = pair
                findings.append({
                    "type": "impossible_travel",
                    "severity": "critical",
                    "ts": fev.get("@timestamp"),
                    "username": fev.get("username", ""),
                    "from": {"country": fc, "ip": fev.get("src_ip", ""),
                             "lat": fgeo[0], "lon": fgeo[1], "ts": fev.get("@timestamp")},
                    "to": {"country": tc, "ip": tev.get("src_ip", ""),
                           "lat": tgeo[0], "lon": tgeo[1], "ts": tev.get("@timestamp")},
                    "message": (f"Impossible travel: account active from {len(by_country)} "
                                f"countries within {SIMUL_WINDOW_S:.0f}s "
                                f"({', '.join(clist)}); widest separation {max_d:,.0f} km "
                                f"({fc}-{tc}) -- single identity cannot be in all at once"),
                    "evidence": {"countries": clist, "distance_km": round(max_d, 1),
                                 "window_s": SIMUL_WINDOW_S, "same_instant": True},
                })
        i = j

    # --- 2) Sequential impossible travel: among remaining events, collapse
    #         consecutive same-country runs and flag hops faster than any flight. ---
    seq = [placed[k] for k in range(len(placed)) if not handled[k]]
    segments = []
    for ev, geo, country in seq:
        if segments and segments[-1][2] == country:
            continue
        segments.append((ev, geo, country))
    best: dict[frozenset, dict] = {}
    for k in range(1, len(segments)):
        pe, pgeo, pc = segments[k - 1]
        ce, cgeo, cc = segments[k]
        if pc == cc:
            continue
        t1, t2 = _parse_ts(pe.get("@timestamp")), _parse_ts(ce.get("@timestamp"))
        dt_h = max(0.0, (t2 - t1) / 3600.0)
        dist = haversine_km(pgeo[0], pgeo[1], cgeo[0], cgeo[1])
        if dist < TRAVEL_MIN_KM or dt_h <= (1.0 / 3600.0):
            continue
        speed = dist / dt_h
        if speed <= TRAVEL_MAX_KMH:
            continue
        finding = {
            "type": "impossible_travel", "severity": "high",
            "ts": ce.get("@timestamp"), "username": ce.get("username", ""),
            "from": {"country": pc, "ip": pe.get("src_ip", ""),
                     "lat": pgeo[0], "lon": pgeo[1], "ts": pe.get("@timestamp")},
            "to": {"country": cc, "ip": ce.get("src_ip", ""),
                   "lat": cgeo[0], "lon": cgeo[1], "ts": ce.get("@timestamp")},
            "message": (f"Impossible travel: {dist:,.0f} km in {dt_h:.2f} h "
                        f"(~{speed:,.0f} km/h) between {pc or '?'} and {cc or '?'} "
                        f"-- faster than any flight"),
            "evidence": {"distance_km": round(dist, 1), "hours": round(dt_h, 4),
                         "speed_kmh": round(speed, 1), "same_instant": False},
        }
        key = frozenset((pc, cc))
        if key not in best or dist > best[key]["evidence"]["distance_km"]:
            best[key] = finding
    findings.extend(best.values())

    findings.sort(key=lambda f: (f["severity"] != "critical",
                                 -f["evidence"]["distance_km"]))
    return findings[:25]


# ── UEBA v2: per-user risk scoring (market-grade pattern) ──────────────────────
# Each user is compared to THEIR OWN 30-day baseline (the Exabeam/Securonix
# model): what changed in the last 24h that this identity has never done
# before? Anomalies are additive scored drivers with plain-English evidence,
# capped at 100. Population context (peer z-scores) adds on top.

RISK_LEVELS = ((70, "critical"), (45, "high"), (25, "medium"), (0, "low"))


def _ist_hour(h_utc: int) -> str:
    """UTC hour -> IST wall-clock label (banks read IST)."""
    m = (h_utc * 60 + 330) % 1440
    return f"{m // 60:02d}:{m % 60:02d}"


def _hist_dict(pair) -> dict:
    """sumMap([keys],[vals]) arrives as ([k...],[v...]) or {k:v}; normalise to
    {key: int(count)}. Keys keep their native type (int hours, date days)."""
    if isinstance(pair, dict):
        return {k: int(v) for k, v in pair.items()}
    try:
        keys, vals = pair
        return {k: int(v) for k, v in zip(keys, vals)}
    except Exception:
        return {}


def score_user_profiles(rows: list[dict],
                        travel_by_user: dict[str, list] | None = None,
                        baseline_days: int = 30) -> list[dict]:
    """Turn get_ueba_user_profiles() rows into ranked risk entries with
    plain-English drivers. Pure function: trivially testable."""
    travel_by_user = travel_by_user or {}

    # population stats for peer context (on 24h volume + criticals)
    peer_rows = [{"entity": r["username"], "events": r.get("ev_24", 0),
                  "crit": r.get("crit_24", 0),
                  "dsts": len(r.get("ports_24") or []),
                  "ports": len(r.get("ports_24") or []),
                  "countries": len(r.get("countries_24") or []),
                  "srcs": len(r.get("srcs_24") or [])} for r in rows]
    peer_hits = {p["entity"]: p for p in peer_outliers(peer_rows)}

    out = []
    for r in rows:
        user = r["username"]
        ev_base, ev_24 = int(r.get("ev_base", 0)), int(r.get("ev_24", 0))
        mature = ev_base >= 50          # enough history to trust the baseline
        drivers, score = [], 0.0

        def add(pts: float, kind: str, text: str):
            nonlocal score
            score += pts
            drivers.append({"kind": kind, "points": round(pts), "text": text})

        # 1 — new host for this identity (classic lateral-movement tell)
        hb = set(r.get("hosts_base") or [])
        if mature and hb:
            new_hosts = [h for h in (r.get("hosts_24") or []) if h not in hb]
            for h in new_hosts[:2]:
                add(22, "new_host",
                    f"accessed {h} - a machine this account never touched in its "
                    f"{baseline_days}-day baseline (usual: {', '.join(sorted(hb)[:3])})")

        # 2 — new country
        cb = set(r.get("countries_base") or [])
        if mature and cb:
            for c in [c for c in (r.get("countries_24") or []) if c not in cb][:2]:
                add(28, "new_country",
                    f"activity from {c} - never seen for this account "
                    f"(usual: {', '.join(sorted(cb)[:3])})")

        # 3 — off-hours: active in hours where the baseline is essentially zero
        hb_hist = _hist_dict(r.get("hours_base"))
        h24_hist = _hist_dict(r.get("hours_24"))
        if mature and hb_hist:
            total_b = sum(hb_hist.values()) or 1
            usual = {h for h, n in hb_hist.items() if n / total_b >= 0.02}
            odd = [(h, n) for h, n in h24_hist.items()
                   if h not in usual and n >= 3]
            if odd and usual:
                h, n = max(odd, key=lambda x: x[1])
                lo, hi = min(usual), max(usual)
                add(18, "off_hours",
                    f"{n} events at {_ist_hour(h)} IST - outside this account's usual "
                    f"{_ist_hour(lo)}-{_ist_hour(hi)} IST working window")

        # 4 — volume spike vs own daily average
        daily_avg = ev_base / max(1, baseline_days - 1)
        if mature and daily_avg >= 2 and ev_24 >= 30 and ev_24 / daily_avg >= 5:
            add(15, "volume_spike",
                f"{ev_24} events in 24h - {ev_24 / daily_avg:.0f}x this account's "
                f"normal {daily_avg:.0f}/day")

        # 5 — brute-force pressure / takeover pattern
        fails, succ = int(r.get("fails_24", 0)), int(r.get("success_24", 0))
        if fails >= 20 and succ >= 1:
            add(30, "ato_pattern",
                f"{fails} failed logins followed by {succ} successful login(s) "
                f"in 24h - the brute-force-then-success takeover pattern")
        elif fails >= 20:
            add(15, "fail_burst", f"{fails} failed logins against this account in 24h")

        # 6 — high/critical detections
        crit = int(r.get("crit_24", 0))
        if crit:
            add(min(20, crit * 4), "critical_hits",
                f"{crit} high/critical detection(s) in the last 24h")

        # 7 — impossible travel (from the geo detector, merged by user)
        for f in (travel_by_user.get(user) or [])[:1]:
            add(35, "impossible_travel", f.get("message", "impossible travel detected"))

        # 8 — peer outlier context
        pz = peer_hits.get(user)
        if pz:
            add(12, "peer_outlier",
                f"deviates from the user population (max z={pz['max_z']}): "
                + ", ".join(d['feature'] for d in pz['drivers'][:3]))

        if not drivers:
            continue
        score = min(100.0, score)
        level = next(lvl for thr, lvl in RISK_LEVELS if score >= thr)
        days7 = _hist_dict(r.get("days_7"))
        out.append({
            "user": user,
            "score": round(score),
            "level": level,
            "drivers": sorted(drivers, key=lambda d: -d["points"]),
            "ev_24": ev_24, "ev_base": ev_base,
            "baseline_mature": mature,
            "hosts": sorted(set((r.get("hosts_base") or []) + (r.get("hosts_24") or [])))[:6],
            "countries": sorted(set((r.get("countries_base") or []) + (r.get("countries_24") or [])))[:6],
            "sparkline": [int(v) for _, v in sorted(days7.items())][-7:],
            "last_seen": r.get("last_ts", ""),
        })
    out.sort(key=lambda x: -x["score"])
    return out


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
