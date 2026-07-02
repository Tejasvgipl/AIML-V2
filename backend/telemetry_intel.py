"""
Telemetry Intelligence - value from the 95% of logs that never fire an alert.

Five analytics, all pure ClickHouse aggregation over CHEAP columns (the one
exception, policy analytics, prefilters to firewall rows on cheap columns
before touching `raw`, and every endpoint that calls this module is TTL-cached
in main.py so ClickHouse sees at most one scan per module per cache window):

  1. Silence Sentinel  - agents that stopped reporting (dead agent, or an
     attacker killing telemetry: MITRE T1562 defense evasion).
  2. First-Seen Ledger - org-wide novelty: new agents, new user<->agent pairs,
     new process binaries (+ org prevalence), new countries, new dst ports.
  3. Beaconing         - src->dst:port flows with suspiciously REGULAR timing
     (C2 heartbeats hide inside allowed traffic; no rule ever fires on them).
  4. Policy Analytics  - per-firewall-policy behaviour + drift (surges,
     went-quiet, new countries through a policy).
  5. Coverage Map      - per-agent telemetry blind spots (no process/auth/FIM
     visibility) + org-level ATT&CK tactics with zero telemetry ever.
"""

import logging
from datetime import datetime, timezone

from clickhouse_client import _q, _iso, LOGS_TABLE

logger = logging.getLogger("telemetry-intel")

_ALLOWED = "('allow','allowed','accept','accepted','pass','permit','permitted')"
_BLOCKED = "('deny','denied','drop','dropped','block','blocked','reject','rejected')"

# Ports whose regular cadence is expected infrastructure, not C2.
_INFRA_PORTS = {"53", "123", "514", "1514", "1515", "5601"}


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _human_secs(s: float) -> str:
    s = max(0, int(s))
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m"
    if s < 86400:
        return f"{s // 3600}h {(s % 3600) // 60}m"
    return f"{s // 86400}d {(s % 86400) // 3600}h"


# ── 1. Silence Sentinel ─────────────────────────────────────────────────────

def silence_report(days: int = 14, min_events: int = 10) -> dict:
    """Per-agent reporting health. An agent is SILENT when its current quiet
    gap exceeds what its own history says is normal (3x its average active-hour
    gap, or 1.5x its worst historical gap, whichever is larger, floor 1h)."""
    rows = _q(
        f"""
        SELECT agent,
               count()                                        AS total,
               max(ts)                                        AS last_ts,
               min(ts)                                        AS first_ts,
               countIf(ts >= now() - INTERVAL 1 DAY)          AS last24,
               arraySort(groupUniqArray(toStartOfHour(ts)))   AS hrs
        FROM {LOGS_TABLE}
        WHERE agent != '' AND ts >= now() - INTERVAL {{days:UInt32}} DAY
        GROUP BY agent
        HAVING total >= {{minev:UInt32}}
        ORDER BY total DESC
        LIMIT 500
        """,
        {"days": int(days), "minev": int(min_events)},
    )
    now = _now_utc()
    agents, silent, degraded = [], 0, 0
    for r in rows:
        hrs = r.get("hrs") or []
        # gaps between consecutive ACTIVE hours (bounded: <= 24*days entries)
        epochs = sorted(int(h.timestamp()) if isinstance(h, datetime) else 0 for h in hrs)
        gaps = [b - a for a, b in zip(epochs, epochs[1:])] or [3600]
        avg_gap = sum(gaps) / len(gaps)
        max_gap = max(gaps)
        expected = max(avg_gap * 3, max_gap * 1.5, 3600)
        last = r.get("last_ts")
        last_dt = last if isinstance(last, datetime) else now
        if last_dt.tzinfo is None:
            last_dt = last_dt.replace(tzinfo=timezone.utc)
        quiet_s = (now - last_dt).total_seconds()
        span_days = max(1.0, (now - (r["first_ts"].replace(tzinfo=timezone.utc)
                                     if isinstance(r.get("first_ts"), datetime) and r["first_ts"].tzinfo is None
                                     else r.get("first_ts", now))).total_seconds() / 86400)
        avg_day = r["total"] / span_days
        drop_pct = 0
        if avg_day >= 5:  # only meaningful with some volume
            drop_pct = round(max(0.0, 1.0 - (r["last24"] / avg_day)) * 100)
        status = "ok"
        if quiet_s > expected * 2:
            status = "silent_critical"
        elif quiet_s > expected:
            status = "silent"
        elif drop_pct >= 75:
            status = "degraded"
        if status.startswith("silent"):
            silent += 1
        elif status == "degraded":
            degraded += 1
        agents.append({
            "agent": r["agent"],
            "status": status,
            "last_seen": _iso(last),
            "quiet_for": _human_secs(quiet_s),
            "quiet_seconds": int(quiet_s),
            "expected_max_gap": _human_secs(expected),
            "events_total": int(r["total"]),
            "events_24h": int(r["last24"]),
            "avg_per_day": round(avg_day, 1),
            "drop_pct": drop_pct,
        })
    rank = {"silent_critical": 0, "silent": 1, "degraded": 2, "ok": 3}
    agents.sort(key=lambda a: (rank.get(a["status"], 9), -a["quiet_seconds"]))
    return {
        "agents": agents,
        "summary": {"total": len(agents), "silent": silent, "degraded": degraded,
                    "ok": len(agents) - silent - degraded},
        "window_days": days,
        "generated_at": _iso(_now_utc()),
    }


# ── 2. First-Seen Ledger ────────────────────────────────────────────────────

def first_seen_report(days: int = 7) -> dict:
    """Org-wide novelty: entities whose FIRST EVER appearance is inside the
    window. Every log row contributes to the 'known' ledger; only genuine
    novelty surfaces. Near-zero false positives by construction."""
    p = {"days": int(days)}
    lookback = _q(f"SELECT min(ts) AS m, max(ts) AS x FROM {LOGS_TABLE}")
    global_min = lookback[0]["m"] if lookback else None
    learning = False
    if isinstance(global_min, datetime):
        gm = global_min.replace(tzinfo=timezone.utc) if global_min.tzinfo is None else global_min
        history_days = (_now_utc() - gm).total_seconds() / 86400
        learning = history_days < days * 2  # not enough history to call things "new"

    def fs(select: str, where: str, group: str, limit: int = 60) -> list[dict]:
        return _q(
            f"""
            SELECT {select}, min(ts) AS first_ts, count() AS events
            FROM {LOGS_TABLE}
            WHERE {where}
            GROUP BY {group}
            HAVING first_ts >= now() - INTERVAL {{days:UInt32}} DAY
            ORDER BY first_ts DESC
            LIMIT {limit}
            """, p)

    new_agents = fs("agent", "agent != ''", "agent")
    new_pairs = fs(
        "username, agent",
        "username != '' AND agent != '' AND NOT endsWith(username, '$') "
        "AND lower(username) != lower(agent)",
        "username, agent",
    )
    new_binaries = fs("proc_image", "proc_image != ''", "proc_image")
    new_countries = fs("country", "country != ''", "country", 30)
    new_ports = fs("dst_port", "dst_port != ''", "dst_port", 30)

    # Org prevalence: binaries seen on very few machines = worth a look.
    rare_binaries = _q(
        f"""
        SELECT proc_image, uniqExact(agent) AS on_agents, count() AS runs,
               min(ts) AS first_ts, max(ts) AS last_ts
        FROM {LOGS_TABLE}
        WHERE proc_image != '' AND agent != ''
        GROUP BY proc_image
        HAVING on_agents <= 2
        ORDER BY on_agents ASC, runs ASC
        LIMIT 40
        """)

    def clean(rows):
        out = []
        for r in rows:
            d = dict(r)
            for k in ("first_ts", "last_ts"):
                if k in d:
                    d[k] = _iso(d[k])
            for k in ("events", "runs", "on_agents"):
                if k in d:
                    d[k] = int(d[k])
            out.append(d)
        return out

    return {
        "learning_mode": learning,
        "history_from": _iso(global_min) if global_min else None,
        "window_days": days,
        "new_agents": clean(new_agents),
        "new_user_host_pairs": clean(new_pairs),
        "new_binaries": clean(new_binaries),
        "new_countries": clean(new_countries),
        "new_dst_ports": clean(new_ports),
        "rare_binaries": clean(rare_binaries),
        "summary": {
            "novelties": sum(len(x) for x in (new_agents, new_pairs, new_binaries,
                                              new_countries, new_ports)),
            "rare_binaries": len(rare_binaries),
        },
        "generated_at": _iso(_now_utc()),
    }


# ── 3. Beaconing detection ──────────────────────────────────────────────────

def beacon_report(hours: int = 24, min_hits: int = 12) -> dict:
    """Flows whose inter-arrival timing is machine-regular. cv = stddev/mean of
    the gaps; humans are bursty (cv >> 1), implant heartbeats are clockwork
    (cv < ~0.35 even with jitter). Runs on ALL traffic incl. allowed."""
    rows = _q(
        f"""
        WITH arraySort(groupArray(toUnixTimestamp(toDateTime(ts)))) AS times,
             arraySlice(arrayDifference(times), 2)                  AS gaps,
             arrayAvg(gaps)                                         AS mu,
             sqrt(arrayAvg(arrayMap(x -> (x - mu) * (x - mu), gaps))) AS sigma
        SELECT src_ip, dst_ip, dst_port,
               count()                                   AS hits,
               countIf(action IN {_ALLOWED})             AS allowed_hits,
               countIf(action IN {_BLOCKED})             AS blocked_hits,
               min(ts) AS first_ts, max(ts) AS last_ts,
               round(mu, 1)                              AS period_s,
               round(if(mu > 0, sigma / mu, 999), 3)     AS cv,
               any(country)                              AS country,
               any(agent)                                AS agent
        FROM {LOGS_TABLE}
        WHERE ts >= now() - INTERVAL {{hours:UInt32}} HOUR
          AND src_ip != '' AND dst_ip != ''
        GROUP BY src_ip, dst_ip, dst_port
        HAVING hits >= {{minhits:UInt32}}
           AND period_s BETWEEN 5 AND 3600
           AND cv < 0.35
        ORDER BY cv ASC, hits DESC
        LIMIT 50
        """,
        {"hours": int(hours), "minhits": int(min_hits)},
    )
    beacons = []
    for r in rows:
        period = float(r["period_s"] or 0)
        cv = float(r["cv"] or 1)
        # regularity 0..100 (lower cv = higher), weighted by evidence volume
        score = round(max(0.0, 1 - cv / 0.35) * 70 + min(30, int(r["hits"]) / 4))
        infra = str(r["dst_port"]) in _INFRA_PORTS
        beacons.append({
            "src_ip": r["src_ip"], "dst_ip": r["dst_ip"], "dst_port": r["dst_port"],
            "agent": r.get("agent") or "", "country": r.get("country") or "",
            "hits": int(r["hits"]),
            "allowed_hits": int(r["allowed_hits"]), "blocked_hits": int(r["blocked_hits"]),
            "period": _human_secs(period), "period_s": period,
            "cv": cv, "score": score,
            "likely_infra": infra,
            "first_ts": _iso(r["first_ts"]), "last_ts": _iso(r["last_ts"]),
            "verdict": ("expected infrastructure cadence" if infra else
                        "machine-regular heartbeat inside "
                        + ("ALLOWED" if r["allowed_hits"] >= r["blocked_hits"] else "blocked")
                        + " traffic - C2 beacon pattern"),
        })
    suspicious = [b for b in beacons if not b["likely_infra"]]
    return {
        "beacons": beacons,
        "summary": {"total": len(beacons), "suspicious": len(suspicious),
                    "infra": len(beacons) - len(suspicious)},
        "window_hours": hours,
        "generated_at": _iso(_now_utc()),
    }


# ── 4. Firewall policy analytics ────────────────────────────────────────────

_FW_FILTER = (
    "(decoder ILIKE '%fortigate%' OR decoder ILIKE '%firewall%' "
    "OR rule_groups ILIKE '%firewall%' OR rule ILIKE '%fortigate%' "
    "OR location ILIKE '%fortigate%')"
)
_PID_EXPR = (
    "if(JSONExtractString(raw, 'data', 'policyid') != '', "
    "JSONExtractString(raw, 'data', 'policyid'), "
    "extract(full_log, 'policyid=\"?([0-9]+)'))"
)


def policy_report(days: int = 7) -> dict:
    """Per-firewall-policy behaviour + drift. The raw JSON extraction only ever
    runs on rows passing the cheap firewall prefilter, and the endpoint caches
    the whole result, so this is one bounded scan per cache window."""
    rows = _q(
        f"""
        WITH {_PID_EXPR} AS pid
        SELECT pid                                          AS policy_id,
               count()                                      AS hits,
               countIf(action IN {_ALLOWED})                AS allowed,
               countIf(action IN {_BLOCKED})                AS blocked,
               countIf(ts >= now() - INTERVAL 1 DAY)        AS hits_24h,
               uniqExact(src_ip)                            AS src_count,
               uniqExact(dst_ip)                            AS dst_count,
               groupUniqArrayIf(country, ts >= now() - INTERVAL 1 DAY)  AS countries_24h,
               groupUniqArrayIf(country, ts <  now() - INTERVAL 1 DAY)  AS countries_before,
               min(ts) AS first_ts, max(ts) AS last_ts
        FROM {LOGS_TABLE}
        WHERE {_FW_FILTER} AND ts >= now() - INTERVAL {{days:UInt32}} DAY
        GROUP BY pid
        HAVING policy_id != ''
        ORDER BY hits DESC
        LIMIT 100
        """,
        {"days": int(days)},
    )
    policies, findings = [], []
    for r in rows:
        hits, h24 = int(r["hits"]), int(r["hits_24h"])
        prior_days = max(1, days - 1)
        prior_avg = (hits - h24) / prior_days
        surge = round(h24 / prior_avg, 1) if prior_avg >= 5 else 0
        new_countries = sorted(set(filter(None, r["countries_24h"] or [])) -
                               set(filter(None, r["countries_before"] or [])))
        went_quiet = prior_avg >= 20 and h24 == 0
        pol = {
            "policy_id": str(r["policy_id"]),
            "hits": hits, "hits_24h": h24,
            "allowed": int(r["allowed"]), "blocked": int(r["blocked"]),
            "src_count": int(r["src_count"]), "dst_count": int(r["dst_count"]),
            "surge_x": surge if surge >= 3 else 0,
            "new_countries_24h": new_countries,
            "went_quiet": went_quiet,
            "first_ts": _iso(r["first_ts"]), "last_ts": _iso(r["last_ts"]),
        }
        policies.append(pol)
        if surge >= 3:
            findings.append({"policy_id": pol["policy_id"], "kind": "surge",
                             "detail": f"policy #{pol['policy_id']} matched {surge}x its "
                                       f"daily average in the last 24h ({h24} hits)"})
        if new_countries:
            findings.append({"policy_id": pol["policy_id"], "kind": "new_country",
                             "detail": f"policy #{pol['policy_id']} passed traffic for "
                                       f"{', '.join(new_countries[:5])} for the first time "
                                       f"in {days} days"})
        if went_quiet:
            findings.append({"policy_id": pol["policy_id"], "kind": "went_quiet",
                             "detail": f"policy #{pol['policy_id']} (avg {int(prior_avg)}/day) "
                                       f"matched NOTHING in 24h - rule change or traffic rerouted?"})
    return {
        "policies": policies,
        "findings": findings,
        "summary": {"policies": len(policies), "findings": len(findings)},
        "window_days": days,
        "note": "hit-based: only policies that matched traffic are visible in logs",
        "generated_at": _iso(_now_utc()),
    }


# ── 5. Telemetry coverage / blind spots ─────────────────────────────────────

def coverage_report() -> dict:
    """Which telemetry classes each agent actually emits. An agent with zero
    process telemetry has no Sysmon = you are blind to execution there."""
    rows = _q(
        f"""
        SELECT agent,
               count()                                                    AS total,
               countIf(proc_image != '' OR proc_cmdline != '')            AS proc_ev,
               countIf(logon_type != '' OR rule_groups ILIKE '%authentication%'
                       OR rule ILIKE '%logon%' OR rule ILIKE '%login%')   AS auth_ev,
               countIf(rule_groups ILIKE '%syscheck%' OR sc_path != '')   AS fim_ev,
               countIf(mitre != '' OR mitre_technique != '')              AS mitre_ev,
               max(ts)                                                    AS last_ts
        FROM {LOGS_TABLE}
        WHERE agent != ''
        GROUP BY agent
        ORDER BY total DESC
        LIMIT 500
        """)
    tactic_rows = _q(
        f"""
        SELECT mitre_tactic, count() AS c FROM {LOGS_TABLE}
        WHERE mitre_tactic != '' GROUP BY mitre_tactic
        """)
    tactic_events: dict[str, int] = {}
    for r in tactic_rows:
        for t in str(r["mitre_tactic"]).split(","):
            t = t.strip()
            if t:
                tactic_events[t] = tactic_events.get(t, 0) + int(r["c"])

    agents, blind = [], 0
    for r in rows:
        gaps = []
        if not int(r["proc_ev"]):
            gaps.append("process")
        if not int(r["auth_ev"]):
            gaps.append("auth")
        if not int(r["fim_ev"]):
            gaps.append("fim")
        if gaps:
            blind += 1
        agents.append({
            "agent": r["agent"], "total": int(r["total"]),
            "process": int(r["proc_ev"]), "auth": int(r["auth_ev"]),
            "fim": int(r["fim_ev"]), "mitre": int(r["mitre_ev"]),
            "gaps": gaps, "last_seen": _iso(r["last_ts"]),
        })
    agents.sort(key=lambda a: (-len(a["gaps"]), -a["total"]))
    return {
        "agents": agents,
        "tactic_events": tactic_events,
        "summary": {"agents": len(agents), "with_gaps": blind,
                    "fully_covered": len(agents) - blind},
        "generated_at": _iso(_now_utc()),
    }


# ── Combined overview strip ─────────────────────────────────────────────────

def intel_summary() -> dict:
    """One cheap call for the overview KPI strip (each part already bounded)."""
    try:
        sil = silence_report()
        fsr = first_seen_report()
        bea = beacon_report()
        pol = policy_report()
        cov = coverage_report()
        return {
            "silent_agents": sil["summary"]["silent"] + sil["summary"]["degraded"],
            "agents_total": sil["summary"]["total"],
            "novelties_7d": fsr["summary"]["novelties"],
            "learning_mode": fsr["learning_mode"],
            "beacons": bea["summary"]["suspicious"],
            "policy_findings": pol["summary"]["findings"],
            "blind_agents": cov["summary"]["with_gaps"],
            "generated_at": _iso(_now_utc()),
        }
    except Exception as e:  # noqa: BLE001 - summary strip must never 500 the overview
        logger.error(f"intel_summary failed: {e}")
        return {"error": str(e), "generated_at": _iso(_now_utc())}
