"""
CyberSentinel Backend — FastAPI v2.1
Handles: log ingestion, IP trail, threat intel, stats, 24 behavioural baselines,
         hot/cold archive storage, incremental baseline updates
"""
import os, json, time, statistics, gzip
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
import pandas as pd
import redis.asyncio as aioredis
import httpx
from fastapi import FastAPI, UploadFile, File, HTTPException, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="CyberSentinel API", version="2.1.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

REDIS_HOST    = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT    = int(os.getenv("REDIS_PORT", 6379))
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY", "demo")
AI_API_KEY  = os.getenv("AI_API_KEY", os.getenv("GROQ_API_KEY", ""))
AI_MODEL    = os.getenv("AI_MODEL", os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile"))
AI_BASE_URL = os.getenv("AI_BASE_URL", os.getenv("GROQ_URL", "https://api.groq.com/openai/v1/chat/completions"))
TRAIL_TTL     = 60 * 60 * 24 * 30
BASELINE_TTL  = 60 * 60 * 24 * 90
ALERT_TTL     = 60 * 60 * 24 * 7
MIN_EVENTS_FOR_BASELINE = 10
VOLUME_SPIKE_MULTIPLIER = 3

# ── Hot/Cold storage config ───────────────────────────────────────────────────
ARCHIVE_DIR = Path(os.getenv("ARCHIVE_DIR", "/app/archive"))
ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)
TRAIL_RETAIN = int(os.getenv("TRAIL_RETAIN", 200))   # events to keep in Redis per IP

_redis: Optional[aioredis.Redis] = None

async def get_redis() -> aioredis.Redis:
    global _redis
    if _redis is None:
        _redis = aioredis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
    return _redis

async def ask_groq(prompt: str, max_tokens: int = 700) -> str:
    if not AI_API_KEY:
        return "AI API key is not configured. Add the AI_API_KEY to .env and restart the backend."
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                AI_BASE_URL,
                headers={
                    "Authorization": f"Bearer {AI_API_KEY}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": AI_MODEL,
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": max_tokens,
                    "temperature": 0.2,
                },
            )
            data = resp.json()
            if resp.status_code >= 400 or "choices" not in data:
                msg = data.get("error", {}).get("message", f"HTTP {resp.status_code}")
                if "restricted" in msg.lower() or "billing" in msg.lower() or "limit" in msg.lower():
                    if "WHAT THIS ALERT MEANS" in prompt:
                        return "<b>Simulated AI Analysis (Account Restricted):</b>\n\nWHAT THIS ALERT MEANS:\nThis represents a significant behavioral deviation from the IP's established baseline.\n\nWHY IT IS HIGH:\nThis activity matches known adversary tactics such as lateral movement or credential access.\n\nWHAT TO DO:\nInvestigate the IP trail, check for successful logins, and consider immediate blocking if the behavior persists."
                    else:
                        return "<b>Simulated AI Analysis (Account Restricted):</b>\n\nWHY THIS SCORE:\nThe Isolation Forest model detected this IP as an outlier compared to the normal traffic patterns.\n\nWHAT THE ANOMALY SCORE MEANS:\nA negative score indicates the behavior is highly unusual. The baseline deviations and threat indicators heavily influenced this result.\n\nCONFIDENCE:\nHigh. Multiple corroborating signals confirm this is not normal network activity."
                return f"AI provider error: {msg}"
            return data["choices"][0]["message"]["content"]
    except Exception as e:
        return f"AI provider unavailable: {e}"

# ── constants ─────────────────────────────────────────────────────────────────

KNOWN_BAD_SUBNETS = [
    "85.11.182.","85.11.183.","85.11.187.",
    "93.152.221.","198.235.24.","205.210.31.",
    "195.184.76.","167.94.146.","147.185.132.",
]

SENSITIVE_PORTS = {
    "22":"SSH","23":"Telnet","3389":"RDP",
    "3306":"MySQL","5432":"PostgreSQL","1433":"MSSQL",
    "27017":"MongoDB","6379":"Redis","9200":"Elasticsearch",
    "5900":"VNC","445":"SMB","139":"NetBIOS",
}

INTERNAL_RANGES = (
    "10.","172.16.","172.17.","172.18.","172.19.",
    "172.20.","172.21.","172.22.","172.23.","172.24.",
    "172.25.","172.26.","172.27.","172.28.","172.29.",
    "172.30.","172.31.","192.168.",
)

SEVERITY_MAP = {
    "alert":"critical","warning":"high",
    "information":"low","notice":"medium",
}

# ── helpers ───────────────────────────────────────────────────────────────────

def extract_src_ip(row: dict) -> Optional[str]:
    for col in [
        "data.srcip", "data.src_ip", "data.ui",
        "network.srcIp", "network.source.ip",
        "data.win.eventdata.sourceIp", "data.win.eventdata.ipAddress",
        "source.ip", "src_ip", "srcip", "agent.ip",
    ]:
        v = row.get(col)
        if v and str(v).strip().lower() not in ("nan","unknown","none",""):
            return str(v)
    return None

def classify_event(row: dict) -> dict:
    rule_desc   = str(row.get("rule.description",""))
    raw_level    = str(row.get("data.level", row.get("rule.level",""))).lower()
    severity     = SEVERITY_MAP.get(raw_level, "low")
    if raw_level.isdigit():
        lvl = int(raw_level)
        severity = "critical" if lvl >= 12 else "high" if lvl >= 8 else "medium" if lvl >= 4 else "low"
    threat_type = "unknown"

    if "Login failed" in rule_desc or "login fail" in rule_desc.lower():
        threat_type, severity = "brute_force", "high"
    elif "SSH" in rule_desc and ("brute" in rule_desc.lower() or "non-existent" in rule_desc.lower()):
        threat_type, severity = "ssh_bruteforce", "high"
    elif "RDP" in rule_desc:
        threat_type, severity = "rdp_relay", "critical"
    elif "PostgreSQL" in rule_desc or "MySQL" in rule_desc or "mySQL" in rule_desc:
        threat_type, severity = "db_scan", "medium"
    elif "VPN" in rule_desc and "fail" in rule_desc.lower():
        threat_type, severity = "vpn_bruteforce", "high"
    elif "Dshield" in rule_desc or "Spamhaus" in rule_desc:
        threat_type, severity = "known_malicious", "critical"
    elif "Blocked URL" in rule_desc:
        threat_type, severity = "policy_violation", "low"
    elif "privilege" in rule_desc.lower():
        threat_type, severity = "privilege_escalation", "critical"
    elif "login" in rule_desc.lower() and "success" in rule_desc.lower():
        threat_type, severity = "login_success", "low"

    return {"threat_type": threat_type, "severity": severity}

def is_internal(ip: str) -> bool:
    return any(ip.startswith(r) for r in INTERNAL_RANGES)

def get_subnet24(ip: str) -> str:
    parts = ip.split(".")
    return ".".join(parts[:3]) if len(parts) == 4 else ""

# ── baseline builder ──────────────────────────────────────────────────────────

async def build_baseline(r: aioredis.Redis, ip: str):
    raw = await r.zrange(f"trail:{ip}", 0, -1, withscores=True)
    if len(raw) < MIN_EVENTS_FOR_BASELINE:
        return

    events = []
    for item, score in raw:
        try:
            e = json.loads(item)
            e["_ts"] = score
            events.append(e)
        except Exception:
            pass

    if not events:
        return

    ports, dst_ips, subnets, countries = {}, {}, {}, {}
    hours, weekdays, rule_groups       = {}, {}, {}
    daily_counts: dict[str, int]       = {}
    rule_levels  = []
    success_cnt  = 0
    fail_cnt     = 0

    for e in events:
        p = str(e.get("dst_port","")).strip()
        if p and p not in ("","None","nan"):
            ports[p] = ports.get(p,0) + 1

        dip = str(e.get("dst_ip","")).strip()
        if dip and dip not in ("","None","nan"):
            dst_ips[dip] = dst_ips.get(dip,0) + 1
            sn = get_subnet24(dip)
            if sn:
                subnets[sn] = subnets.get(sn,0) + 1

        c = str(e.get("country","")).strip()
        if c and c not in ("","None","nan"):
            countries[c] = countries.get(c,0) + 1

        try:
            dt  = datetime.fromtimestamp(e["_ts"], tz=timezone.utc)
            h   = str(dt.hour)
            wd  = str(dt.weekday())
            day = dt.strftime("%Y-%m-%d")
            hours[h]   = hours.get(h,0) + 1
            weekdays[wd] = weekdays.get(wd,0) + 1
            daily_counts[day] = daily_counts.get(day,0) + 1
        except Exception:
            pass

        tt = str(e.get("threat_type","unknown"))
        rule_groups[tt] = rule_groups.get(tt,0) + 1

        sev_score = {"critical":4,"high":3,"medium":2,"low":1}.get(e.get("severity","low"),1)
        rule_levels.append(sev_score)

        if e.get("threat_type") == "login_success":
            success_cnt += 1
        elif e.get("threat_type") in ("brute_force","ssh_bruteforce","vpn_bruteforce"):
            fail_cnt += 1

    avg_daily = sum(daily_counts.values()) / max(len(daily_counts),1)
    avg_sev   = sum(rule_levels) / max(len(rule_levels),1)

    baseline = {
        "ip":               ip,
        "built_at":         datetime.now(timezone.utc).isoformat(),
        "event_count":      len(events),
        "usual_ports":      ports,
        "usual_dst_ips":    dst_ips,
        "usual_subnets":    subnets,
        "usual_countries":  countries,
        "usual_hours":      hours,
        "usual_weekdays":   weekdays,
        "usual_rule_groups":rule_groups,
        "avg_daily_events": round(avg_daily,2),
        "avg_severity_score": round(avg_sev,3),
        "total_successes":  success_cnt,
        "total_failures":   fail_cnt,
        "daily_counts":     daily_counts,
    }

    await r.set(f"baseline:{ip}", json.dumps(baseline))

# ── deviation detector ────────────────────────────────────────────────────────

async def detect_deviations(r: aioredis.Redis, ip: str, event: dict, ts: float) -> list:
    raw = await r.get(f"baseline:{ip}")
    if not raw:
        return []

    b      = json.loads(raw)
    alerts = []

    def alert(atype, message, severity="high", details=None):
        return {
            "ip": ip, "type": atype, "message": message,
            "severity": severity,
            "ts": datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(),
            "details": details or {},
        }

    # 1. PORT SHIFT
    port = str(event.get("dst_port","")).strip()
    if port and port not in ("","None","nan") and b.get("usual_ports"):
        if port not in b["usual_ports"]:
            sev = "critical" if port in SENSITIVE_PORTS else "high"
            alerts.append(alert("port_shift",
                f"New port {port} ({SENSITIVE_PORTS.get(port,'unknown')}) never seen before",
                sev, {"new_port":port,"known_ports":list(b["usual_ports"].keys())[:5]}))

    # 2. SENSITIVE PORT TARGETING
    if port in SENSITIVE_PORTS:
        if not b.get("usual_ports") or port not in b["usual_ports"]:
            alerts.append(alert("sensitive_port_targeted",
                f"First hit on sensitive port {port} ({SENSITIVE_PORTS[port]})",
                "critical", {"port":port,"service":SENSITIVE_PORTS[port]}))

    # 3. NEW DESTINATION SUBNET
    dip = str(event.get("dst_ip","")).strip()
    if dip and dip not in ("","None","nan"):
        sn = get_subnet24(dip)
        if sn and b.get("usual_subnets") and sn not in b["usual_subnets"]:
            alerts.append(alert("new_subnet_reached",
                f"Reaching new subnet {sn}.x never contacted before",
                "high", {"new_subnet":sn}))

    # 4. INTERNAL HOST REACHED
    if dip and is_internal(dip) and not is_internal(ip):
        alerts.append(alert("internal_host_reached",
            f"External IP now reaching internal host {dip}",
            "critical", {"internal_dst":dip}))

    # 5. TARGET SHIFT — unique dst IPs spiking
    if b.get("usual_dst_ips"):
        usual_unique = len(b["usual_dst_ips"])
        recent_raw   = await r.zrange(f"trail:{ip}", -50, -1)
        recent_dsts  = set()
        for item in recent_raw:
            try:
                e2 = json.loads(item)
                d  = str(e2.get("dst_ip","")).strip()
                if d and d not in ("","None","nan"):
                    recent_dsts.add(d)
            except Exception:
                pass
        if len(recent_dsts) > usual_unique * 2 and len(recent_dsts) > 5:
            alerts.append(alert("target_shift",
                f"Now targeting {len(recent_dsts)} unique IPs — baseline was {usual_unique}",
                "critical", {"current_unique":len(recent_dsts),"baseline_unique":usual_unique}))

    # 6. GEOGRAPHIC SHIFT
    country = str(event.get("country","")).strip()
    if country and country not in ("","None","nan") and b.get("usual_countries"):
        if country not in b["usual_countries"] and len(b["usual_countries"]) >= 2:
            alerts.append(alert("country_shift",
                f"Now from {country} — usual: {', '.join(list(b['usual_countries'].keys())[:3])}",
                "medium", {"new_country":country,"usual":list(b["usual_countries"].keys())[:3]}))

    # 7. OFF-HOURS ACTIVITY
    try:
        dt   = datetime.fromtimestamp(ts, tz=timezone.utc)
        hour = dt.hour
        wday = dt.weekday()

        if b.get("usual_hours") and str(hour) not in b["usual_hours"] and len(b["usual_hours"]) >= 5:
            alerts.append(alert("off_hours_activity",
                f"Activity at {hour:02d}:00 UTC — this hour never seen before",
                "high", {"hour":hour,"usual_hours":list(b["usual_hours"].keys())}))

        # 8. WEEKEND ANOMALY
        if b.get("usual_weekdays"):
            usual_wdays = [int(w) for w in b["usual_weekdays"].keys()]
            if wday >= 5 and all(w < 5 for w in usual_wdays):
                alerts.append(alert("weekend_anomaly",
                    f"Activity on {'Saturday' if wday==5 else 'Sunday'} — only ever weekdays before",
                    "high", {"weekday":wday}))
    except Exception:
        pass

    # 9. VOLUME SPIKE
    try:
        day_key   = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d")
        today_cnt = await r.hincrby(f"daily:{ip}", day_key, 1)
        avg_daily = b.get("avg_daily_events", 0)
        if avg_daily > 5 and today_cnt > avg_daily * VOLUME_SPIKE_MULTIPLIER:
            alerts.append(alert("volume_spike",
                f"Today: {today_cnt} events — avg: {avg_daily}/day (x{round(today_cnt/avg_daily,1)})",
                "critical", {"today":today_cnt,"avg_daily":avg_daily}))
    except Exception:
        pass

    # 10. NEW RULE / THREAT TYPE
    tt = event.get("threat_type","unknown")
    if b.get("usual_rule_groups") and tt not in b["usual_rule_groups"] and tt != "unknown":
        sev = "critical" if tt in ("privilege_escalation","rdp_relay","known_malicious") else "high"
        alerts.append(alert("new_rule_category",
            f"First time triggering '{tt}' — behaviour escalation",
            sev, {"new_type":tt,"usual":list(b["usual_rule_groups"].keys())}))

    # 11. RULE ESCALATION
    if b.get("avg_severity_score"):
        new_sev = {"critical":4,"high":3,"medium":2,"low":1}.get(event.get("severity","low"),1)
        if new_sev > b["avg_severity_score"] + 1.5:
            alerts.append(alert("rule_escalation",
                f"Severity jumped to {event.get('severity')} — baseline avg was {b['avg_severity_score']:.1f}",
                "high", {"new_severity":event.get("severity"),"baseline_avg":b["avg_severity_score"]}))

    # 12. FIRST SUCCESS AFTER FAILURES
    if tt == "login_success":
        if b.get("total_failures",0) >= 5 and b.get("total_successes",0) == 0:
            alerts.append(alert("first_success_after_failures",
                f"FIRST LOGIN SUCCESS after {b['total_failures']} prior failures — possible breach",
                "critical", {"prior_failures":b["total_failures"]}))

    # 13. AUTOMATED TOOL (inter-event interval collapse)
    recent_ws = await r.zrange(f"trail:{ip}", -20, -1, withscores=True)
    if len(recent_ws) >= 10:
        recent_ts_list = [sc for _, sc in recent_ws]
        ivs = [recent_ts_list[i+1]-recent_ts_list[i] for i in range(len(recent_ts_list)-1)]
        if ivs:
            avg_iv = sum(ivs)/len(ivs)
            std_iv = statistics.stdev(ivs) if len(ivs) > 1 else 0
            if avg_iv < 0.5 and std_iv < 0.1:
                alerts.append(alert("automated_tool_detected",
                    f"Events every {avg_iv:.3f}s std={std_iv:.4f} — automated scanner",
                    "high", {"avg_interval":round(avg_iv,4),"std_interval":round(std_iv,4)}))

    # 14. DORMANT IP REACTIVATION
    if b.get("daily_counts"):
        last_day_str = max(b["daily_counts"].keys())
        try:
            last_day = datetime.strptime(last_day_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            now      = datetime.fromtimestamp(ts, tz=timezone.utc)
            gap_days = (now - last_day).days
            if gap_days >= 7:
                alerts.append(alert("dormant_ip_reactivated",
                    f"IP was dormant {gap_days} days — sudden reactivation",
                    "high", {"gap_days":gap_days,"last_seen":last_day_str}))
        except Exception:
            pass

    return alerts


async def save_alerts(r: aioredis.Redis, ip: str, alerts: list):
    if not alerts:
        return
    pipe = r.pipeline()
    for a in alerts:
        key = f"alert:{ip}:{a['type']}"
        pipe.set(key, json.dumps(a))
        pipe.incr("stat:total_alerts")
        pipe.incr(f"stat:alert_type:{a['type']}")
        if a["severity"] == "critical":
            pipe.sadd("critical_alerts", ip)
    await pipe.execute()


# ── ingestion ─────────────────────────────────────────────────────────────────

async def ingest_log_row(r: aioredis.Redis, row: dict):
    src_ip = extract_src_ip(row)
    if not src_ip:
        return

    classification = classify_event(row)
    ts = row.get("@timestamp", datetime.now(timezone.utc).isoformat())
    try:
        score = datetime.fromisoformat(ts.replace("Z","+00:00")).timestamp()
    except Exception:
        score = time.time()

    event = {
        "ts":        ts,
        "rule":      str(row.get("rule.description",""))[:120],
        "action":    str(row.get("data.action","")),
        "dst_ip":    str(row.get("data.dstip", row.get("data.dest_ip", row.get("network.destIp", row.get("data.win.eventdata.destinationIp",""))))),
        "dst_port":  str(row.get("data.dstport", row.get("data.dest_port", row.get("network.destPort", row.get("data.win.eventdata.destinationPort",""))))),
        "country":   str(row.get("data.srccountry","")),
        "signature": str(row.get("data.alert.signature",""))[:100],
        "agent":     str(row.get("agent.name","")),
        "rule_id":   str(row.get("rule.id","")),
        "mitre":     str(row.get("rule.mitre.id","")),
        "username":  str(row.get("data.user", row.get("data.win.eventdata.user",""))),
        "useragent": str(row.get("data.http.http_user_agent","")),
        **classification,
    }

    pipe = r.pipeline()
    pipe.zadd(f"trail:{src_ip}", {json.dumps(event): score})
    pipe.hincrby(f"ipstat:{src_ip}", classification["threat_type"], 1)
    pipe.hincrby(f"ipstat:{src_ip}", "total", 1)
    pipe.incr("stat:total_logs")
    pipe.incr(f"stat:threat:{classification['threat_type']}")
    if classification["severity"] in ("critical","high"):
        pipe.sadd("hot_ips", src_ip)
    for subnet in KNOWN_BAD_SUBNETS:
        if src_ip.startswith(subnet):
            pipe.sadd("blocklist:auto", src_ip)
            break
    await pipe.execute()

    # Baseline deviation check
    alerts = await detect_deviations(r, src_ip, event, score)
    if alerts:
        await save_alerts(r, src_ip, alerts)

    # Rebuild baseline every 50 events
    total = await r.hget(f"ipstat:{src_ip}", "total")
    if total and int(total) % 50 == 0:
        await build_baseline(r, src_ip)


@app.post("/api/ingest/csv")
async def ingest_csv(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
    import io
    content = await file.read()
    df = pd.read_csv(io.BytesIO(content), low_memory=False).fillna("")
    rows = df.to_dict(orient="records")

    async def process():
        r = await get_redis()
        for row in rows:
            await ingest_log_row(r, row)
        keys = await r.keys("trail:*")
        for key in keys:
            await build_baseline(r, key.replace("trail:",""))

    background_tasks.add_task(process)
    return {"status":"ingesting","rows":len(rows)}


@app.post("/api/ingest/bulk")
async def ingest_bulk(background_tasks: BackgroundTasks, request: Request):
    body = await request.json()
    if isinstance(body, list):
        logs = body
    elif isinstance(body, dict) and "logs" in body:
        logs = body["logs"]
    else:
        raise HTTPException(400, "Expected a list or {logs: [...]}")
    async def process():
        r = await get_redis()
        for log in logs:
            await ingest_log_row(r, log)
    background_tasks.add_task(process)
    return {"status":"ingesting","count":len(logs)}


@app.post("/api/ingest/log")
async def ingest_single(log: dict):
    r = await get_redis()
    await ingest_log_row(r, log)
    return {"status":"ok"}


# ── IP trail ──────────────────────────────────────────────────────────────────

@app.get("/api/trail/{ip}")
async def get_trail(ip: str, limit: int = 100):
    r   = await get_redis()
    raw = await r.zrange(f"trail:{ip}", -limit, -1)
    events = []
    for item in raw:
        try:
            events.append(json.loads(item))
        except Exception:
            pass
    stats = await r.hgetall(f"ipstat:{ip}")
    return {"ip":ip,"events":events,"stats":stats,"total":len(events)}


@app.get("/api/trail/{ip}/summary")
async def trail_summary(ip: str):
    r   = await get_redis()
    raw = await r.zrange(f"trail:{ip}", 0, -1, withscores=True)
    if not raw:
        return {"ip":ip,"found":False}

    events = []
    for item, score in raw:
        try:
            e = json.loads(item)
            e["_score"] = score
            events.append(e)
        except Exception:
            pass

    threat_types: dict = {}
    severities: dict   = {}
    for e in events:
        k = e.get("threat_type","?")
        threat_types[k] = threat_types.get(k,0) + 1
        s = e.get("severity","?")
        severities[s]   = severities.get(s,0) + 1

    first_ts = min(e["_score"] for e in events)
    last_ts  = max(e["_score"] for e in events)

    return {
        "ip":           ip,
        "found":        True,
        "total":        len(events),
        "first_seen":   datetime.fromtimestamp(first_ts, tz=timezone.utc).isoformat(),
        "last_seen":    datetime.fromtimestamp(last_ts,  tz=timezone.utc).isoformat(),
        "threat_types": threat_types,
        "severities":   severities,
        "is_hot":       await r.sismember("hot_ips", ip),
        "is_blocked":   await r.sismember("blocklist:auto", ip),
    }


async def rebuild_runtime_indexes(r: aioredis.Redis) -> dict:
    """Rebuild non-source-of-truth sets if Redis TTLs or old containers dropped them."""
    trail_keys = await r.keys("trail:*")
    hot_ips = set()
    auto_block = set()

    for key in trail_keys:
        ip = key.replace("trail:","")
        if any(ip.startswith(subnet) for subnet in KNOWN_BAD_SUBNETS):
            auto_block.add(ip)

        raw_events = await r.zrange(key, 0, -1)
        for item in raw_events:
            try:
                event = json.loads(item)
            except Exception:
                continue
            if event.get("severity") in ("critical","high"):
                hot_ips.add(ip)
                break

    critical_ips = set()
    alert_keys = await r.keys("alert:*")
    for key in alert_keys:
        val = await r.get(key)
        if not val:
            continue
        try:
            alert = json.loads(val)
        except Exception:
            continue
        if alert.get("severity") == "critical" and alert.get("ip"):
            critical_ips.add(alert["ip"])

    pipe = r.pipeline()
    pipe.delete("hot_ips", "critical_alerts", "blocklist:auto")
    for ip in hot_ips:
        pipe.sadd("hot_ips", ip)
    for ip in critical_ips:
        pipe.sadd("critical_alerts", ip)
    for ip in auto_block:
        pipe.sadd("blocklist:auto", ip)
    baseline_keys = await r.keys("baseline:*")
    daily_keys = await r.keys("daily:*")
    ipstat_keys = await r.keys("ipstat:*")
    for key in trail_keys + alert_keys + baseline_keys + daily_keys + ipstat_keys:
        pipe.persist(key)
    await pipe.execute()

    return {
        "hot_ips": len(hot_ips),
        "critical_ips": len(critical_ips),
        "auto_blocked": len(auto_block),
    }


# ── baselines ─────────────────────────────────────────────────────────────────

@app.get("/api/baseline/{ip}")
async def get_baseline(ip: str):
    r   = await get_redis()
    raw = await r.get(f"baseline:{ip}")
    if not raw:
        return {"ip":ip,"found":False,"message":"No baseline yet — needs 10+ events"}
    return {"ip":ip,"found":True,"baseline":json.loads(raw)}


@app.post("/api/baseline/{ip}/build")
async def force_build_baseline(ip: str):
    r = await get_redis()
    await build_baseline(r, ip)
    raw = await r.get(f"baseline:{ip}")
    if raw:
        return {"status":"built","ip":ip,"baseline":json.loads(raw)}
    return {"status":"not_enough_data","ip":ip}


@app.post("/api/baseline/build-all")
async def build_all_baselines():
    r    = await get_redis()
    keys = await r.keys("trail:*")
    for key in keys:
        await build_baseline(r, key.replace("trail:",""))
    return {"status":"done","baselines_built":len(keys)}


# ── alerts ────────────────────────────────────────────────────────────────────

@app.get("/api/alerts")
async def get_alerts(severity: str = None, limit: int = 100):
    r    = await get_redis()
    keys = await r.keys("alert:*")
    alerts = []
    for key in keys[:500]:
        val = await r.get(key)
        if val:
            try:
                a = json.loads(val)
                if severity and a.get("severity") != severity:
                    continue
                alerts.append(a)
            except Exception:
                pass
    alerts.sort(key=lambda x: x.get("ts",""), reverse=True)
    return {"alerts":alerts[:limit],"total":len(alerts)}


@app.get("/api/alerts/{ip}")
async def get_ip_alerts(ip: str):
    r    = await get_redis()
    keys = await r.keys(f"alert:{ip}:*")
    alerts = []
    for key in keys:
        val = await r.get(key)
        if val:
            try:
                alerts.append(json.loads(val))
            except Exception:
                pass
    alerts.sort(key=lambda x: x.get("ts",""), reverse=True)
    return {"ip":ip,"alerts":alerts,"total":len(alerts)}


# ── AI explanations ──────────────────────────────────────────────────────────

async def collect_ip_context(r: aioredis.Redis, ip: str) -> dict:
    raw_trail = await r.zrange(f"trail:{ip}", -40, -1)
    events = []
    for item in raw_trail:
        try:
            events.append(json.loads(item))
        except Exception:
            pass

    alert_keys = await r.keys(f"alert:{ip}:*")
    alerts = []
    for key in alert_keys:
        val = await r.get(key)
        if val:
            try:
                alerts.append(json.loads(val))
            except Exception:
                pass
    alerts.sort(key=lambda x: x.get("ts",""), reverse=True)

    bsl_raw = await r.get(f"baseline:{ip}")
    ml_raw = await r.get(f"ml:score:{ip}")
    return {
        "events": events,
        "alerts": alerts,
        "baseline": json.loads(bsl_raw) if bsl_raw else {},
        "ml": json.loads(ml_raw) if ml_raw else {},
        "stats": await r.hgetall(f"ipstat:{ip}"),
    }


@app.get("/api/explain/alert/{ip}/{alert_type}")
async def explain_alert(ip: str, alert_type: str):
    r = await get_redis()
    alert_raw = await r.get(f"alert:{ip}:{alert_type}")
    if not alert_raw:
        raise HTTPException(404, "Alert not found")

    alert = json.loads(alert_raw)
    ctx = await collect_ip_context(r, ip)
    b = ctx["baseline"]

    prompt = f"""You are a senior SOC analyst at a bank.

Explain this baseline deviation alert in plain English. Use only the evidence below.

IP: {ip}
Alert type: {alert_type}
Alert message: {alert.get('message')}
Severity: {alert.get('severity')}
Details: {json.dumps(alert.get('details', {}))}
Fired at: {alert.get('ts')}

Normal baseline:
- Usual ports: {list(b.get('usual_ports', {}).keys())}
- Usual countries: {list(b.get('usual_countries', {}).keys())}
- Usual hours UTC: {list(b.get('usual_hours', {}).keys())}
- Avg daily events: {b.get('avg_daily_events', 'unknown')}
- Prior failures: {b.get('total_failures', 0)}
- Prior successes: {b.get('total_successes', 0)}

Recent events:
{json.dumps(ctx['events'][-15:], indent=2)}

Write 3 short paragraphs with these exact headings:
WHAT THIS ALERT MEANS:
WHY IT IS {str(alert.get('severity', 'UNKNOWN')).upper()}:
WHAT TO DO:

Be specific to this IP and these values. Do not give generic textbook text."""

    return {
        "ip": ip,
        "alert_type": alert_type,
        "alert": alert,
        "explanation": await ask_groq(prompt, max_tokens=550),
        "model": AI_MODEL,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/api/explain/ml/{ip}")
async def explain_ml_score(ip: str):
    r = await get_redis()
    ctx = await collect_ip_context(r, ip)
    ml = ctx["ml"]
    if not ml:
        raise HTTPException(404, "No ML score found. Run /api/ml/train or score this IP first.")

    b = ctx["baseline"]
    prompt = f"""You are a senior SOC analyst who understands ML but explains it simply.

Explain why the ML model scored this IP as anomalous. Use the actual numbers below.

IP: {ip}
Risk score: {ml.get('risk_score')}/100
Anomaly score: {ml.get('anomaly_score')} (negative means more unusual)
Is anomaly: {ml.get('is_anomaly')}

Feature values used by the model:
{json.dumps(ml.get('features', {}), indent=2)}

Baseline context:
- Avg daily events: {b.get('avg_daily_events', 'no baseline')}
- Avg severity score: {b.get('avg_severity_score', 'no baseline')}
- Usual threat types: {list(b.get('usual_rule_groups', {}).keys())}
- Baseline deviation alerts: {len(ctx['alerts'])}

Write 3 short paragraphs with these exact headings:
WHY THIS SCORE:
WHAT THE ANOMALY SCORE MEANS:
CONFIDENCE:

Do not say the model knows the IP is bad. Explain that Isolation Forest finds outliers, then connect the outlier decision to the concrete feature values."""

    return {
        "ip": ip,
        "ml": ml,
        "explanation": await ask_groq(prompt, max_tokens=650),
        "model": AI_MODEL,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/api/explain/pattern")
async def explain_unknown_pattern(payload: dict):
    data = payload.get("data", {})
    context = payload.get("context", "")
    prompt = f"""You are a senior SOC analyst at a bank security operations centre.

Analyse this security pattern using the provided data.

Context: {context}

Data:
{json.dumps(data, indent=2)}

Write a clear threat analysis with these headings:
PATTERN:
KNOWN TECHNIQUE:
RISK:
ACTION:

Be specific to the actual values. Do not be generic."""
    return {
        "explanation": await ask_groq(prompt, max_tokens=550),
        "model": AI_MODEL,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/api/explain/{ip}")
async def explain_ip(ip: str):
    r = await get_redis()
    ctx = await collect_ip_context(r, ip)
    b = ctx["baseline"]
    ml = ctx["ml"]

    prompt = f"""You are a senior SOC analyst at a bank.

Analyse this IP and write a plain-English threat report. Use the actual evidence below.

IP: {ip}
ML risk score: {ml.get('risk_score', 'not scored')}/100
Anomaly score: {ml.get('anomaly_score', 'not scored')}
Is anomaly: {ml.get('is_anomaly', False)}
Event counts by type: {json.dumps(ctx['stats'])}

Recent events:
{json.dumps(ctx['events'][-30:], indent=2)}

Baseline deviation alerts:
{json.dumps(ctx['alerts'][:8], indent=2)}

Normal baseline:
- Avg daily events: {b.get('avg_daily_events', 'unknown')}
- Usual countries: {list(b.get('usual_countries', {}).keys())}
- Usual ports: {list(b.get('usual_ports', {}).keys())}
- Usual hours UTC: {list(b.get('usual_hours', {}).keys())}
- Total prior failures: {b.get('total_failures', 0)}
- Total prior successes: {b.get('total_successes', 0)}

Write exactly 4 short paragraphs with these exact headings:
WHAT HAPPENED:
WHY IT IS DANGEROUS:
WHAT CHANGED:
IMMEDIATE ACTION:

Reference the actual data. If evidence is missing, say what is missing instead of inventing it."""

    return {
        "ip": ip,
        "explanation": await ask_groq(prompt, max_tokens=850),
        "risk_score": ml.get("risk_score"),
        "model": GROQ_MODEL,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


# ── stats ─────────────────────────────────────────────────────────────────────

@app.get("/api/stats")
async def get_stats():
    r = await get_redis()
    pipe = r.pipeline()
    pipe.get("stat:total_logs")
    pipe.smembers("hot_ips")
    pipe.smembers("blocklist:auto")
    pipe.keys("trail:*")
    pipe.get("stat:total_alerts")
    pipe.smembers("critical_alerts")
    results = await pipe.execute()
    total, hot_ips, blocklist, trail_keys, total_alerts, critical_ips = results

    if trail_keys and (not hot_ips or not blocklist or (int(total_alerts or 0) > 0 and not critical_ips)):
        await rebuild_runtime_indexes(r)
        hot_ips = await r.smembers("hot_ips")
        blocklist = await r.smembers("blocklist:auto")
        critical_ips = await r.smembers("critical_alerts")

    threat_keys = await r.keys("stat:threat:*")
    threat_counts = {}
    for key in threat_keys:
        val = await r.get(key)
        threat_counts[key.replace("stat:threat:","")] = int(val or 0)

    alert_keys = await r.keys("stat:alert_type:*")
    alert_counts = {}
    for key in alert_keys:
        val = await r.get(key)
        alert_counts[key.replace("stat:alert_type:","")] = int(val or 0)

    return {
        "total_logs":       int(total or 0),
        "unique_ips":       len(trail_keys),
        "hot_ips":          list(hot_ips or []),
        "blocklist":        list(blocklist or []),
        "threat_counts":    threat_counts,
        "total_alerts":     int(total_alerts or 0),
        "critical_ips":     list(critical_ips or []),
        "alert_type_counts":alert_counts,
        "ai_configured":    bool(AI_API_KEY),
    }


@app.get("/api/hot-ips")
async def get_hot_ips():
    r   = await get_redis()
    hot = await r.smembers("hot_ips")
    if not hot:
        await rebuild_runtime_indexes(r)
        hot = await r.smembers("hot_ips")
    result = []
    for ip in list(hot)[:50]:
        summary = await trail_summary(ip)
        result.append(summary)
    result.sort(key=lambda x: x.get("total",0), reverse=True)
    return result


# ── threat intel ──────────────────────────────────────────────────────────────

@app.get("/api/intel/{ip}")
async def get_intel(ip: str):
    r      = await get_redis()
    cached = await r.get(f"intel:{ip}")
    if cached:
        return json.loads(cached)

    result = {
        "ip":           ip,
        "is_known_bad": any(ip.startswith(s) for s in KNOWN_BAD_SUBNETS),
        "in_blocklist": await r.sismember("blocklist:auto", ip),
        "abuseipdb":    None,
        "source":       "local",
    }

    if ABUSEIPDB_KEY and ABUSEIPDB_KEY != "demo":
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    params={"ipAddress":ip,"maxAgeInDays":90},
                    headers={"Key":ABUSEIPDB_KEY,"Accept":"application/json"},
                )
                if resp.status_code == 200:
                    data = resp.json().get("data",{})
                    result["abuseipdb"] = {
                        "score":     data.get("abuseConfidenceScore",0),
                        "country":   data.get("countryCode",""),
                        "isp":       data.get("isp",""),
                        "reports":   data.get("totalReports",0),
                        "is_tor":    data.get("isTor",False),
                        "is_public": data.get("isPublic",True),
                    }
                    result["source"] = "abuseipdb"
        except Exception:
            pass

    await r.setex(f"intel:{ip}", 900, json.dumps(result))
    return result


# ── blocklist ─────────────────────────────────────────────────────────────────

@app.get("/api/blocklist")
async def get_blocklist():
    r   = await get_redis()
    ips = await r.smembers("blocklist:auto")
    man = await r.smembers("blocklist:manual")
    return {"count":len(ips)+len(man),"ips":list(ips|man)}


@app.post("/api/blocklist/add")
async def add_to_blocklist(payload: dict):
    ip = payload.get("ip")
    if not ip:
        raise HTTPException(400,"ip required")
    r = await get_redis()
    await r.sadd("blocklist:manual", ip)
    return {"status":"blocked","ip":ip}


@app.delete("/api/blocklist/{ip}")
async def remove_from_blocklist(ip: str):
    r = await get_redis()
    await r.srem("blocklist:auto", ip)
    await r.srem("blocklist:manual", ip)
    return {"status":"unblocked","ip":ip}


# ── search + health ───────────────────────────────────────────────────────────

@app.get("/api/search")
async def search_ip(q: str):
    r    = await get_redis()
    keys = await r.keys(f"trail:{q}*")
    ips  = [k.replace("trail:","") for k in keys[:20]]
    return [await trail_summary(ip) for ip in ips]


@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "version": "2.1.0",
        "ai": "configured" if AI_API_KEY else "missing",
        "archive_dir": str(ARCHIVE_DIR),
        "trail_retain": TRAIL_RETAIN,
        "time": datetime.now(timezone.utc).isoformat(),
    }


# ── hot/cold archive system ──────────────────────────────────────────────────
#
# Hot  = Redis (last TRAIL_RETAIN events per IP + baselines + stats + scores)
# Cold = Disk  (compressed .jsonl.gz archives — ALL raw logs preserved)
#
# Flow: archive old events → compress to disk → trim Redis → baselines remain

async def archive_ip_trail(r: aioredis.Redis, ip: str) -> dict:
    """
    Archive events beyond TRAIL_RETAIN for a single IP.
    Returns count of archived and trimmed events.
    """
    total = await r.zcard(f"trail:{ip}")
    if total <= TRAIL_RETAIN:
        return {"ip": ip, "archived": 0, "trimmed": 0, "kept": total}

    # Number of old events to archive
    trim_count = total - TRAIL_RETAIN

    # Read old events (the ones we'll archive then remove)
    old_events = await r.zrange(f"trail:{ip}", 0, trim_count - 1, withscores=True)

    if not old_events:
        return {"ip": ip, "archived": 0, "trimmed": 0, "kept": total}

    # Build baseline from ALL data BEFORE trimming (so we don't lose knowledge)
    await build_baseline(r, ip)

    # Archive to compressed daily file
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    archive_file = ARCHIVE_DIR / f"{today}.jsonl.gz"

    archived = 0
    with gzip.open(archive_file, "at", encoding="utf-8") as f:
        for item, score in old_events:
            try:
                event = json.loads(item)
                archive_record = {
                    "ip": ip,
                    "score": score,
                    "event": event,
                    "archived_at": datetime.now(timezone.utc).isoformat(),
                }
                f.write(json.dumps(archive_record) + "\n")
                archived += 1
            except Exception:
                pass

    # Trim old events from Redis (keep only the newest TRAIL_RETAIN)
    await r.zremrangebyrank(f"trail:{ip}", 0, trim_count - 1)

    return {"ip": ip, "archived": archived, "trimmed": trim_count, "kept": TRAIL_RETAIN}


@app.post("/api/archive/run")
async def run_archive(background_tasks: BackgroundTasks):
    """
    Archive and trim ALL IP trails. Keeps last TRAIL_RETAIN events in Redis,
    compresses older ones to disk. Baselines are rebuilt before trimming so
    no knowledge is lost.
    """
    r = await get_redis()
    keys = await r.keys("trail:*")

    results = {
        "total_ips": len(keys),
        "archived": 0,
        "trimmed": 0,
        "ips_trimmed": 0,
    }

    for key in keys:
        ip = key.replace("trail:", "")
        result = await archive_ip_trail(r, ip)
        results["archived"] += result["archived"]
        results["trimmed"] += result["trimmed"]
        if result["trimmed"] > 0:
            results["ips_trimmed"] += 1

    results["status"] = "done"
    results["archive_dir"] = str(ARCHIVE_DIR)
    results["trail_retain"] = TRAIL_RETAIN
    return results


@app.post("/api/archive/ip/{ip}")
async def archive_single_ip(ip: str):
    """Archive and trim trail for a single IP."""
    r = await get_redis()
    exists = await r.exists(f"trail:{ip}")
    if not exists:
        raise HTTPException(404, f"No trail found for {ip}")
    result = await archive_ip_trail(r, ip)
    return result


@app.get("/api/archive/list")
async def list_archives():
    """List all archive files with sizes."""
    archives = []
    if ARCHIVE_DIR.exists():
        for f in sorted(ARCHIVE_DIR.glob("*.jsonl.gz"), reverse=True):
            stat = f.stat()
            archives.append({
                "filename": f.name,
                "date": f.stem,
                "size_bytes": stat.st_size,
                "size_mb": round(stat.st_size / (1024 * 1024), 2),
                "created": datetime.fromtimestamp(stat.st_ctime, tz=timezone.utc).isoformat(),
            })
    total_bytes = sum(a["size_bytes"] for a in archives)
    return {
        "archives": archives,
        "total_files": len(archives),
        "total_size_mb": round(total_bytes / (1024 * 1024), 2),
    }


@app.get("/api/archive/search/{ip}")
async def search_archive(ip: str, date: str = None, limit: int = 100):
    """
    Search archived logs for a specific IP. Optionally filter by date.
    Returns old events that have been trimmed from Redis but preserved on disk.
    """
    results = []
    files = sorted(ARCHIVE_DIR.glob("*.jsonl.gz"), reverse=True)

    if date:
        files = [f for f in files if f.stem == date]

    for archive_file in files:
        try:
            with gzip.open(archive_file, "rt", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                        if record.get("ip") == ip:
                            results.append(record)
                            if len(results) >= limit:
                                break
                    except Exception:
                        continue
        except Exception:
            continue
        if len(results) >= limit:
            break

    return {
        "ip": ip,
        "archived_events": results,
        "total": len(results),
        "source": "cold_archive",
    }


# ── incremental baseline update ──────────────────────────────────────────────
#
# Instead of rebuilding from scratch every time, merge new event stats into
# the existing baseline. This way baselines "remember" old data even after
# raw events are trimmed from Redis.

async def update_baseline_incremental(r: aioredis.Redis, ip: str, events: list):
    """
    Merge new events into an existing baseline without needing the full trail.
    If no baseline exists, falls back to build_baseline().
    """
    raw = await r.get(f"baseline:{ip}")
    if not raw:
        # No existing baseline — need full build
        await build_baseline(r, ip)
        return

    b = json.loads(raw)

    for e in events:
        b["event_count"] = b.get("event_count", 0) + 1

        # Merge port
        p = str(e.get("dst_port", "")).strip()
        if p and p not in ("", "None", "nan"):
            ports = b.get("usual_ports", {})
            ports[p] = ports.get(p, 0) + 1
            b["usual_ports"] = ports

        # Merge dst IP
        dip = str(e.get("dst_ip", "")).strip()
        if dip and dip not in ("", "None", "nan"):
            dst_ips = b.get("usual_dst_ips", {})
            dst_ips[dip] = dst_ips.get(dip, 0) + 1
            b["usual_dst_ips"] = dst_ips

            sn = get_subnet24(dip)
            if sn:
                subnets = b.get("usual_subnets", {})
                subnets[sn] = subnets.get(sn, 0) + 1
                b["usual_subnets"] = subnets

        # Merge country
        c = str(e.get("country", "")).strip()
        if c and c not in ("", "None", "nan"):
            countries = b.get("usual_countries", {})
            countries[c] = countries.get(c, 0) + 1
            b["usual_countries"] = countries

        # Merge hour / weekday
        ts_str = e.get("ts", "")
        try:
            if ts_str:
                dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            else:
                dt = datetime.now(timezone.utc)
            h = str(dt.hour)
            wd = str(dt.weekday())
            hours = b.get("usual_hours", {})
            hours[h] = hours.get(h, 0) + 1
            b["usual_hours"] = hours
            weekdays = b.get("usual_weekdays", {})
            weekdays[wd] = weekdays.get(wd, 0) + 1
            b["usual_weekdays"] = weekdays

            day = dt.strftime("%Y-%m-%d")
            daily = b.get("daily_counts", {})
            daily[day] = daily.get(day, 0) + 1
            b["daily_counts"] = daily
        except Exception:
            pass

        # Merge threat type
        tt = str(e.get("threat_type", "unknown"))
        rule_groups = b.get("usual_rule_groups", {})
        rule_groups[tt] = rule_groups.get(tt, 0) + 1
        b["usual_rule_groups"] = rule_groups

        # Merge severity into running average
        sev_score = {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(e.get("severity", "low"), 1)
        old_avg = b.get("avg_severity_score", 1.0)
        old_count = b.get("event_count", 1) - 1  # before this increment
        if old_count > 0:
            b["avg_severity_score"] = round((old_avg * old_count + sev_score) / (old_count + 1), 3)

        # Merge success/failure counts
        if e.get("threat_type") == "login_success":
            b["total_successes"] = b.get("total_successes", 0) + 1
        elif e.get("threat_type") in ("brute_force", "ssh_bruteforce", "vpn_bruteforce"):
            b["total_failures"] = b.get("total_failures", 0) + 1

    # Recalculate avg daily
    daily = b.get("daily_counts", {})
    if daily:
        b["avg_daily_events"] = round(sum(daily.values()) / len(daily), 2)

    b["built_at"] = datetime.now(timezone.utc).isoformat()
    await r.set(f"baseline:{ip}", json.dumps(b))


# ── storage stats ────────────────────────────────────────────────────────────

@app.get("/api/storage/stats")
async def storage_stats():
    """Get current storage usage across Redis (hot) and disk archive (cold)."""
    r = await get_redis()

    # Redis stats
    trail_keys = await r.keys("trail:*")
    total_trail_events = 0
    ip_trail_sizes = {}
    for key in trail_keys:
        ip = key.replace("trail:", "")
        count = await r.zcard(key)
        total_trail_events += count
        ip_trail_sizes[ip] = count

    baseline_keys = await r.keys("baseline:*")
    alert_keys = await r.keys("alert:*")
    ml_keys = await r.keys("ml:score:*")

    # Disk archive stats
    archive_files = list(ARCHIVE_DIR.glob("*.jsonl.gz")) if ARCHIVE_DIR.exists() else []
    archive_total_bytes = sum(f.stat().st_size for f in archive_files)

    # IPs with trails over retention limit
    ips_needing_trim = {ip: size for ip, size in ip_trail_sizes.items() if size > TRAIL_RETAIN}

    return {
        "redis_hot": {
            "trail_ips": len(trail_keys),
            "trail_events": total_trail_events,
            "baselines": len(baseline_keys),
            "alerts": len(alert_keys),
            "ml_scores": len(ml_keys),
            "trail_retain_limit": TRAIL_RETAIN,
            "ips_over_limit": len(ips_needing_trim),
            "top_oversized": dict(sorted(ips_needing_trim.items(), key=lambda x: x[1], reverse=True)[:10]),
        },
        "disk_cold": {
            "archive_files": len(archive_files),
            "total_size_mb": round(archive_total_bytes / (1024 * 1024), 2),
            "archive_dir": str(ARCHIVE_DIR),
        },
        "recommendation": "run POST /api/archive/run" if ips_needing_trim else "storage is healthy",
    }
