"""
CyberSentinel Backend — FastAPI v2.2
Handles: log ingestion, IP trail, threat intel, stats, 24 behavioural baselines,
         hot/cold archive storage, incremental baseline updates,
         OpenSearch persistent store with ILM
"""
import os, json, time, statistics, gzip, logging, asyncio, threading
from collections import deque, OrderedDict
try:
    import opensearch_client as osc
except Exception:
    osc = None  # type: ignore
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional
import pandas as pd
import redis.asyncio as aioredis
import httpx
from fastapi import FastAPI, UploadFile, File, HTTPException, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware

logger = logging.getLogger("cybersentinel.backend")

app = FastAPI(title="CyberSentinel API", version="2.2.0")
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

# ── OpenSearch config ─────────────────────────────────────────────────────────
OPENSEARCH_ENABLED = os.getenv("OPENSEARCH_ENABLED", "false").lower() in ("true", "1", "yes")
OPENSEARCH_HOST    = os.getenv("OPENSEARCH_HOST", "localhost")
OPENSEARCH_PORT    = int(os.getenv("OPENSEARCH_PORT", 9200))
OPENSEARCH_USER    = os.getenv("OPENSEARCH_USER", "admin")
OPENSEARCH_PASS    = os.getenv("OPENSEARCH_PASS", "admin")
OS_INDEX_ALIAS     = "cybersentinel-logs"           # rollover write alias
OS_BULK_SIZE       = int(os.getenv("OS_BULK_SIZE", 200))
OS_FLUSH_INTERVAL  = float(os.getenv("OS_FLUSH_INTERVAL", 5.0))  # seconds

_redis: Optional[aioredis.Redis] = None

async def get_redis() -> aioredis.Redis:
    global _redis
    if _redis is None:
        _redis = aioredis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
    return _redis

# ── In-process recent-events LRU cache ───────────────────────────────────────
# Keeps last RECENT_PER_IP events per IP in Python process memory (NOT Redis).
# Bounded by RECENT_MAX_IPS active IPs — evicts LRU IP when exceeded.
# Used by deviation detection (target_shift, automated_tool).
# Lost on container restart — acceptable: needs a few events to warm up.

RECENT_PER_IP  = 50           # events kept per IP
RECENT_MAX_IPS = 3000         # max IPs tracked; LRU eviction beyond this

_recent: OrderedDict[str, deque] = OrderedDict()   # ip → deque of (score, event)

def _push_recent(ip: str, score: float, event: dict) -> None:
    """Append an event to the in-process recent-events cache."""
    if ip not in _recent:
        if len(_recent) >= RECENT_MAX_IPS:
            _recent.popitem(last=False)          # evict oldest IP
        _recent[ip] = deque(maxlen=RECENT_PER_IP)
    else:
        _recent.move_to_end(ip)
    _recent[ip].append((score, event))

def _get_recent(ip: str, limit: int = 50) -> list[tuple[float, dict]]:
    """Return last `limit` (score, event) tuples for an IP, newest last."""
    dq = _recent.get(ip)
    if not dq:
        return []
    items = list(dq)
    return items[-limit:]

# ── OpenSearch client & bulk buffer ───────────────────────────────────────────

_os_client = None
_os_buffer: list[dict] = []
_os_lock = threading.Lock()
_os_flush_task: Optional[asyncio.Task] = None

def get_opensearch():
    """Lazy singleton for the OpenSearch client."""
    global _os_client
    if _os_client is not None:
        return _os_client
    if not OPENSEARCH_ENABLED:
        return None
    try:
        from opensearchpy import OpenSearch
        _os_client = OpenSearch(
            hosts=[{"host": OPENSEARCH_HOST, "port": OPENSEARCH_PORT}],
            http_auth=(OPENSEARCH_USER, OPENSEARCH_PASS),
            use_ssl=True,
            verify_certs=False,
            ssl_show_warn=False,
            timeout=30,
        )
        info = _os_client.info()
        ver = info.get("version", {}).get("number", "?")
        logger.info(f"OpenSearch connected: v{ver} at {OPENSEARCH_HOST}:{OPENSEARCH_PORT}")
        return _os_client
    except Exception as e:
        logger.warning(f"OpenSearch connection failed: {e} — continuing with Redis only")
        _os_client = None
        return None


def _os_queue_doc(doc: dict) -> None:
    """Add a document to the bulk buffer. Thread-safe."""
    if not OPENSEARCH_ENABLED:
        return
    with _os_lock:
        _os_buffer.append(doc)
        if len(_os_buffer) >= OS_BULK_SIZE:
            _flush_os_buffer_sync()


def _flush_os_buffer_sync() -> None:
    """Flush the OpenSearch bulk buffer (called under _os_lock)."""
    global _os_buffer
    if not _os_buffer:
        return
    client = get_opensearch()
    if client is None:
        _os_buffer.clear()
        return
    docs_to_flush = _os_buffer[:]
    _os_buffer = []

    bulk_body = []
    for doc in docs_to_flush:
        bulk_body.append({"index": {"_index": OS_INDEX_ALIAS}})
        bulk_body.append(doc)
    try:
        resp = client.bulk(body=bulk_body, refresh=False)
        errors = resp.get("errors", False)
        if errors:
            failed = sum(1 for item in resp.get("items", []) if item.get("index", {}).get("error"))
            logger.warning(f"OpenSearch bulk: {len(docs_to_flush)} docs, {failed} errors")
        else:
            logger.debug(f"OpenSearch bulk: {len(docs_to_flush)} docs indexed")
    except Exception as e:
        logger.error(f"OpenSearch bulk flush failed: {e}")


async def _os_periodic_flush() -> None:
    """Background task that flushes OpenSearch buffer every OS_FLUSH_INTERVAL seconds."""
    while True:
        await asyncio.sleep(OS_FLUSH_INTERVAL)
        with _os_lock:
            _flush_os_buffer_sync()


@app.on_event("startup")
async def _start_os_flusher():
    global _os_flush_task
    if OPENSEARCH_ENABLED:
        get_opensearch()  # warm up connection
        _os_flush_task = asyncio.create_task(_os_periodic_flush())
        logger.info(f"OpenSearch bulk flusher started (interval={OS_FLUSH_INTERVAL}s, batch={OS_BULK_SIZE})")


@app.on_event("shutdown")
async def _stop_os_flusher():
    if _os_flush_task:
        _os_flush_task.cancel()
    # Final flush
    with _os_lock:
        _flush_os_buffer_sync()

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
                        return "**Simulated AI Analysis (Account Restricted):**\n\nWHAT THIS ALERT MEANS:\nThis represents a significant behavioral deviation from the IP's established baseline.\n\nWHY IT IS HIGH:\nThis activity matches known adversary tactics such as lateral movement or credential access.\n\nWHAT TO DO:\nInvestigate the IP trail, check for successful logins, and consider immediate blocking if the behavior persists."
                    else:
                        return "**Simulated AI Analysis (Account Restricted):**\n\nWHY THIS SCORE:\nThe Isolation Forest model detected this IP as an outlier compared to the normal traffic patterns.\n\nWHAT THE ANOMALY SCORE MEANS:\nA negative score indicates the behavior is highly unusual. The baseline deviations and threat indicators heavily influenced this result.\n\nCONFIDENCE:\nHigh. Multiple corroborating signals confirm this is not normal network activity."
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
    """
    Build a behavioural baseline for an IP.
    Source of truth is OpenSearch (full history).
    Falls back to the in-process recent-events cache when OpenSearch is disabled.
    """
    # --- source: OpenSearch (preferred) ---
    if OPENSEARCH_ENABLED and osc:
        events = osc.get_ip_events(ip, limit=5000)  # up to last 5k events
    else:
        # Fallback: use in-process cache
        events = [e for _, e in _get_recent(ip, limit=RECENT_PER_IP)]

    if len(events) < MIN_EVENTS_FOR_BASELINE:
        return

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

    # 5. TARGET SHIFT — unique dst IPs spiking (uses in-process LRU cache)
    if b.get("usual_dst_ips"):
        usual_unique = len(b["usual_dst_ips"])
        recent_dsts  = set()
        for _, e2 in _get_recent(ip, limit=50):
            d = str(e2.get("dst_ip","")).strip()
            if d and d not in ("","None","nan"):
                recent_dsts.add(d)
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

    # 13. AUTOMATED TOOL (inter-event interval collapse) — uses in-process LRU cache
    recent_ws = _get_recent(ip, limit=20)
    if len(recent_ws) >= 10:
        recent_ts_list = [sc for sc, _ in recent_ws]
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

async def ingest_log_row(r: aioredis.Redis, row: dict) -> bool:
    src_ip = extract_src_ip(row)
    if not src_ip:
        return False

    classification = classify_event(row)
    ts = row.get("@timestamp", datetime.now(timezone.utc).isoformat())
    try:
        score = datetime.fromisoformat(ts.replace("Z","+00:00")).timestamp()
    except Exception:
        score = time.time()

    dst_ip_val   = str(row.get("data.dstip", row.get("data.dest_ip", row.get("network.destIp", row.get("data.win.eventdata.destinationIp","")))))
    dst_port_val = str(row.get("data.dstport", row.get("data.dest_port", row.get("network.destPort", row.get("data.win.eventdata.destinationPort","")))))

    event = {
        "ts":        ts,
        "rule":      str(row.get("rule.description",""))[:120],
        "action":    str(row.get("data.action","")),
        "dst_ip":    dst_ip_val,
        "dst_port":  dst_port_val,
        "country":   str(row.get("data.srccountry","")),
        "signature": str(row.get("data.alert.signature",""))[:100],
        "agent":     str(row.get("agent.name","")),
        "rule_id":   str(row.get("rule.id","")),
        "mitre":     str(row.get("rule.mitre.id","")),
        "username":  str(row.get("data.user", row.get("data.win.eventdata.user",""))),
        "useragent": str(row.get("data.http.http_user_agent","")),
        **classification,
    }

    # ── Update in-process recent-events LRU cache (for deviation detection) ─
    _push_recent(src_ip, score, event)

    # ── Redis: thin aggregates only — NO trail, NO ipstat per-IP ─────────
    pipe = r.pipeline()
    pipe.incr("stat:total_logs")
    pipe.incr(f"stat:threat:{classification['threat_type']}")
    pipe.incr(f"ipcnt:{src_ip}")            # lightweight per-IP event counter
    if classification["severity"] in ("critical", "high"):
        pipe.sadd("hot_ips", src_ip)
    for subnet in KNOWN_BAD_SUBNETS:
        if src_ip.startswith(subnet):
            pipe.sadd("blocklist:auto", src_ip)
            break
    results = await pipe.execute()

    # ── OpenSearch: primary log store ─────────────────────────────────────
    if OPENSEARCH_ENABLED:
        os_doc = {
            "@timestamp":  ts,
            "ingested_at": datetime.now(timezone.utc).isoformat(),
            "src_ip":      src_ip,
            "dst_ip":      dst_ip_val,
            "dst_port":    dst_port_val,
            "threat_type": classification["threat_type"],
            "severity":    classification["severity"],
            "rule":        str(row.get("rule.description",""))[:120],
            "rule_id":     str(row.get("rule.id","")),
            "action":      str(row.get("data.action","")),
            "country":     str(row.get("data.srccountry","")),
            "agent":       str(row.get("agent.name","")),
            "mitre":       str(row.get("rule.mitre.id","")),
            "username":    str(row.get("data.user", row.get("data.win.eventdata.user",""))),
            "useragent":   str(row.get("data.http.http_user_agent","")),
            "signature":   str(row.get("data.alert.signature",""))[:100],
        }
        _os_queue_doc(os_doc)

    # ── Baseline deviation check ──────────────────────────────────────────
    alerts = await detect_deviations(r, src_ip, event, score)
    if alerts:
        await save_alerts(r, src_ip, alerts)

    # ── Rebuild baseline every 100 events per IP ──────────────────────────
    # ipcnt result is the 3rd pipeline result (index 2)
    ipcnt_val = results[2] if len(results) > 2 else 0
    if ipcnt_val and int(ipcnt_val) % 100 == 0:
        await build_baseline(r, src_ip)

    return True


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
        # Build baselines for all IPs seen in OpenSearch after CSV ingest
        if OPENSEARCH_ENABLED and osc:
            for ip in osc.get_all_unique_ips():
                await build_baseline(r, ip)
        else:
            # Fallback: build from in-process cache
            for ip in list(_recent.keys()):
                await build_baseline(r, ip)

    background_tasks.add_task(process)
    return {"status":"ingesting","rows":len(rows)}


@app.post("/api/ingest/bulk")
async def ingest_bulk(request: Request):
    body = await request.json()
    if isinstance(body, list):
        logs = body
    elif isinstance(body, dict) and "logs" in body:
        logs = body["logs"]
    else:
        raise HTTPException(400, "Expected a list or {logs: [...]}")
    r = await get_redis()
    saved = 0
    skipped = 0
    for log in logs:
        if await ingest_log_row(r, log):
            saved += 1
        else:
            skipped += 1
    return {"status":"ok","count":len(logs),"saved":saved,"skipped":skipped}


@app.post("/api/ingest/log")
async def ingest_single(log: dict):
    r = await get_redis()
    await ingest_log_row(r, log)
    return {"status":"ok"}


# ── IP trail ──────────────────────────────────────────────────────────────────

@app.get("/api/trail/{ip}")
async def get_trail(ip: str, limit: int = 100):
    """Recent trail for an IP. Reads from OpenSearch when enabled."""
    if OPENSEARCH_ENABLED and osc:
        events = osc.get_ip_events_desc(ip, limit=limit)
        total  = osc.get_ip_total_count(ip)
        threat_counts = osc.get_ip_threat_counts(ip)
        return {"ip": ip, "events": events, "stats": threat_counts, "total": total, "source": "opensearch"}
    # Fallback: in-process cache
    recent = _get_recent(ip, limit=limit)
    events = [e for _, e in recent]
    return {"ip": ip, "events": events, "stats": {}, "total": len(events), "source": "cache"}


@app.get("/api/trail/{ip}/summary")
async def trail_summary(ip: str):
    """IP summary: threat types, severities, first/last seen — from OpenSearch."""
    r = await get_redis()
    if OPENSEARCH_ENABLED and osc:
        total = osc.get_ip_total_count(ip)
        if total == 0:
            return {"ip": ip, "found": False}
        threat_types  = osc.get_ip_threat_counts(ip)
        severities    = osc.get_ip_severity_counts(ip)
        first_seen, last_seen = osc.get_ip_first_last_seen(ip)
        return {
            "ip":           ip,
            "found":        True,
            "total":        total,
            "first_seen":   first_seen,
            "last_seen":    last_seen,
            "threat_types": threat_types,
            "severities":   severities,
            "is_hot":       await r.sismember("hot_ips", ip),
            "is_blocked":   await r.sismember("blocklist:auto", ip),
            "source":       "opensearch",
        }

    # Fallback when OpenSearch is disabled — use in-process cache
    recent = _get_recent(ip, limit=RECENT_PER_IP)
    if not recent:
        return {"ip": ip, "found": False}
    events = [e for _, e in recent]
    threat_types: dict = {}
    severities: dict   = {}
    for e in events:
        threat_types[e.get("threat_type","?")] = threat_types.get(e.get("threat_type","?"),0)+1
        severities[e.get("severity","?")]       = severities.get(e.get("severity","?"),0)+1
    first_ts = min(sc for sc, _ in recent)
    last_ts  = max(sc for sc, _ in recent)

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
    ipcnt_keys = await r.keys("ipcnt:*")
    for key in alert_keys + baseline_keys + daily_keys + ipcnt_keys:
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
    r = await get_redis()
    if OPENSEARCH_ENABLED and osc:
        ips = osc.get_all_unique_ips()
    else:
        cnt_keys = await r.keys("ipcnt:*")
        ips = [k.replace("ipcnt:", "") for k in cnt_keys]
    for ip in ips:
        await build_baseline(r, ip)
    return {"status": "done", "baselines_built": len(ips)}


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
    # Pull recent events from OpenSearch for AI explanations
    if OPENSEARCH_ENABLED and osc:
        events = osc.get_ip_events_desc(ip, limit=40)
    else:
        events = [e for _, e in _get_recent(ip, limit=40)]

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
    # Use ipcnt counter for event count; full stats come from OpenSearch
    ipcnt = await r.get(f"ipcnt:{ip}")
    return {
        "events": events,
        "alerts": alerts,
        "baseline": json.loads(bsl_raw) if bsl_raw else {},
        "ml": json.loads(ml_raw) if ml_raw else {},
        "stats": {"total": ipcnt or "0"},
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
        "model": AI_MODEL,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


# ── Deterministic Reports ─────────────────────────────────────────────────────

def _human_count(value) -> str:
    try:
        return f"{int(value):,}"
    except Exception:
        return "0"


def _top_items(values: dict, limit: int = 5) -> list[tuple[str, int]]:
    items = []
    for key, value in (values or {}).items():
        try:
            items.append((str(key), int(value)))
        except Exception:
            continue
    return sorted(items, key=lambda item: item[1], reverse=True)[:limit]


def _primary_driver(counts: dict) -> str:
    items = _top_items(counts, 1)
    return items[0][0].replace("_", " ") if items else "unknown activity"


def _report_window(timeframe: str) -> tuple[int, datetime, datetime]:
    if timeframe not in ("weekly", "monthly"):
        raise HTTPException(400, "Timeframe must be weekly or monthly")
    days = 7 if timeframe == "weekly" else 30
    end = datetime.now(timezone.utc)
    return days, end - timedelta(days=days), end


async def _report_from_opensearch(days: int, r: aioredis.Redis) -> dict:
    client = get_opensearch()
    if not client:
        return {}
    query = {"bool": {"filter": [{"range": {"@timestamp": {"gte": f"now-{days}d"}}}]}}
    try:
        resp = client.search(
            index="cybersentinel-logs-*",
            body={
                "size": 0,
                "query": query,
                "aggs": {
                    "threats": {"terms": {"field": "threat_type", "size": 12}},
                    "severities": {"terms": {"field": "severity", "size": 8}},
                    "top_ips": {
                        "terms": {"field": "src_ip", "size": 10},
                        "aggs": {
                            "threats": {"terms": {"field": "threat_type", "size": 5}},
                            "severities": {"terms": {"field": "severity", "size": 5}},
                            "ports": {"terms": {"field": "dst_port", "size": 5}},
                            "last_seen": {"max": {"field": "@timestamp"}},
                            "samples": {
                                "top_hits": {
                                    "size": 3,
                                    "sort": [{"@timestamp": {"order": "desc"}}],
                                    "_source": ["@timestamp", "rule", "threat_type", "severity", "dst_ip", "dst_port", "agent", "username"],
                                }
                            },
                        },
                    },
                    "agents": {"terms": {"field": "agent", "size": 8}},
                },
            },
        )
    except Exception as e:
        logger.warning(f"OpenSearch report aggregation failed: {e}")
        return {}

    total = resp.get("hits", {}).get("total", {}).get("value", 0)
    aggs = resp.get("aggregations", {})
    top_ips = []
    for bucket in aggs.get("top_ips", {}).get("buckets", []):
        ip = bucket.get("key")
        threat_counts = {b["key"]: b["doc_count"] for b in bucket.get("threats", {}).get("buckets", [])}
        severity_counts = {b["key"]: b["doc_count"] for b in bucket.get("severities", {}).get("buckets", [])}
        ports = [str(b["key"]) for b in bucket.get("ports", {}).get("buckets", []) if b.get("key") not in ("", None)]
        samples = [h.get("_source", {}) for h in bucket.get("samples", {}).get("hits", {}).get("hits", [])]
        ml_raw = await r.get(f"ml:score:{ip}") if ip else None
        try:
            ml_score = json.loads(ml_raw) if ml_raw else {}
        except Exception:
            ml_score = {}
        alerts = await get_ip_alerts(ip) if ip else {"alerts": []}
        top_ips.append({
            "ip": ip,
            "events": int(bucket.get("doc_count", 0)),
            "driver": _primary_driver(threat_counts),
            "threat_counts": threat_counts,
            "severity_counts": severity_counts,
            "top_ports": ports,
            "last_seen": bucket.get("last_seen", {}).get("value_as_string"),
            "samples": samples,
            "risk_score": ml_score.get("risk_score"),
            "is_anomaly": ml_score.get("is_anomaly"),
            "alert_count": len(alerts.get("alerts", [])),
        })

    return {
        "source": "opensearch",
        "total_logs": total,
        "threat_counts": {b["key"]: b["doc_count"] for b in aggs.get("threats", {}).get("buckets", [])},
        "severity_counts": {b["key"]: b["doc_count"] for b in aggs.get("severities", {}).get("buckets", [])},
        "top_agents": {b["key"]: b["doc_count"] for b in aggs.get("agents", {}).get("buckets", [])},
        "top_ips": top_ips,
    }


async def _report_from_redis(r: aioredis.Redis) -> dict:
    stats = await get_stats()
    top_ips = []
    for ip in list(stats.get("hot_ips", []))[:10]:
        summary = await trail_summary(ip)
        ml_raw = await r.get(f"ml:score:{ip}")
        try:
            ml_score = json.loads(ml_raw) if ml_raw else {}
        except Exception:
            ml_score = {}
        top_ips.append({
            "ip": ip,
            "events": summary.get("total", 0),
            "driver": _primary_driver(summary.get("threat_types", {})),
            "threat_counts": summary.get("threat_types", {}),
            "severity_counts": summary.get("severities", {}),
            "top_ports": [],
            "last_seen": summary.get("last_seen"),
            "samples": [],
            "risk_score": ml_score.get("risk_score"),
            "is_anomaly": ml_score.get("is_anomaly"),
            "alert_count": 0,
        })
    return {
        "source": "redis",
        "total_logs": stats.get("total_logs", 0),
        "threat_counts": stats.get("threat_counts", {}),
        "severity_counts": {},
        "top_agents": {},
        "top_ips": top_ips,
    }


def _render_security_report(timeframe: str, start: datetime, end: datetime, data: dict, controls: dict) -> str:
    top_threats = _top_items(data.get("threat_counts", {}), 6)
    top_ips = data.get("top_ips", [])
    critical = int(data.get("severity_counts", {}).get("critical", 0) or 0)
    high = int(data.get("severity_counts", {}).get("high", 0) or 0)
    total = int(data.get("total_logs", 0) or 0)
    posture = "Elevated" if critical or high > 100 else "Active" if total else "No recent data"
    main_driver = top_threats[0][0].replace("_", " ") if top_threats else "no dominant threat type"

    lines = [
        f"# CyberSentinel {timeframe.capitalize()} Security Report",
        "",
        f"**Period:** {start.strftime('%Y-%m-%d %H:%M UTC')} to {end.strftime('%Y-%m-%d %H:%M UTC')}",
        f"**Data source:** {data.get('source', 'unknown')}",
        f"**Generated:** {end.isoformat()}",
        "",
        "## Executive Summary",
        f"- Posture: **{posture}**.",
        f"- Processed **{_human_count(total)}** security events in this period.",
        f"- Primary observed activity: **{main_driver}**.",
        f"- Severity pressure: **{_human_count(critical)} critical** and **{_human_count(high)} high** events.",
        f"- Current controls: **{_human_count(controls.get('auto_blocked'))} auto-blocked** and **{_human_count(controls.get('manual_blocked'))} manually blocked** indicators.",
        "",
        "## Threat Breakdown",
    ]

    if top_threats:
        lines.extend([f"- **{name.replace('_', ' ')}:** {_human_count(count)} events" for name, count in top_threats])
    else:
        lines.append("- No threat distribution available for this period.")

    lines.extend(["", "## Notable IP Activity"])
    if top_ips:
        lines.append("| IP | Events | Main activity | Severity | Risk | What happened |")
        lines.append("|---|---:|---|---|---:|---|")
        for item in top_ips[:8]:
            sev = ", ".join(f"{k}:{v}" for k, v in _top_items(item.get("severity_counts", {}), 2)) or "-"
            ports = ", ".join(item.get("top_ports", [])[:3]) or "not observed"
            sample_rule = ""
            for sample in item.get("samples", []):
                sample_rule = sample.get("rule") or sample.get("signature") or sample_rule
                if sample_rule:
                    break
            action = f"{item['ip']} generated {item['events']} events, mainly {item['driver']}"
            if ports != "not observed":
                action += f", touching ports {ports}"
            if sample_rule:
                action += f". Latest evidence: {sample_rule[:90]}"
            risk = item.get("risk_score")
            risk_text = str(risk) if risk is not None else "-"
            if item.get("is_anomaly"):
                risk_text += " anomaly"
            lines.append(f"| `{item['ip']}` | {_human_count(item['events'])} | {item['driver']} | {sev} | {risk_text} | {action} |")
    else:
        lines.append("- No high-signal IPs were available for this period.")

    lines.extend(["", "## Detection And Baseline Findings"])
    alert_counts = controls.get("alert_type_counts", {})
    if alert_counts:
        for name, count in _top_items(alert_counts, 6):
            lines.append(f"- **{name.replace('_', ' ')}:** {_human_count(count)} detections")
    else:
        lines.append("- No baseline deviation counts are currently available.")

    lines.extend(["", "## Recommended Actions"])
    if top_ips:
        lines.append(f"- Review the top IP `{top_ips[0]['ip']}` first because it has the highest event volume in this report window.")
    if critical or high:
        lines.append("- Validate whether critical/high events map to expected scanners, trusted agents, or external attackers; block or suppress only after ownership is confirmed.")
    if controls.get("auto_blocked", 0):
        lines.append("- Confirm auto-blocked indicators are enforced on the firewall, not only listed in CyberSentinel.")
    lines.append("- Keep this report with the incident notes; update the editable section before sharing if business context is known.")

    return "\n".join(lines) + "\n"


async def _generate_report_payload(timeframe: str) -> dict:
    days, start, end = _report_window(timeframe)
    r = await get_redis()
    data = await _report_from_opensearch(days, r) if OPENSEARCH_ENABLED else {}
    if not data:
        data = await _report_from_redis(r)
    blocklist_auto = await r.smembers("blocklist:auto")
    blocklist_manual = await r.smembers("blocklist:manual")
    stats = await get_stats()
    controls = {
        "auto_blocked": len(blocklist_auto),
        "manual_blocked": len(blocklist_manual),
        "alert_type_counts": stats.get("alert_type_counts", {}),
    }
    report = _render_security_report(timeframe, start, end, data, controls)
    return {
        "timeframe": timeframe,
        "period_days": days,
        "source": data.get("source"),
        "generated_by": "deterministic-cybersentinel-report-v1",
        "generated_at": end.isoformat(),
        "summary": {
            "total_logs": data.get("total_logs", 0),
            "top_threats": dict(_top_items(data.get("threat_counts", {}), 6)),
            "top_ips": data.get("top_ips", [])[:8],
            "auto_blocked": controls["auto_blocked"],
            "manual_blocked": controls["manual_blocked"],
        },
        "report": report,
    }


@app.get("/api/reports/generate")
async def generate_report(timeframe: str = "weekly"):
    return await _generate_report_payload(timeframe)


@app.get("/api/report/smart")
async def generate_smart_report(timeframe: str = "weekly"):
    return await _generate_report_payload(timeframe)




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
    os_status = "disabled"
    if OPENSEARCH_ENABLED:
        client = get_opensearch()
        if client:
            try:
                client.ping()
                os_status = "connected"
            except Exception:
                os_status = "error"
        else:
            os_status = "connection_failed"
    return {
        "status": "ok",
        "version": "2.2.0",
        "ai": "configured" if AI_API_KEY else "missing",
        "archive_dir": str(ARCHIVE_DIR),
        "trail_retain": TRAIL_RETAIN,
        "opensearch": os_status,
        "time": datetime.now(timezone.utc).isoformat(),
    }


# ── OpenSearch query endpoints ────────────────────────────────────────────────

@app.get("/api/trail/{ip}/full")
async def get_trail_full(ip: str, limit: int = 10000, days: int = 0):
    """Full IP trail from OpenSearch — complete history, not limited by Redis TRAIL_RETAIN."""
    if not OPENSEARCH_ENABLED:
        # Fallback: return Redis trail
        return await get_trail(ip, limit=limit)

    client = get_opensearch()
    if not client:
        return await get_trail(ip, limit=limit)

    query: dict = {
        "bool": {
            "must": [{"term": {"src_ip": ip}}]
        }
    }
    if days > 0:
        query["bool"]["filter"] = [
            {"range": {"@timestamp": {"gte": f"now-{days}d"}}}
        ]

    try:
        resp = client.search(
            index="cybersentinel-logs-*",
            body={
                "query": query,
                "sort": [{"@timestamp": {"order": "desc"}}],
                "size": min(limit, 10000),
            },
        )
        hits = resp.get("hits", {})
        total = hits.get("total", {}).get("value", 0)
        events = [hit["_source"] for hit in hits.get("hits", [])]

        # Use lightweight ipcnt counter instead of removed ipstat
        r = await get_redis()
        ipcnt = await r.get(f"ipcnt:{ip}")

        return {
            "ip": ip,
            "source": "opensearch",
            "total": total,
            "returned": len(events),
            "events": events,
            "stats": {"total": ipcnt or "0"},
        }
    except Exception as e:
        logger.error(f"OpenSearch query failed for {ip}: {e}")
        return await get_trail(ip, limit=limit)


@app.get("/api/opensearch/stats")
async def opensearch_stats():
    """OpenSearch index health, doc counts, and ILM phase info."""
    if not OPENSEARCH_ENABLED:
        return {"status": "disabled"}

    client = get_opensearch()
    if not client:
        return {"status": "connection_failed"}

    try:
        cat = client.cat.indices(index="cybersentinel-logs-*", format="json")
        indices = []
        total_docs = 0
        total_size = ""
        for idx in cat:
            doc_count = int(idx.get("docs.count", 0))
            total_docs += doc_count
            indices.append({
                "index": idx.get("index"),
                "docs": doc_count,
                "size": idx.get("store.size", "?"),
                "health": idx.get("health", "?"),
                "status": idx.get("status", "?"),
            })
            total_size = idx.get("store.size", total_size)

        # Check alias
        alias_targets = []
        try:
            alias_info = client.indices.get_alias(name=OS_INDEX_ALIAS)
            alias_targets = list(alias_info.keys())
        except Exception:
            pass

        # Pending buffer size
        with _os_lock:
            pending = len(_os_buffer)

        return {
            "status": "connected",
            "total_docs": total_docs,
            "indices": indices,
            "write_alias": OS_INDEX_ALIAS,
            "alias_targets": alias_targets,
            "pending_buffer": pending,
            "bulk_size": OS_BULK_SIZE,
            "flush_interval": OS_FLUSH_INTERVAL,
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


@app.post("/api/opensearch/flush")
async def opensearch_flush():
    """Manually flush the OpenSearch bulk buffer."""
    if not OPENSEARCH_ENABLED:
        return {"status": "disabled"}
    with _os_lock:
        count = len(_os_buffer)
        _flush_os_buffer_sync()
    return {"status": "flushed", "docs_flushed": count}


@app.get("/api/search/advanced")
async def advanced_search(
    q: str = "",
    src_ip: str = "",
    threat_type: str = "",
    severity: str = "",
    days: int = 7,
    limit: int = 200,
):
    """Advanced search across OpenSearch with filters."""
    if not OPENSEARCH_ENABLED:
        # Fallback to basic Redis search
        if src_ip:
            return await search_ip(src_ip)
        return {"error": "OpenSearch not enabled", "events": []}

    client = get_opensearch()
    if not client:
        return {"error": "OpenSearch connection failed", "events": []}

    must_clauses = []
    if q:
        must_clauses.append({"multi_match": {"query": q, "fields": ["rule", "signature", "username", "agent"]}})
    if src_ip:
        must_clauses.append({"term": {"src_ip": src_ip}})
    if threat_type:
        must_clauses.append({"term": {"threat_type": threat_type}})
    if severity:
        must_clauses.append({"term": {"severity": severity}})

    if not must_clauses:
        must_clauses.append({"match_all": {}})

    try:
        resp = client.search(
            index="cybersentinel-logs-*",
            body={
                "query": {
                    "bool": {
                        "must": must_clauses,
                        "filter": [{"range": {"@timestamp": {"gte": f"now-{days}d"}}}],
                    }
                },
                "sort": [{"@timestamp": {"order": "desc"}}],
                "size": min(limit, 10000),
            },
        )
        hits = resp.get("hits", {})
        total = hits.get("total", {}).get("value", 0)
        events = [hit["_source"] for hit in hits.get("hits", [])]
        return {"total": total, "returned": len(events), "events": events, "source": "opensearch"}
    except Exception as e:
        return {"error": str(e), "events": []}


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
