"""
CyberSentinel ML Engine v2.0
- Isolation Forest: anomaly detection per IP
- Subnet clustering: coordinated attack groups
- Baseline comparison: behavioural shift scoring
- Risk scorer: combined 0-100 risk per IP
"""
import os, json, joblib, statistics
from datetime import datetime, timezone
from pathlib import Path
import sys
import numpy as np
import redis.asyncio as aioredis
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import networkx as nx
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Import shared OpenSearch client (same directory as this file in Docker)
sys.path.insert(0, "/app")
try:
    import opensearch_client as osc
    OS_ENABLED = osc.OPENSEARCH_ENABLED
except ImportError:
    osc = None
    OS_ENABLED = False

app = FastAPI(title="CyberSentinel ML Engine", version="2.1.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

REDIS_HOST = os.getenv("REDIS_HOST","localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
MODEL_DIR  = Path(os.getenv("MODEL_DIR", "./models"))
MODEL_DIR.mkdir(parents=True, exist_ok=True)

_redis = None

async def get_redis():
    global _redis
    if _redis is None:
        _redis = aioredis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
    return _redis

# ── feature extraction ────────────────────────────────────────────────────────
# Primary source: OpenSearch (full event history per IP)
# Fallback: Redis trail:{ip} (legacy, used when OpenSearch is disabled)

FEATURE_COLS = [
    "n_events","event_rate_pm","avg_interval_s","min_interval_s",
    "std_interval_s","unique_dst_ips","unique_dst_ports","unique_countries",
    "pct_critical","pct_high","brute_force_cnt","ssh_bf_cnt",
    "rdp_cnt","db_scan_cnt","known_bad_cnt","priv_esc_cnt",
    "vpn_bf_cnt","baseline_alerts","critical_alerts",
]

async def _get_alert_counts(r: aioredis.Redis, ip: str) -> tuple[int, int]:
    """Return (baseline_alert_count, critical_alert_count) from Redis."""
    alert_keys = await r.keys(f"alert:{ip}:*")
    baseline_alerts = len(alert_keys)
    critical_alerts = 0
    for key in alert_keys:
        val = await r.get(key)
        if val:
            try:
                a = json.loads(val)
                if a.get("severity") == "critical":
                    critical_alerts += 1
            except Exception:
                pass
    return baseline_alerts, critical_alerts

async def extract_ip_features(r: aioredis.Redis, ip: str) -> dict:
    """Extract feature vector for an IP. Uses OpenSearch if enabled, Redis trail otherwise."""
    baseline_alerts, critical_alerts = await _get_alert_counts(r, ip)

    # --- OpenSearch path (preferred) ---
    if OS_ENABLED and osc:
        events = osc.get_ip_events(ip, limit=2000)
        if not events:
            return {}
        f = osc.extract_features_from_events(ip, events)
        if not f:
            return {}
        f["baseline_alerts"] = baseline_alerts
        f["critical_alerts"]  = critical_alerts
        return f

    # --- Legacy Redis path (fallback) ---
    raw = await r.zrange(f"trail:{ip}", 0, -1, withscores=True)
    if not raw:
        return {}

    events = []
    for item, score in raw:
        try:
            e = json.loads(item)
            e["_score"] = score
            events.append(e)
        except Exception:
            pass

    if not events:
        return {}

    timestamps = sorted(e["_score"] for e in events)
    n = len(events)
    intervals  = [timestamps[i+1]-timestamps[i] for i in range(len(timestamps)-1)]

    avg_interval = float(np.mean(intervals))   if intervals else 0
    min_interval = float(np.min(intervals))    if intervals else 0
    std_interval = float(np.std(intervals))    if intervals else 0

    threat_counts = {}
    severities    = {"critical":0,"high":0,"medium":0,"low":0}
    dst_ips       = set()
    dst_ports     = set()
    countries     = set()

    for e in events:
        tt = e.get("threat_type","unknown")
        threat_counts[tt] = threat_counts.get(tt,0) + 1
        sev = e.get("severity","low")
        if sev in severities:
            severities[sev] += 1

        dip = str(e.get("dst_ip","")).strip()
        if dip and dip not in ("","None","nan"):
            dst_ips.add(dip)

        dp = str(e.get("dst_port","")).strip()
        if dp and dp not in ("","None","nan"):
            dst_ports.add(dp)

        c = str(e.get("country","")).strip()
        if c and c not in ("","None","nan"):
            countries.add(c)

    window_seconds = (max(timestamps)-min(timestamps)) + 1
    event_rate     = n / window_seconds * 60

    return {
        "ip":                   ip,
        "n_events":             n,
        "event_rate_pm":        round(event_rate, 3),
        "avg_interval_s":       round(avg_interval, 3),
        "min_interval_s":       round(min_interval, 3),
        "std_interval_s":       round(std_interval, 3),
        "unique_dst_ips":       len(dst_ips),
        "unique_dst_ports":     len(dst_ports),
        "unique_countries":     len(countries),
        "pct_critical":         round(severities["critical"]/n, 3),
        "pct_high":             round(severities["high"]/n, 3),
        "brute_force_cnt":      threat_counts.get("brute_force", 0),
        "ssh_bf_cnt":           threat_counts.get("ssh_bruteforce", 0),
        "rdp_cnt":              threat_counts.get("rdp_relay", 0),
        "db_scan_cnt":          threat_counts.get("db_scan", 0),
        "known_bad_cnt":        threat_counts.get("known_malicious", 0),
        "priv_esc_cnt":         threat_counts.get("privilege_escalation", 0),
        "vpn_bf_cnt":           threat_counts.get("vpn_bruteforce", 0),
        "baseline_alerts":      baseline_alerts,
        "critical_alerts":      critical_alerts,
        "window_minutes":       round(window_seconds/60, 2),
    }

    "std_interval_s","unique_dst_ips","unique_dst_ports","unique_countries",
    "pct_critical","pct_high","brute_force_cnt","ssh_bf_cnt",
    "rdp_cnt","db_scan_cnt","known_bad_cnt","priv_esc_cnt",
    "vpn_bf_cnt","baseline_alerts","critical_alerts",
]

# ── baseline deviation summary per IP ─────────────────────────────────────────

async def get_baseline_deviation_summary(r: aioredis.Redis, ip: str) -> dict:
    """Returns a human-readable summary of all baseline deviations for an IP."""
    raw_baseline = await r.get(f"baseline:{ip}")
    alert_keys   = await r.keys(f"alert:{ip}:*")

    alerts = []
    for key in alert_keys:
        val = await r.get(key)
        if val:
            try:
                alerts.append(json.loads(val))
            except Exception:
                pass

    alerts.sort(key=lambda x: x.get("ts",""), reverse=True)

    deviation_score = 0
    for a in alerts:
        deviation_score += {"critical":10,"high":5,"medium":2,"low":1}.get(a.get("severity","low"),1)

    return {
        "ip":              ip,
        "has_baseline":    raw_baseline is not None,
        "alert_count":     len(alerts),
        "deviation_score": deviation_score,
        "alerts":          alerts[:10],
        "alert_types":     list({a["type"] for a in alerts}),
    }

# ── train / load ──────────────────────────────────────────────────────────────

async def get_all_ip_features(r: aioredis.Redis):
    keys     = await r.keys("trail:*")
    ips      = [k.replace("trail:","") for k in keys]
    features = []
    for ip in ips:
        f = await extract_ip_features(r, ip)
        if f:
            features.append(f)
    return features

def train_isolation_forest(features: list) -> tuple:
    if len(features) < 5:
        return None, None
    X      = np.array([[f.get(c,0) for c in FEATURE_COLS] for f in features])
    scaler = StandardScaler()
    Xs     = scaler.fit_transform(X)
    model  = IsolationForest(contamination=0.1, random_state=42, n_estimators=150)
    model.fit(Xs)
    return model, scaler


async def score_and_cache_features(r: aioredis.Redis, model, scaler, features: list[dict]) -> list[dict]:
    if not features:
        return []

    X  = np.array([[f.get(c,0) for c in FEATURE_COLS] for f in features])
    Xs = scaler.transform(X)
    raw_scores = model.decision_function(Xs)

    anomalies = []
    for i, f in enumerate(features):
        score  = float(raw_scores[i])
        is_anom = bool(model.predict(Xs[i:i+1])[0] == -1)
        risk    = max(0, min(100, int((1-(score+0.5))*100)))

        baseline_alerts = f.get("baseline_alerts", 0)
        critical_alerts = f.get("critical_alerts", 0)
        risk = min(100, risk + baseline_alerts * 2 + critical_alerts * 5)

        await r.set(f"ml:score:{f['ip']}",
            json.dumps({"anomaly_score":round(score,4),"is_anomaly":is_anom,"risk_score":risk}))
        if is_anom:
            anomalies.append({"ip":f["ip"],"score":round(score,4),"risk":risk})

    return anomalies

@app.post("/api/ml/train")
async def train_model():
    r        = await get_redis()
    features = await get_all_ip_features(r)
    if len(features) < 5:
        return {"status":"not_enough_data","ip_count":len(features)}

    model, scaler = train_isolation_forest(features)
    if model is None:
        return {"status":"training_failed"}

    joblib.dump(model,  MODEL_DIR/"isolation_forest.pkl")
    joblib.dump(scaler, MODEL_DIR/"scaler.pkl")

    anomalies = await score_and_cache_features(r, model, scaler, features)

    return {
        "status":        "trained",
        "ip_count":      len(features),
        "anomalies":     len(anomalies),
        "top_anomalies": sorted(anomalies, key=lambda x: x["risk"], reverse=True)[:10],
    }

# ── score single IP ───────────────────────────────────────────────────────────

@app.get("/api/ml/score/{ip}")
async def score_ip(ip: str):
    r = await get_redis()

    cached = await r.get(f"ml:score:{ip}")
    if cached:
        data = json.loads(cached)
        data["ip"]     = ip
        data["source"] = "cached"
        if "features" not in data:
            features = await extract_ip_features(r, ip)
            if features:
                data["features"] = features
        return data

    features = await extract_ip_features(r, ip)
    if not features:
        return {"ip":ip,"found":False}

    model_path  = MODEL_DIR/"isolation_forest.pkl"
    scaler_path = MODEL_DIR/"scaler.pkl"

    if not model_path.exists():
        return {
            "ip":ip,"features":features,
            "anomaly_score":None,
            "note":"Model not trained yet. POST /api/ml/train first.",
        }

    model  = joblib.load(model_path)
    scaler = joblib.load(scaler_path)
    x  = np.array([[features.get(c,0) for c in FEATURE_COLS]])
    xs = scaler.transform(x)
    score   = float(model.decision_function(xs)[0])
    is_anom = bool(model.predict(xs)[0] == -1)
    risk    = max(0, min(100, int((1-(score+0.5))*100)))

    # Boost from baseline alerts
    risk = min(100, risk + features.get("baseline_alerts",0)*2 + features.get("critical_alerts",0)*5)

    result = {
        "ip":            ip,
        "anomaly_score": round(score,4),
        "risk_score":    risk,
        "is_anomaly":    is_anom,
        "features":      features,
        "source":        "live",
    }
    await r.set(f"ml:score:{ip}",
        json.dumps({k:v for k,v in result.items() if k!="ip"}))
    return result

# ── baseline deviation report ─────────────────────────────────────────────────

@app.get("/api/ml/baseline/{ip}")
async def ml_baseline_report(ip: str):
    r = await get_redis()
    return await get_baseline_deviation_summary(r, ip)

@app.get("/api/ml/baseline-alerts")
async def all_baseline_alerts():
    """All IPs that have triggered baseline deviation alerts."""
    r    = await get_redis()
    keys = await r.keys("alert:*:*")
    ip_set = set()
    for key in keys:
        parts = key.split(":")
        if len(parts) >= 2:
            ip_set.add(parts[1])

    results = []
    for ip in ip_set:
        summary = await get_baseline_deviation_summary(r, ip)
        results.append(summary)

    results.sort(key=lambda x: x.get("deviation_score",0), reverse=True)
    return {"total":len(results),"ips":results[:50]}

# ── subnet clustering ─────────────────────────────────────────────────────────

@app.get("/api/ml/clusters")
async def get_clusters():
    r    = await get_redis()
    keys = await r.keys("trail:*")
    ips  = [k.replace("trail:","") for k in keys]
    G    = nx.Graph()

    subnets: dict[str,list] = {}
    for ip in ips:
        parts = ip.split(".")
        if len(parts) == 4:
            sn = ".".join(parts[:3])
            subnets.setdefault(sn,[]).append(ip)

    for sn, sn_ips in subnets.items():
        if len(sn_ips) > 1:
            for ip in sn_ips:
                G.add_node(ip, subnet=sn)
            for i in range(len(sn_ips)):
                for j in range(i+1, len(sn_ips)):
                    G.add_edge(sn_ips[i], sn_ips[j], weight=1)

    clusters = []
    for component in nx.connected_components(G):
        if len(component) > 1:
            ips_list     = list(component)
            subnet_key   = ".".join(ips_list[0].split(".")[:3]) + ".x/24"
            total_events = 0
            total_alerts = 0
            for ip in ips_list:
                stat = await r.hget(f"ipstat:{ip}","total")
                total_events += int(stat or 0)
                ak = await r.keys(f"alert:{ip}:*")
                total_alerts += len(ak)

            clusters.append({
                "subnet":       subnet_key,
                "ip_count":     len(ips_list),
                "ips":          ips_list[:20],
                "total_events": total_events,
                "total_alerts": total_alerts,
                "threat_level": "critical" if total_events > 500 else "high" if total_events > 100 else "medium",
            })

    clusters.sort(key=lambda x: x["total_events"], reverse=True)
    return {"clusters":clusters,"total_subnets":len(subnets)}

# ── anomaly list ──────────────────────────────────────────────────────────────

@app.get("/api/ml/anomalies")
async def list_anomalies():
    r    = await get_redis()
    keys = await r.keys("ml:score:*")
    if not keys:
        model_path  = MODEL_DIR/"isolation_forest.pkl"
        scaler_path = MODEL_DIR/"scaler.pkl"
        if model_path.exists() and scaler_path.exists():
            features = await get_all_ip_features(r)
            if features:
                model  = joblib.load(model_path)
                scaler = joblib.load(scaler_path)
                await score_and_cache_features(r, model, scaler, features)
                keys = await r.keys("ml:score:*")

    anomalies = []
    for key in keys:
        val = await r.get(key)
        if val:
            data = json.loads(val)
            if data.get("is_anomaly"):
                ip = key.replace("ml:score:","")
                anomalies.append({"ip":ip,**data})
    anomalies.sort(key=lambda x: x.get("risk_score",0), reverse=True)
    return {"anomalies":anomalies}

@app.get("/api/ml/health")
async def ml_health():
    model_ready = (MODEL_DIR/"isolation_forest.pkl").exists()
    return {"status":"ok","model_ready":model_ready,"version":"2.0.0",
            "time":datetime.now(timezone.utc).isoformat()}
