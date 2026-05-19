"""
CyberSentinel ML Intern

This service monitors Redis, decides when retraining is useful, creates
candidate Isolation Forest models, and waits for manual approval before a model
becomes active. It does not replace the backend or the existing ML engine.
"""
import json
import os
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import joblib
import numpy as np
import redis.asyncio as aioredis
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


app = FastAPI(title="CyberSentinel ML Intern", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))

MODEL_DIR = Path(os.getenv("ML_INTERN_MODEL_DIR", "./models"))
CANDIDATE_DIR = MODEL_DIR / "candidates"
REPORT_DIR = MODEL_DIR / "reports"
MODEL_DIR.mkdir(parents=True, exist_ok=True)
CANDIDATE_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)

CHECK_MINUTES = int(os.getenv("ML_INTERN_CHECK_MINUTES", "5"))
TIME_TRIGGER_HOURS = int(os.getenv("ML_INTERN_TIME_HOURS", "24"))
NEW_LOG_THRESHOLD = int(os.getenv("ML_INTERN_NEW_LOG_THRESHOLD", "10000"))
DRIFT_THRESHOLD = float(os.getenv("ML_INTERN_DRIFT_THRESHOLD", "0.35"))
STRONG_DRIFT_THRESHOLD = float(os.getenv("ML_INTERN_STRONG_DRIFT_THRESHOLD", str(DRIFT_THRESHOLD)))
MIN_TRAINING_IPS = int(os.getenv("ML_INTERN_MIN_TRAINING_IPS", "5"))

META_KEY = "ml_intern:models"
ACTIVE_KEY = "ml_intern:active_model"
LAST_TRAIN_KEY = "ml_intern:last_train"
LATEST_REPORT_KEY = "ml_intern:latest_report"

FEATURE_COLS = [
    "n_events", "event_rate_pm", "avg_interval_s", "min_interval_s",
    "std_interval_s", "unique_dst_ips", "unique_dst_ports", "unique_countries",
    "pct_critical", "pct_high", "brute_force_cnt", "ssh_bf_cnt",
    "rdp_cnt", "db_scan_cnt", "known_bad_cnt", "priv_esc_cnt",
    "vpn_bf_cnt", "baseline_alerts", "critical_alerts",
]

_redis: Optional[aioredis.Redis] = None
_scheduler: Optional[AsyncIOScheduler] = None
_running_job = False


async def get_redis() -> aioredis.Redis:
    global _redis
    if _redis is None:
        _redis = aioredis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
    try:
        await _redis.ping()
    except Exception:
        try:
            await _redis.aclose()
        except Exception:
            pass
        _redis = aioredis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
    return _redis


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def parse_dt(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return None


def safe_float(value, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return default


async def extract_ip_features(r: aioredis.Redis, ip: str) -> dict:
    """Build the same per-IP feature style used by the existing ML engine."""
    raw = await r.zrange(f"trail:{ip}", 0, -1, withscores=True)
    if not raw:
        return {}

    events = []
    for item, score in raw:
        try:
            event = json.loads(item)
            event["_score"] = score
            events.append(event)
        except Exception:
            continue

    if not events:
        return {}

    timestamps = sorted(event["_score"] for event in events)
    intervals = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]
    threat_counts = {}
    severities = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    dst_ips, dst_ports, countries = set(), set(), set()

    for event in events:
        threat_type = event.get("threat_type", "unknown")
        threat_counts[threat_type] = threat_counts.get(threat_type, 0) + 1

        severity = event.get("severity", "low")
        if severity in severities:
            severities[severity] += 1

        dst_ip = str(event.get("dst_ip", "")).strip()
        if dst_ip and dst_ip not in ("None", "nan"):
            dst_ips.add(dst_ip)

        dst_port = str(event.get("dst_port", "")).strip()
        if dst_port and dst_port not in ("None", "nan"):
            dst_ports.add(dst_port)

        country = str(event.get("country", "")).strip()
        if country and country not in ("None", "nan"):
            countries.add(country)

    n_events = len(events)
    window_seconds = (max(timestamps) - min(timestamps)) + 1
    alert_keys = await r.keys(f"alert:{ip}:*")
    critical_alerts = 0
    for key in alert_keys:
        try:
            alert = json.loads(await r.get(key) or "{}")
            if alert.get("severity") == "critical":
                critical_alerts += 1
        except Exception:
            continue

    return {
        "ip": ip,
        "n_events": n_events,
        "event_rate_pm": round(n_events / window_seconds * 60, 3),
        "avg_interval_s": round(float(np.mean(intervals)), 3) if intervals else 0,
        "min_interval_s": round(float(np.min(intervals)), 3) if intervals else 0,
        "std_interval_s": round(float(np.std(intervals)), 3) if intervals else 0,
        "unique_dst_ips": len(dst_ips),
        "unique_dst_ports": len(dst_ports),
        "unique_countries": len(countries),
        "pct_critical": round(severities["critical"] / n_events, 3),
        "pct_high": round(severities["high"] / n_events, 3),
        "brute_force_cnt": threat_counts.get("brute_force", 0),
        "ssh_bf_cnt": threat_counts.get("ssh_bruteforce", 0),
        "rdp_cnt": threat_counts.get("rdp_relay", 0),
        "db_scan_cnt": threat_counts.get("db_scan", 0),
        "known_bad_cnt": threat_counts.get("known_malicious", 0),
        "priv_esc_cnt": threat_counts.get("privilege_escalation", 0),
        "vpn_bf_cnt": threat_counts.get("vpn_bruteforce", 0),
        "baseline_alerts": len(alert_keys),
        "critical_alerts": critical_alerts,
    }


async def collect_training_features(r: aioredis.Redis) -> list[dict]:
    keys = await r.keys("trail:*")
    features = []
    for key in keys:
        ip = key.replace("trail:", "")
        row = await extract_ip_features(r, ip)
        if row:
            features.append(row)
    return features


def feature_matrix(features: list[dict]) -> np.ndarray:
    return np.array([[safe_float(row.get(col, 0)) for col in FEATURE_COLS] for row in features])


def summarize_distribution(features: list[dict]) -> dict:
    if not features:
        return {}
    summary = {}
    for col in FEATURE_COLS:
        vals = [safe_float(row.get(col, 0)) for row in features]
        summary[col] = {
            "mean": round(float(np.mean(vals)), 6),
            "std": round(float(np.std(vals)), 6),
        }
    return summary


def distribution_difference(current: dict, baseline: dict) -> float:
    """A simple normalized mean shift score across feature means."""
    if not current or not baseline:
        return 0.0
    diffs = []
    for col in FEATURE_COLS:
        cur = current.get(col, {}).get("mean", 0)
        old = baseline.get(col, {}).get("mean", 0)
        scale = max(abs(old), 1.0)
        diffs.append(abs(cur - old) / scale)
    return round(float(np.mean(diffs)), 4) if diffs else 0.0


async def current_log_count(r: aioredis.Redis) -> int:
    return int(await r.get("stat:total_logs") or 0)


async def get_model_metadata(r: aioredis.Redis) -> list[dict]:
    raw = await r.hgetall(META_KEY)
    models = []
    for value in raw.values():
        try:
            models.append(json.loads(value))
        except Exception:
            continue
    return sorted(models, key=lambda item: item.get("trained_at", ""), reverse=True)


async def save_model_metadata(r: aioredis.Redis, metadata: dict) -> None:
    await r.hset(META_KEY, metadata["model_id"], json.dumps(metadata))


async def clear_cached_ml_scores(r: aioredis.Redis) -> int:
    deleted = 0
    async for key in r.scan_iter(match="ml:score:*", count=500):
        deleted += await r.delete(key)
    return deleted


async def latest_training_metadata(r: aioredis.Redis) -> Optional[dict]:
    raw = await r.get(LAST_TRAIN_KEY)
    if raw:
        try:
            return json.loads(raw)
        except Exception:
            return None
    models = await get_model_metadata(r)
    return models[0] if models else None


async def active_model_metadata(r: aioredis.Redis) -> Optional[dict]:
    active_id = await r.get(ACTIVE_KEY)
    if not active_id:
        return None
    raw = await r.hget(META_KEY, active_id)
    if not raw:
        return None
    return json.loads(raw)


async def compute_trigger_state(r: aioredis.Redis, features: Optional[list[dict]] = None) -> dict:
    last_train = await latest_training_metadata(r)
    models = await get_model_metadata(r)
    pending_candidate_count = len([m for m in models if m.get("status") == "candidate"])
    total_logs = await current_log_count(r)
    current_summary = summarize_distribution(features or await collect_training_features(r))

    last_time = parse_dt(last_train.get("trained_at")) if last_train else None
    hours_since_train = None
    if last_time:
        hours_since_train = (utc_now() - last_time).total_seconds() / 3600

    last_log_count = int(last_train.get("total_logs_at_train", 0)) if last_train else 0
    new_logs_count = max(0, total_logs - last_log_count)
    drift_score = distribution_difference(current_summary, last_train.get("feature_summary", {}) if last_train else {})

    time_trigger = last_time is None or hours_since_train >= TIME_TRIGGER_HOURS
    data_trigger = new_logs_count >= NEW_LOG_THRESHOLD
    drift_trigger = drift_score >= DRIFT_THRESHOLD
    strong_drift_trigger = drift_score >= STRONG_DRIFT_THRESHOLD
    initial_model_needed = not models
    pending_candidate_exists = pending_candidate_count > 0
    should_retrain = initial_model_needed or (not pending_candidate_exists and strong_drift_trigger)

    return {
        "should_retrain": should_retrain,
        "time_trigger": time_trigger,
        "data_trigger": data_trigger,
        "drift_trigger": drift_trigger,
        "strong_drift_trigger": strong_drift_trigger,
        "initial_model_needed": initial_model_needed,
        "pending_candidate_exists": pending_candidate_exists,
        "pending_candidate_count": pending_candidate_count,
        "hours_since_train": round(hours_since_train, 2) if hours_since_train is not None else None,
        "new_logs_count": new_logs_count,
        "drift_score": drift_score,
        "total_logs": total_logs,
        "thresholds": {
            "time_hours": TIME_TRIGGER_HOURS,
            "new_logs": NEW_LOG_THRESHOLD,
            "drift": DRIFT_THRESHOLD,
            "strong_drift": STRONG_DRIFT_THRESHOLD,
            "check_minutes": CHECK_MINUTES,
        },
    }


def train_candidate(features: list[dict]) -> tuple[IsolationForest, StandardScaler, np.ndarray, np.ndarray]:
    X = feature_matrix(features)
    scaler = StandardScaler()
    Xs = scaler.fit_transform(X)
    model = IsolationForest(contamination=0.1, random_state=42, n_estimators=150)
    model.fit(Xs)
    predictions = model.predict(Xs)
    scores = model.decision_function(Xs)
    return model, scaler, predictions, scores


async def run_retraining_job(reason: str = "manual") -> dict:
    global _running_job
    if _running_job:
        return {"status": "already_running"}

    _running_job = True
    try:
        r = await get_redis()
        features = await collect_training_features(r)
        trigger_state = await compute_trigger_state(r, features)

        if len(features) < MIN_TRAINING_IPS:
            report = {
                "status": "not_enough_data",
                "reason": reason,
                "training_rows": len(features),
                "minimum_required": MIN_TRAINING_IPS,
                "created_at": utc_now().isoformat(),
            }
            await r.set(LATEST_REPORT_KEY, json.dumps(report))
            return report

        model, scaler, predictions, scores = train_candidate(features)
        anomaly_count = int(np.sum(predictions == -1))
        anomaly_rate = round(anomaly_count / len(features), 4)
        feature_summary = summarize_distribution(features)
        active = await active_model_metadata(r)
        distribution_diff = distribution_difference(feature_summary, active.get("feature_summary", {}) if active else {})

        score_shift = None
        active_model_path = MODEL_DIR / "isolation_forest.pkl"
        active_scaler_path = MODEL_DIR / "scaler.pkl"
        if active_model_path.exists() and active_scaler_path.exists():
            old_model = joblib.load(active_model_path)
            old_scaler = joblib.load(active_scaler_path)
            X = feature_matrix(features)
            old_scores = old_model.decision_function(old_scaler.transform(X))
            score_shift = round(float(abs(np.mean(scores) - np.mean(old_scores))), 4)

        model_id = "candidate-" + utc_now().strftime("%Y%m%d%H%M%S")
        model_dir = CANDIDATE_DIR / model_id
        model_dir.mkdir(parents=True, exist_ok=True)
        joblib.dump(model, model_dir / "isolation_forest.pkl")
        joblib.dump(scaler, model_dir / "scaler.pkl")

        report_summary = (
            f"Candidate trained on {len(features)} IP feature rows. "
            f"Anomaly rate {anomaly_rate:.2%}. Drift score {trigger_state['drift_score']}."
        )
        recommendation = "approve_after_review"
        if anomaly_rate > 0.35:
            recommendation = "review_anomaly_rate_before_approval"
        if distribution_diff > 1.0:
            recommendation = "review_distribution_shift_before_approval"

        metadata = {
            "model_id": model_id,
            "trained_at": utc_now().isoformat(),
            "training_rows": len(features),
            "total_logs_at_train": trigger_state["total_logs"],
            "anomaly_rate": anomaly_rate,
            "drift_score": trigger_state["drift_score"],
            "distribution_difference": distribution_diff,
            "score_shift": score_shift,
            "status": "candidate",
            "recommendation": recommendation,
            "report_summary": report_summary,
            "feature_summary": feature_summary,
            "trigger_state": trigger_state,
            "model_path": str(model_dir),
        }
        report = {
            **metadata,
            "reason": reason,
            "feature_columns": FEATURE_COLS,
            "top_anomaly_ips": [
                {"ip": features[i]["ip"], "score": round(float(scores[i]), 4)}
                for i in np.argsort(scores)[:10]
            ],
        }

        await save_model_metadata(r, metadata)
        await r.set(LAST_TRAIN_KEY, json.dumps(metadata))
        await r.set(LATEST_REPORT_KEY, json.dumps(report))
        (REPORT_DIR / f"{model_id}.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        return report
    finally:
        _running_job = False


async def scheduler_tick() -> None:
    r = await get_redis()
    state = await compute_trigger_state(r)
    await r.set("ml_intern:last_check", json.dumps({"checked_at": utc_now().isoformat(), **state}))
    if state["should_retrain"]:
        await run_retraining_job(reason="hybrid_scheduler")


@app.on_event("startup")
async def startup() -> None:
    global _scheduler
    _scheduler = AsyncIOScheduler(timezone="UTC")
    _scheduler.add_job(scheduler_tick, "interval", minutes=CHECK_MINUTES, max_instances=1)
    _scheduler.start()


@app.on_event("shutdown")
async def shutdown() -> None:
    if _scheduler:
        _scheduler.shutdown(wait=False)
    if _redis:
        await _redis.close()


@app.get("/health")
async def health():
    r = await get_redis()
    await r.ping()
    return {
        "status": "ok",
        "service": "ml-intern",
        "scheduler_running": bool(_scheduler and _scheduler.running),
        "time": utc_now().isoformat(),
    }


@app.get("/status")
async def status():
    r = await get_redis()
    last_check = await r.get("ml_intern:last_check")
    return {
        "service": "ml-intern",
        "active_model": await active_model_metadata(r),
        "latest_training": await latest_training_metadata(r),
        "latest_check": json.loads(last_check) if last_check else await compute_trigger_state(r),
        "running_job": _running_job,
    }


@app.post("/retrain")
async def manual_retrain():
    return await run_retraining_job(reason="manual_api")


@app.get("/models")
async def models():
    r = await get_redis()
    return {"models": await get_model_metadata(r), "active_model_id": await r.get(ACTIVE_KEY)}


@app.post("/approve-model/{model_id}")
async def approve_model(model_id: str):
    r = await get_redis()
    raw = await r.hget(META_KEY, model_id)
    if not raw:
        raise HTTPException(404, "Model not found")

    metadata = json.loads(raw)
    model_dir = Path(metadata.get("model_path", ""))
    model_path = model_dir / "isolation_forest.pkl"
    scaler_path = model_dir / "scaler.pkl"
    if not model_path.exists() or not scaler_path.exists():
        raise HTTPException(404, "Candidate model files are missing")

    previous = await active_model_metadata(r)
    if previous:
        previous["status"] = "previous"
        await save_model_metadata(r, previous)

    shutil.copy2(model_path, MODEL_DIR / "isolation_forest.pkl")
    shutil.copy2(scaler_path, MODEL_DIR / "scaler.pkl")

    metadata["status"] = "active"
    metadata["approved_at"] = utc_now().isoformat()
    await save_model_metadata(r, metadata)
    await r.set(ACTIVE_KEY, model_id)
    last_train = await r.get(LAST_TRAIN_KEY)
    if last_train:
        try:
            last_train_metadata = json.loads(last_train)
            if last_train_metadata.get("model_id") == model_id:
                await r.set(LAST_TRAIN_KEY, json.dumps(metadata))
        except Exception:
            pass
    cleared_scores = await clear_cached_ml_scores(r)
    return {
        "status": "approved",
        "active_model": metadata,
        "previous_model": previous,
        "cleared_ml_scores": cleared_scores,
    }


@app.post("/rollback")
async def rollback():
    r = await get_redis()
    models = await get_model_metadata(r)
    active_id = await r.get(ACTIVE_KEY)
    previous_models = [m for m in models if m.get("model_id") != active_id and m.get("status") in ("previous", "active")]
    if not previous_models:
        raise HTTPException(404, "No previous model available for rollback")

    target = previous_models[0]
    model_dir = Path(target.get("model_path", ""))
    model_path = model_dir / "isolation_forest.pkl"
    scaler_path = model_dir / "scaler.pkl"
    if not model_path.exists() or not scaler_path.exists():
        raise HTTPException(404, "Rollback model files are missing")

    active = await active_model_metadata(r)
    if active:
        active["status"] = "candidate"
        active["rolled_back_at"] = utc_now().isoformat()
        await save_model_metadata(r, active)

    shutil.copy2(model_path, MODEL_DIR / "isolation_forest.pkl")
    shutil.copy2(scaler_path, MODEL_DIR / "scaler.pkl")
    target["status"] = "active"
    target["rollback_activated_at"] = utc_now().isoformat()
    await save_model_metadata(r, target)
    await r.set(ACTIVE_KEY, target["model_id"])
    cleared_scores = await clear_cached_ml_scores(r)
    return {"status": "rolled_back", "active_model": target, "cleared_ml_scores": cleared_scores}


@app.get("/reports/latest")
async def latest_report():
    r = await get_redis()
    raw = await r.get(LATEST_REPORT_KEY)
    if not raw:
        return {"status": "none", "message": "No training report has been generated yet."}
    return json.loads(raw)
