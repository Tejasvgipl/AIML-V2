"""
CyberSentinel — OpenSearch client helpers
Shared by backend, ml-engine, ml-intern.

Provides synchronous helpers (safe to call from any context).
The backend also uses the async bulk buffer for ingestion.
"""
import os
import logging
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("cybersentinel.os_client")

OPENSEARCH_ENABLED = os.getenv("OPENSEARCH_ENABLED", "false").lower() in ("true", "1", "yes")
OPENSEARCH_HOST    = os.getenv("OPENSEARCH_HOST", "localhost")
OPENSEARCH_PORT    = int(os.getenv("OPENSEARCH_PORT", 9200))
OPENSEARCH_USER    = os.getenv("OPENSEARCH_USER", "admin")
OPENSEARCH_PASS    = os.getenv("OPENSEARCH_PASS", "admin")
OS_INDEX_PATTERN   = "cybersentinel-logs-*"
OS_INDEX_ALIAS     = "cybersentinel-logs"

_client = None


def get_client():
    """Lazy singleton OpenSearch client with HTTPS + self-signed cert support."""
    global _client
    if _client is not None:
        return _client
    if not OPENSEARCH_ENABLED:
        return None
    try:
        from opensearchpy import OpenSearch
        _client = OpenSearch(
            hosts=[{"host": OPENSEARCH_HOST, "port": OPENSEARCH_PORT}],
            http_auth=(OPENSEARCH_USER, OPENSEARCH_PASS),
            use_ssl=True,
            verify_certs=False,
            ssl_show_warn=False,
            timeout=30,
        )
        info = _client.info()
        ver  = info.get("version", {}).get("number", "?")
        logger.info(f"OpenSearch connected: v{ver} at {OPENSEARCH_HOST}:{OPENSEARCH_PORT}")
        return _client
    except Exception as e:
        logger.warning(f"OpenSearch unavailable: {e} — running Redis-only mode")
        _client = None
        return None


# ── IP event queries ──────────────────────────────────────────────────────────

def get_ip_events(ip: str, limit: int = 500, days: int = 0) -> list[dict]:
    """Fetch events for a given IP from OpenSearch, oldest-first."""
    client = get_client()
    if not client:
        return []
    query: dict = {"bool": {"must": [{"term": {"src_ip": ip}}]}}
    if days > 0:
        query["bool"]["filter"] = [{"range": {"@timestamp": {"gte": f"now-{days}d"}}}]
    try:
        resp = client.search(
            index=OS_INDEX_PATTERN,
            body={
                "query": query,
                "sort":  [{"@timestamp": {"order": "asc"}}],
                "size":  min(limit, 10000),
            },
        )
        hits = resp.get("hits", {}).get("hits", [])
        events = []
        for h in hits:
            src = h["_source"]
            # Convert @timestamp string to a float _ts for baseline compat
            try:
                src["_ts"] = datetime.fromisoformat(
                    src.get("@timestamp", "").replace("Z", "+00:00")
                ).timestamp()
            except Exception:
                src["_ts"] = 0.0
            events.append(src)
        return events
    except Exception as e:
        logger.error(f"get_ip_events({ip}) failed: {e}")
        return []


def get_ip_events_desc(ip: str, limit: int = 100, days: int = 0) -> list[dict]:
    """Fetch events newest-first (for trail display)."""
    client = get_client()
    if not client:
        return []
    query: dict = {"bool": {"must": [{"term": {"src_ip": ip}}]}}
    if days > 0:
        query["bool"]["filter"] = [{"range": {"@timestamp": {"gte": f"now-{days}d"}}}]
    try:
        resp = client.search(
            index=OS_INDEX_PATTERN,
            body={
                "query": query,
                "sort":  [{"@timestamp": {"order": "desc"}}],
                "size":  min(limit, 10000),
            },
        )
        return [h["_source"] for h in resp.get("hits", {}).get("hits", [])]
    except Exception as e:
        logger.error(f"get_ip_events_desc({ip}) failed: {e}")
        return []


def get_ip_total_count(ip: str) -> int:
    """Total event count for an IP in OpenSearch."""
    client = get_client()
    if not client:
        return 0
    try:
        resp = client.count(
            index=OS_INDEX_PATTERN,
            body={"query": {"term": {"src_ip": ip}}},
        )
        return resp.get("count", 0)
    except Exception as e:
        logger.error(f"get_ip_total_count({ip}) failed: {e}")
        return 0


def get_ip_first_last_seen(ip: str) -> tuple[Optional[str], Optional[str]]:
    """Return (first_seen_iso, last_seen_iso) for an IP."""
    client = get_client()
    if not client:
        return None, None
    try:
        resp = client.search(
            index=OS_INDEX_PATTERN,
            body={
                "size": 0,
                "query": {"term": {"src_ip": ip}},
                "aggs": {
                    "first": {"min": {"field": "@timestamp"}},
                    "last":  {"max": {"field": "@timestamp"}},
                },
            },
        )
        aggs = resp.get("aggregations", {})
        return (
            aggs.get("first", {}).get("value_as_string"),
            aggs.get("last",  {}).get("value_as_string"),
        )
    except Exception as e:
        logger.error(f"get_ip_first_last_seen({ip}) failed: {e}")
        return None, None


def get_ip_threat_counts(ip: str) -> dict:
    """Threat type → count for an IP via aggregation."""
    client = get_client()
    if not client:
        return {}
    try:
        resp = client.search(
            index=OS_INDEX_PATTERN,
            body={
                "size": 0,
                "query": {"term": {"src_ip": ip}},
                "aggs": {"threats": {"terms": {"field": "threat_type", "size": 50}}},
            },
        )
        buckets = resp.get("aggregations", {}).get("threats", {}).get("buckets", [])
        return {b["key"]: b["doc_count"] for b in buckets}
    except Exception:
        return {}


def get_ip_severity_counts(ip: str) -> dict:
    """Severity → count for an IP via aggregation."""
    client = get_client()
    if not client:
        return {}
    try:
        resp = client.search(
            index=OS_INDEX_PATTERN,
            body={
                "size": 0,
                "query": {"term": {"src_ip": ip}},
                "aggs": {"sevs": {"terms": {"field": "severity", "size": 10}}},
            },
        )
        buckets = resp.get("aggregations", {}).get("sevs", {}).get("buckets", [])
        return {b["key"]: b["doc_count"] for b in buckets}
    except Exception:
        return {}


# ── All-IPs queries ───────────────────────────────────────────────────────────

def get_all_unique_ips(size: int = 10000) -> list[str]:
    """All unique src_ip values in OpenSearch."""
    client = get_client()
    if not client:
        return []
    try:
        resp = client.search(
            index=OS_INDEX_PATTERN,
            body={
                "size": 0,
                "aggs": {"ips": {"terms": {"field": "src_ip", "size": size}}},
            },
        )
        buckets = resp.get("aggregations", {}).get("ips", {}).get("buckets", [])
        return [b["key"] for b in buckets]
    except Exception as e:
        logger.error(f"get_all_unique_ips failed: {e}")
        return []


def get_hot_ips_from_os(size: int = 100) -> list[str]:
    """IPs with critical/high severity events — for hot_ips rebuild."""
    client = get_client()
    if not client:
        return []
    try:
        resp = client.search(
            index=OS_INDEX_PATTERN,
            body={
                "size": 0,
                "query": {"terms": {"severity": ["critical", "high"]}},
                "aggs": {"hot": {"terms": {"field": "src_ip", "size": size}}},
            },
        )
        buckets = resp.get("aggregations", {}).get("hot", {}).get("buckets", [])
        return [b["key"] for b in buckets]
    except Exception:
        return []


def get_global_threat_counts() -> dict:
    """Global threat type distribution across all logs."""
    client = get_client()
    if not client:
        return {}
    try:
        resp = client.search(
            index=OS_INDEX_PATTERN,
            body={
                "size": 0,
                "aggs": {"threats": {"terms": {"field": "threat_type", "size": 50}}},
            },
        )
        buckets = resp.get("aggregations", {}).get("threats", {}).get("buckets", [])
        return {b["key"]: b["doc_count"] for b in buckets}
    except Exception:
        return {}


def get_total_doc_count() -> int:
    """Total documents across all cybersentinel-logs-* indices."""
    client = get_client()
    if not client:
        return 0
    try:
        resp = client.count(index=OS_INDEX_PATTERN)
        return resp.get("count", 0)
    except Exception:
        return 0


def get_index_stats() -> dict:
    """Index health, doc counts, sizes."""
    client = get_client()
    if not client:
        return {"status": "disabled"}
    try:
        cat = client.cat.indices(index="cybersentinel-logs-*", format="json")
        indices = []
        total_docs = 0
        for idx in cat:
            dc = int(idx.get("docs.count", 0) or 0)
            total_docs += dc
            indices.append({
                "index":  idx.get("index"),
                "docs":   dc,
                "size":   idx.get("store.size", "?"),
                "health": idx.get("health", "?"),
                "status": idx.get("status", "?"),
            })
        alias_targets = []
        try:
            alias_info = client.indices.get_alias(name=OS_INDEX_ALIAS)
            alias_targets = list(alias_info.keys())
        except Exception:
            pass
        return {
            "status":        "connected",
            "total_docs":    total_docs,
            "indices":       indices,
            "write_alias":   OS_INDEX_ALIAS,
            "alias_targets": alias_targets,
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


# ── ML feature extraction (shared with ml-engine and ml-intern) ───────────────

FEATURE_COLS = [
    "n_events", "event_rate_pm", "avg_interval_s", "min_interval_s",
    "std_interval_s", "unique_dst_ips", "unique_dst_ports", "unique_countries",
    "pct_critical", "pct_high", "brute_force_cnt", "ssh_bf_cnt",
    "rdp_cnt", "db_scan_cnt", "known_bad_cnt", "priv_esc_cnt",
    "vpn_bf_cnt", "baseline_alerts", "critical_alerts",
]


def extract_features_from_events(ip: str, events: list[dict]) -> dict:
    """
    Compute ML feature vector from a list of OpenSearch event dicts.
    Events must have _ts (float unix timestamp) — added by get_ip_events().
    """
    if not events:
        return {}

    import numpy as np

    timestamps = sorted(e.get("_ts", 0.0) for e in events)
    n = len(events)
    intervals = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]

    threat_counts: dict = {}
    severities = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    dst_ips: set = set()
    dst_ports: set = set()
    countries: set = set()

    for e in events:
        tt = e.get("threat_type", "unknown")
        threat_counts[tt] = threat_counts.get(tt, 0) + 1
        sev = e.get("severity", "low")
        if sev in severities:
            severities[sev] += 1
        dip = str(e.get("dst_ip", "")).strip()
        if dip and dip not in ("", "None", "nan"):
            dst_ips.add(dip)
        dp = str(e.get("dst_port", "")).strip()
        if dp and dp not in ("", "None", "nan"):
            dst_ports.add(dp)
        c = str(e.get("country", "")).strip()
        if c and c not in ("", "None", "nan"):
            countries.add(c)

    window_seconds = (max(timestamps) - min(timestamps)) + 1
    event_rate = n / window_seconds * 60

    return {
        "ip":               ip,
        "n_events":         n,
        "event_rate_pm":    round(event_rate, 3),
        "avg_interval_s":   round(float(np.mean(intervals)), 3)  if intervals else 0,
        "min_interval_s":   round(float(np.min(intervals)), 3)   if intervals else 0,
        "std_interval_s":   round(float(np.std(intervals)), 3)   if intervals else 0,
        "unique_dst_ips":   len(dst_ips),
        "unique_dst_ports": len(dst_ports),
        "unique_countries": len(countries),
        "pct_critical":     round(severities["critical"] / n, 3),
        "pct_high":         round(severities["high"] / n, 3),
        "brute_force_cnt":  threat_counts.get("brute_force", 0),
        "ssh_bf_cnt":       threat_counts.get("ssh_bruteforce", 0),
        "rdp_cnt":          threat_counts.get("rdp_relay", 0),
        "db_scan_cnt":      threat_counts.get("db_scan", 0),
        "known_bad_cnt":    threat_counts.get("known_malicious", 0),
        "priv_esc_cnt":     threat_counts.get("privilege_escalation", 0),
        "vpn_bf_cnt":       threat_counts.get("vpn_bruteforce", 0),
        "baseline_alerts":  0,   # caller injects from Redis
        "critical_alerts":  0,   # caller injects from Redis
    }


def get_ip_features(ip: str, baseline_alerts: int = 0, critical_alerts: int = 0) -> dict:
    """Full feature vector for an IP — fetches events from OpenSearch."""
    events = get_ip_events(ip, limit=2000)
    if not events:
        return {}
    f = extract_features_from_events(ip, events)
    f["baseline_alerts"] = baseline_alerts
    f["critical_alerts"]  = critical_alerts
    return f


def get_all_ip_features(alert_counts: Optional[dict] = None) -> list[dict]:
    """
    Feature vectors for every IP in OpenSearch.
    alert_counts = {ip: {"baseline_alerts": N, "critical_alerts": M}}
    """
    ips = get_all_unique_ips()
    features = []
    for ip in ips:
        events = get_ip_events(ip, limit=2000)
        if not events:
            continue
        f = extract_features_from_events(ip, events)
        if not f:
            continue
        ac = (alert_counts or {}).get(ip, {})
        f["baseline_alerts"] = ac.get("baseline_alerts", 0)
        f["critical_alerts"]  = ac.get("critical_alerts", 0)
        features.append(f)
    return features
