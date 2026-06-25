"""
CyberSentinel — STIX2-style IOC enrichment (IP -> actor / campaign / malware)
=============================================================================
Adds threat-intel *relationships* to an IP, the way MISP / OpenCTI do: an
observable (IP) linked to indicators, threat actors, campaigns and malware, each
with a confidence and a SOURCE so the analyst can trust or discount it.

Honesty first (a core CyberSentinel principle): we NEVER invent attribution. An
IP only gets an actor/campaign if it comes from:
  1. A live MISP or OpenCTI instance (when configured via env), or
  2. The local curated IOC store (data/ioc_store.json), or
  3. The internal known-bad list (provenance = "internal blocklist", no actor).

Works fully air-gapped: with nothing configured it still returns honest internal
provenance and "no external attribution available".

Local store format (data/ioc_store.json) — a list of STIX-lite objects:
  {
    "indicator": "85.11.182.0/24" | "1.2.3.4",
    "type": "ipv4-addr",
    "actor": "FIN7", "campaign": "Carbanak", "malware": "Cobalt Strike",
    "confidence": 80, "source": "MISP:internal", "tlp": "amber",
    "references": ["https://..."], "first_seen": "2026-01-01"
  }
"""
from __future__ import annotations
import os
import json
import ipaddress
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger("cybersentinel.ioc_intel")

# Prefer an analyst-managed file in the data volume; fall back to the bundled
# seed in sample-data (version-controlled) so the feature works out of the box.
def _resolve_store_file() -> Path:
    env = os.getenv("IOC_STORE_FILE", "")
    for p in [env, "/app/data/ioc_store.json", "/app/sample-data/ioc_store.json"]:
        if p and Path(p).exists():
            return Path(p)
    return Path(env or "/app/data/ioc_store.json")

_STORE_FILE = _resolve_store_file()

MISP_URL   = os.getenv("MISP_URL", "").rstrip("/")
MISP_KEY   = os.getenv("MISP_KEY", "")
OPENCTI_URL   = os.getenv("OPENCTI_URL", "").rstrip("/")
OPENCTI_TOKEN = os.getenv("OPENCTI_TOKEN", "")


def misp_configured() -> bool:
    return bool(MISP_URL and MISP_KEY)


def opencti_configured() -> bool:
    return bool(OPENCTI_URL and OPENCTI_TOKEN)


# ── local curated store ─────────────────────────────────────────────────────
_store_cache: Optional[list] = None


def _load_store() -> list:
    global _store_cache
    if _store_cache is not None:
        return _store_cache
    try:
        if _STORE_FILE.exists():
            _store_cache = json.loads(_STORE_FILE.read_text("utf-8"))
        else:
            _store_cache = []
    except Exception as e:
        logger.warning(f"ioc_store load failed: {e}")
        _store_cache = []
    return _store_cache


def reload_store() -> int:
    global _store_cache
    _store_cache = None
    return len(_load_store())


def _ip_matches(ip: str, indicator: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        if "/" in indicator:
            return addr in ipaddress.ip_network(indicator, strict=False)
        return str(addr) == str(ipaddress.ip_address(indicator))
    except ValueError:
        # Fall back to a simple prefix match for legacy "1.2.3." style entries.
        return ip.startswith(indicator)


def _local_relations(ip: str) -> list[dict]:
    out = []
    for obj in _load_store():
        ind = str(obj.get("indicator", ""))
        if ind and _ip_matches(ip, ind):
            out.append({
                "actor": obj.get("actor", ""), "campaign": obj.get("campaign", ""),
                "malware": obj.get("malware", ""), "confidence": int(obj.get("confidence", 50)),
                "source": obj.get("source", "local IOC store"),
                "tlp": obj.get("tlp", ""), "references": obj.get("references", []),
                "first_seen": obj.get("first_seen", ""), "indicator": ind,
            })
    return out


# ── optional live lookups (best-effort, short timeout) ──────────────────────
def _misp_relations(ip: str) -> list[dict]:
    if not misp_configured():
        return []
    try:
        import httpx
        r = httpx.post(f"{MISP_URL}/attributes/restSearch",
                       headers={"Authorization": MISP_KEY, "Accept": "application/json"},
                       json={"value": ip, "type": "ip-src", "limit": 20}, timeout=4, verify=False)
        if r.status_code != 200:
            return []
        attrs = r.json().get("response", {}).get("Attribute", [])
        rels = []
        for a in attrs:
            ev = a.get("Event", {}) or {}
            rels.append({
                "actor": "", "campaign": ev.get("info", ""), "malware": "",
                "confidence": 70, "source": f"MISP:{ev.get('Orgc', {}).get('name', 'event')}",
                "tlp": "", "references": [], "first_seen": a.get("first_seen", ""),
                "indicator": ip, "tags": [t.get("name") for t in a.get("Tag", []) if t.get("name")],
            })
        return rels
    except Exception as e:
        logger.info(f"MISP lookup failed: {e}")
        return []


def _opencti_relations(ip: str) -> list[dict]:
    if not opencti_configured():
        return []
    try:
        import httpx
        q = {"query": "query($f:[StixCyberObservablesFiltering]){stixCyberObservables(filters:$f,first:1)"
                       "{edges{node{... on IPv4Addr{value "
                       "objectLabel{edges{node{value}}}}}}}}",
             "variables": {"f": [{"key": "value", "values": [ip]}]}}
        r = httpx.post(f"{OPENCTI_URL}/graphql",
                       headers={"Authorization": f"Bearer {OPENCTI_TOKEN}"},
                       json=q, timeout=4, verify=False)
        if r.status_code != 200:
            return []
        edges = (r.json().get("data", {}).get("stixCyberObservables", {}) or {}).get("edges", [])
        rels = []
        for e in edges:
            node = e.get("node", {}) or {}
            labels = [l["node"]["value"] for l in node.get("objectLabel", {}).get("edges", [])]
            rels.append({"actor": "", "campaign": "", "malware": "", "confidence": 75,
                         "source": "OpenCTI", "tlp": "", "references": [],
                         "first_seen": "", "indicator": ip, "tags": labels})
        return rels
    except Exception as e:
        logger.info(f"OpenCTI lookup failed: {e}")
        return []


def enrich_ip(ip: str, known_bad: bool = False) -> dict:
    """Return STIX2-style relationships for an IP with honest provenance."""
    relations = _local_relations(ip) + _misp_relations(ip) + _opencti_relations(ip)
    if known_bad and not relations:
        relations.append({
            "actor": "", "campaign": "", "malware": "",
            "confidence": 60, "source": "internal blocklist",
            "tlp": "", "references": [], "first_seen": "", "indicator": ip,
            "note": "Flagged on the internal known-bad list. No external attribution available.",
        })
    actors    = sorted({r["actor"] for r in relations if r.get("actor")})
    campaigns = sorted({r["campaign"] for r in relations if r.get("campaign")})
    malware   = sorted({r["malware"] for r in relations if r.get("malware")})
    return {
        "available": bool(relations),
        "actors": actors, "campaigns": campaigns, "malware": malware,
        "relations": relations,
        "sources_configured": {
            "misp": misp_configured(), "opencti": opencti_configured(),
            "local_store": bool(_load_store()),
        },
    }
