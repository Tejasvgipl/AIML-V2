#!/usr/bin/env python3
"""
CyberSentinel — OpenSearch Index Setup

Run once on .23 to create:
  1. ISM (Index State Management) policy   — lifecycle: hot → warm → cold → delete
  2. Index template                        — field mappings for security log docs
  3. Initial rollover index + alias        — cybersentinel-logs → cybersentinel-logs-000001

Usage:
  python3 opensearch_setup.py                           # defaults: https://localhost:9200 admin/admin
  python3 opensearch_setup.py --host 10.200.10.23       # custom host
  python3 opensearch_setup.py --user admin --pass secret # custom creds

Requires: opensearch-py   (pip install opensearch-py)
"""
import argparse
import json
import sys

from opensearchpy import OpenSearch


# ── ISM Policy ────────────────────────────────────────────────────────────────
# hot  → 30 days or 50 GB  → rollover → warm
# warm → 90 days            → read-only, force-merge → cold
# cold → 180 days           → replica 0 → wait
# delete → 365 days total   → purge

ISM_POLICY_ID = "cybersentinel-ism-policy"

ISM_POLICY_BODY = {
    "policy": {
        "description": "CyberSentinel log lifecycle: hot → warm → cold → delete",
        "default_state": "hot",
        "states": [
            {
                "name": "hot",
                "actions": [
                    {
                        "rollover": {
                            "min_index_age": "30d",
                            "min_primary_shard_size": "50gb",
                        }
                    }
                ],
                "transitions": [
                    {"state_name": "warm", "conditions": {"min_index_age": "30d"}}
                ],
            },
            {
                "name": "warm",
                "actions": [
                    {"force_merge": {"max_num_segments": 1}},
                    {"read_only": {}},
                ],
                "transitions": [
                    {"state_name": "cold", "conditions": {"min_index_age": "90d"}}
                ],
            },
            {
                "name": "cold",
                "actions": [
                    {
                        "replica_count": {"number_of_replicas": 0}
                    }
                ],
                "transitions": [
                    {"state_name": "delete", "conditions": {"min_index_age": "365d"}}
                ],
            },
            {
                "name": "delete",
                "actions": [{"delete": {}}],
                "transitions": [],
            },
        ],
        "ism_template": [
            {"index_patterns": ["cybersentinel-logs-*"], "priority": 100}
        ],
    }
}


# ── Index Template ────────────────────────────────────────────────────────────

INDEX_TEMPLATE_NAME = "cybersentinel-logs-template"

INDEX_TEMPLATE_BODY = {
    "index_patterns": ["cybersentinel-logs-*"],
    "template": {
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0,
            "index.refresh_interval": "5s",
            "plugins.index_state_management.rollover_alias": "cybersentinel-logs",
        },
        "mappings": {
            "properties": {
                "@timestamp": {"type": "date"},
                "ingested_at": {"type": "date"},
                "src_ip": {"type": "ip"},
                "dst_ip": {
                    "type": "text",
                    "fields": {"keyword": {"type": "keyword"}},
                },
                "dst_port": {"type": "keyword"},
                "threat_type": {"type": "keyword"},
                "severity": {"type": "keyword"},
                "rule": {
                    "type": "text",
                    "fields": {"keyword": {"type": "keyword", "ignore_above": 256}},
                },
                "rule_id": {"type": "keyword"},
                "action": {"type": "keyword"},
                "country": {"type": "keyword"},
                "agent": {"type": "keyword"},
                "mitre": {"type": "keyword"},
                "username": {"type": "keyword"},
                "useragent": {
                    "type": "text",
                    "fields": {"keyword": {"type": "keyword", "ignore_above": 512}},
                },
                "signature": {
                    "type": "text",
                    "fields": {"keyword": {"type": "keyword", "ignore_above": 256}},
                },
            }
        },
    },
    "priority": 200,
}


# ── Bootstrap ─────────────────────────────────────────────────────────────────

INITIAL_INDEX = "cybersentinel-logs-000001"
ALIAS_NAME = "cybersentinel-logs"


def create_client(host: str, port: int, user: str, password: str) -> OpenSearch:
    return OpenSearch(
        hosts=[{"host": host, "port": port}],
        http_auth=(user, password),
        use_ssl=True,
        verify_certs=False,
        ssl_show_warn=False,
        timeout=30,
    )


def setup_ism_policy(client: OpenSearch) -> None:
    """Create or update the ISM policy."""
    print(f"\n[1/3] ISM Policy: {ISM_POLICY_ID}")
    try:
        existing = client.transport.perform_request(
            "GET", f"/_plugins/_ism/policies/{ISM_POLICY_ID}"
        )
        seq_no = existing.get("_seq_no")
        primary_term = existing.get("_primary_term")
        client.transport.perform_request(
            "PUT",
            f"/_plugins/_ism/policies/{ISM_POLICY_ID}?if_seq_no={seq_no}&if_primary_term={primary_term}",
            body=ISM_POLICY_BODY,
        )
        print(f"  ✓ Updated existing policy (seq_no={seq_no})")
    except Exception as e:
        if "404" in str(e) or "Not Found" in str(e):
            client.transport.perform_request(
                "PUT",
                f"/_plugins/_ism/policies/{ISM_POLICY_ID}",
                body=ISM_POLICY_BODY,
            )
            print("  ✓ Created new policy")
        else:
            raise


def setup_index_template(client: OpenSearch) -> None:
    """Create or update the composable index template."""
    print(f"\n[2/3] Index Template: {INDEX_TEMPLATE_NAME}")
    client.indices.put_index_template(
        name=INDEX_TEMPLATE_NAME, body=INDEX_TEMPLATE_BODY
    )
    print("  ✓ Template applied")


def bootstrap_index(client: OpenSearch) -> None:
    """Create the initial index with the rollover alias if it doesn't exist."""
    print(f"\n[3/3] Bootstrap Index: {INITIAL_INDEX} → alias {ALIAS_NAME}")
    if client.indices.exists(index=INITIAL_INDEX):
        print(f"  ⏩ Index {INITIAL_INDEX} already exists — skipping")
        # Make sure alias exists
        if not client.indices.exists_alias(name=ALIAS_NAME):
            client.indices.put_alias(index=INITIAL_INDEX, name=ALIAS_NAME)
            print(f"  ✓ Re-created alias {ALIAS_NAME}")
        else:
            print(f"  ✓ Alias {ALIAS_NAME} already exists")
        return

    client.indices.create(
        index=INITIAL_INDEX,
        body={
            "aliases": {
                ALIAS_NAME: {"is_write_index": True}
            }
        },
    )
    print(f"  ✓ Created {INITIAL_INDEX} with write alias {ALIAS_NAME}")


def verify(client: OpenSearch) -> None:
    """Print verification info."""
    print("\n── Verification ─────────────────────────────────────────")

    # Check policy
    try:
        policy = client.transport.perform_request(
            "GET", f"/_plugins/_ism/policies/{ISM_POLICY_ID}"
        )
        states = [s["name"] for s in policy["policy"]["states"]]
        print(f"  ISM Policy:  {ISM_POLICY_ID}  states={states}")
    except Exception as e:
        print(f"  ISM Policy:  ERROR — {e}")

    # Check template
    try:
        tmpl = client.indices.get_index_template(name=INDEX_TEMPLATE_NAME)
        patterns = tmpl["index_templates"][0]["index_template"]["index_patterns"]
        print(f"  Template:    {INDEX_TEMPLATE_NAME}  patterns={patterns}")
    except Exception as e:
        print(f"  Template:    ERROR — {e}")

    # Check index + alias
    try:
        cat = client.cat.indices(index="cybersentinel-logs-*", format="json")
        for idx in cat:
            print(f"  Index:       {idx['index']}  docs={idx.get('docs.count','?')}  size={idx.get('store.size','?')}")
    except Exception:
        print("  Index:       none found")

    try:
        alias_info = client.indices.get_alias(name=ALIAS_NAME)
        for idx_name in alias_info:
            print(f"  Alias:       {ALIAS_NAME} → {idx_name}")
    except Exception:
        print(f"  Alias:       {ALIAS_NAME} not found")

    print("\n✅ OpenSearch setup complete. Backend can now write to alias 'cybersentinel-logs'.\n")


def main():
    parser = argparse.ArgumentParser(description="CyberSentinel OpenSearch Setup")
    parser.add_argument("--host", default="localhost", help="OpenSearch host")
    parser.add_argument("--port", type=int, default=9200, help="OpenSearch port")
    parser.add_argument("--user", default="admin", help="OpenSearch username")
    parser.add_argument("--password", default="admin", help="OpenSearch password")
    args = parser.parse_args()

    print(f"Connecting to OpenSearch at https://{args.host}:{args.port} ...")
    client = create_client(args.host, args.port, args.user, args.password)

    # Quick connectivity check
    info = client.info()
    version = info.get("version", {}).get("number", "?")
    dist = info.get("version", {}).get("distribution", "opensearch")
    print(f"Connected: {dist} v{version}")

    setup_ism_policy(client)
    setup_index_template(client)
    bootstrap_index(client)
    verify(client)


if __name__ == "__main__":
    main()
