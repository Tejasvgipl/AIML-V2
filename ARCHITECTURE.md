# CyberSentinel — Architecture

Threat-intelligence / SOC pipeline. High-volume Wazuh alerts are ingested into
ClickHouse, aggregated, and served to a SOC dashboard plus a Grafana log explorer.

## 1. Data flow

```
 Wazuh server                      CyberSentinel stack
┌─────────────┐
│ alerts.json │  read-only mount
│ lakhs/hour  │──────────────►  wazuh-watcher  (scripts/wazuh_watcher.py)
└─────────────┘                  • byte-offset tail
                                 • smart filter (drop/sample/keep)
                                 • classify threat_type + severity
                                 • batch 5000 + DISK SPOOL (zero loss)
                                        │ bulk INSERT (native 9000)
                                        ▼
                               ┌─────────────────────────────────┐
                               │           ClickHouse             │
                               │  logs  (MergeTree, day-part,     │
                               │         ZSTD, 90d TTL)           │
                               │   ├─ mv_ip_daily    → agg_ip_daily
                               │   └─ mv_threat_hourly→ agg_threat_hourly
                               └───┬───────────────┬──────────┬───┘
                          SQL(default)        SQL(read-only)  SQL
                                   │               │          │
                                   ▼               ▼          ▼
                              backend          grafana    ml-engine
                              (FastAPI)        (:13000)   ml-intern
                                   │ /api/*        │          │ models
                                   ▼               │          ▼
                               nginx ─────────────┘        redis
                               (:18888)                    (small state,
                                   │                         no logs)
                                   ▼
                               frontend  (SOC dashboard)
```

## 2. Components

| Service        | Container          | Host port            | Role |
|----------------|--------------------|----------------------|------|
| wazuh-watcher  | cs_wazuh_watcher   | —                    | Tail `alerts.json`, filter, classify, batch-insert to ClickHouse with disk spool. Started with `--profile wazuh`. |
| ClickHouse     | cs_clickhouse      | 18123 HTTP / 19000 native | Log store + rollups. Built-in SQL UI at `/play`. |
| backend        | cs_backend         | 18110                | FastAPI. Reads ClickHouse via SQL, serves `/api/*`. CSV/manual ingest also writes ClickHouse. |
| redis          | cs_redis           | 16380 (localhost)    | Small mutable state ONLY: baselines, blocklist, alerts, ML coordination. Holds no logs. |
| ml-engine      | cs_ml              | 18111                | Isolation-Forest anomaly scoring; features from ClickHouse. |
| ml-intern      | cs_ml_intern       | 18112                | Candidate model training + drift detection; manual approval. |
| frontend       | cs_frontend        | 18180                | SOC dashboard (static HTML/JS). |
| nginx          | cs_nginx           | 18888                | Reverse proxy: `/`→frontend, `/api/`→backend, `/api/ml/`→ml-engine. |
| grafana        | cs_grafana         | 13000                | Visual log explorer (timeline + raw logs + filters). Reads ClickHouse as read-only user. |

## 3. Ingestion (alerts.json → ClickHouse)

`scripts/wazuh_watcher.py` (v3):
- Reads `alerts.json` read-only, tracks a byte offset (`/app/data/wazuh_offset.json`).
- **Smart filter:** level <4 drop, 4–6 sample 1/N, 7+ keep all. Tames lakhs/hour.
- **Classify:** `severity` from rule level (12+ critical, 8+ high, 4+ medium); `threat_type` from rule groups/description (ssh_bruteforce, brute_force, recon_scan, …).
- **Batch + durability:** accumulates 5000 rows, inserts with `wait_for_async_insert=1`.
  On ClickHouse outage the batch is written to a disk spool and replayed on recovery.
  The read offset only advances once a batch is durably stored → zero log loss.
- Triggers backend baseline build + ML train + archive periodically.

CSV / manual logs via `POST /api/ingest/csv|bulk|log` also land in ClickHouse
(backend builds the same row shape and calls `clickhouse_client.insert_logs`).

## 4. Storage (ClickHouse)

Defined in `clickhouse/init/01-schema.sql` (auto-applied on a fresh data volume):

- **`cybersentinel.logs`** — source of truth. MergeTree, `PARTITION BY toYYYYMMDD(ts)`,
  `ORDER BY (src_ip, ts)`, LowCardinality + ZSTD columns, `TTL ts + 90 DAY`.
  17 columns: ts, ingested_at, src_ip, dst_ip, dst_port, threat_type, severity,
  rule, rule_id, rule_level, action, country, agent, mitre, username, useragent, signature.
- **`agg_ip_daily`** (SummingMergeTree) via `mv_ip_daily` — per day/IP/threat/severity counts.
  Powers top-IPs, threat counts, unique-IPs, per-IP summaries in milliseconds.
- **`agg_threat_hourly`** (SummingMergeTree) via `mv_threat_hourly` — hourly threat trend.

Materialized views roll rows up at insert time, so dashboards never scan raw crores.

## 5. Serving (backend → UI)

`backend/clickhouse_client.py` mirrors the old OpenSearch client API; `backend/main.py`
imports it as `osc` and gates log reads on `STORE_ENABLED` (= `CLICKHOUSE_ENABLED`).

Key endpoints (all ClickHouse SQL): `/api/stats`, `/api/hot-ips`, `/api/trail/{ip}`,
`/api/search`, `/api/health`. nginx serves the SOC UI at `:18888`.

## 6. State (Redis) — small, no logs

Redis holds only mutable non-log state: `baseline:{ip}`, `alert:{ip}:*`, blocklist,
ML metadata/coordination. Removing it does not affect log retrieval (Phase 2 will
migrate this state into ClickHouse tables and drop Redis entirely).

## 7. UIs

| UI | URL | Auth | Purpose |
|----|-----|------|---------|
| SOC dashboard | http://<server-ip>:18888 | — | The app: threats, trails, blocklist, reports |
| Grafana "Logs Explorer" | http://<server-ip>:13000 | admin / CyberSentinel@2026! | Timeline histogram + raw-logs table + severity/threat/search filters |
| ClickHouse Play | http://<server-ip>:18123/play | default / CyberSentinel@2026! | Raw SQL console |

Server IP: `10.200.10.223`. Grafana connects to ClickHouse as **read-only** user
`grafana_ro` (profile readonly=2, allow_ddl=0) so it can never modify data.

## 8. Resilience

- Watcher is fully decoupled — if log ingestion stops, ClickHouse/backend/UI keep
  serving stored logs with no lag.
- Disk spool + acked inserts → no log loss across ClickHouse restarts/outages.
- Backend degrades gracefully (returns empty, not crash) if ClickHouse is unreachable.
- `restart: unless-stopped` + healthchecks on ClickHouse and Redis.
- Day-partitioned TTL → instant, cheap retention drops.

## 9. Security

- ClickHouse: password on `default`, separate read-only `grafana_ro`. HTTP port
  exposed on all interfaces — firewall `18123` to trusted IPs on a real server.
- Grafana: login required (anonymous off).
- OpenSearch path disabled (`OPENSEARCH_ENABLED=false`) — the live `logs-*` server
  at `10.200.10.23` is never touched.

## 10. Run

```bash
docker compose up -d --build                      # core stack
export WAZUH_ALERTS_PATH=/var/ossec/logs/alerts/alerts.json
docker compose --profile wazuh up -d --build      # add the ingester
```

See `RUNBOOK.md` for health checks and failure→fix commands.
