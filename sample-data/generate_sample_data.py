"""
Generate sample log data for testing CyberSentinel
Run: python generate_sample_data.py
"""
import csv, random, json
from datetime import datetime, timedelta, timezone

KNOWN_BAD_IPS = [
    "85.11.187.36","85.11.187.40","85.11.187.48","85.11.187.32",
    "85.11.182.2","85.11.183.4","85.11.187.8","85.11.187.16",
    "93.152.221.10","93.152.221.38","93.152.221.18","93.152.221.6",
    "164.52.194.98","85.11.167.232","198.235.24.176","205.210.31.66",
]
INTERNAL_IPS = ["192.168.1.111","192.168.1.50","192.168.10.5"]
SSH_SCANNERS  = ["103.204.167.14","1.213.180.29","1.214.173.116","101.36.107.152"]

RULES = [
    {"id":"81606","desc":"Fortigate: Login failed.","level":"alert","group":"authentication_failed"},
    {"id":"81614","desc":"Fortigate: SSL VPN login failed.","level":"alert","group":"vpn"},
    {"id":"5710","desc":"sshd: brute force trying to get access to the system.","level":"alert","group":"sshd"},
    {"id":"62103","desc":"Fortigate: Blocked URL.","level":"warning","group":"firewall"},
    {"id":"86601","desc":"Suricata: Alert - ET INFO RDP Response To External Host","level":"alert","group":"suricata"},
    {"id":"86601","desc":"Suricata: Alert - ET SCAN Suspicious inbound to PostgreSQL port 5432","level":"warning","group":"suricata"},
    {"id":"86601","desc":"Suricata: Alert - ET DROP Dshield Block Listed Source group 1","level":"alert","group":"suricata"},
    {"id":"86601","desc":"Suricata: Alert - ET INFO SSH-2.0-Go version string Observed","level":"warning","group":"suricata"},
    {"id":"40704","desc":"Systemd: Unit entered failed state.","level":"notice","group":"systemd"},
    {"id":"92209","desc":"Windows: Privilege escalation attempt","level":"alert","group":"windows"},
]

MITRE = {
    "81606": ("T1110.003","Credential Access","Password Spraying"),
    "5710":  ("T1110.001","Credential Access","Brute Force"),
    "92209": ("T1548","Privilege Escalation","Abuse Elevation Control Mechanism"),
    "81614": ("T1078","Initial Access","Valid Accounts"),
}

start_time = datetime(2026, 4, 22, 4, 0, 0, tzinfo=timezone.utc)

rows = []

def ts(offset_seconds):
    return (start_time + timedelta(seconds=offset_seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")

# Brute force from 85.11.x.x
for i in range(600):
    ip = random.choice(KNOWN_BAD_IPS[:10])
    offset = random.randint(0, 1200)
    rule = RULES[0]
    mid = MITRE.get(rule["id"], ("","",""))
    rows.append({
        "@timestamp": ts(offset),
        "rule.id": rule["id"],
        "rule.description": rule["desc"],
        "rule.groups": rule["group"],
        "data.level": rule["level"],
        "data.ui": ip,
        "data.srcip": "",
        "data.src_ip": "",
        "data.action": "login",
        "data.dstip": "10.0.0.1",
        "data.srccountry": "Russia",
        "rule.mitre.id": mid[0],
        "rule.mitre.tactic": mid[1],
        "rule.mitre.technique": mid[2],
        "agent.name": "VGIL_FW",
        "is_false_positive": "false",
        "data.alert.signature": "",
        "data.dest_ip": "",
        "data.dest_port": "",
        "syscheck.path": "",
        "data.win.system.eventID": "",
    })

# RDP storm from 164.52.194.98
for i in range(400):
    offset = random.randint(0, 1200)
    dst = f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
    rows.append({
        "@timestamp": ts(offset),
        "rule.id": "86601",
        "rule.description": "Suricata: Alert - ET INFO RDP Response To External Host",
        "rule.groups": "suricata",
        "data.level": "alert",
        "data.ui": "",
        "data.srcip": "",
        "data.src_ip": "164.52.194.98",
        "data.action": "allowed",
        "data.dstip": "",
        "data.srccountry": "India",
        "rule.mitre.id": "T1021.001",
        "rule.mitre.tactic": "Lateral Movement",
        "rule.mitre.technique": "Remote Desktop Protocol",
        "agent.name": "VGIL_IDS",
        "is_false_positive": "false",
        "data.alert.signature": "ET INFO RDP Response To External Host",
        "data.dest_ip": dst,
        "data.dest_port": "3389",
        "syscheck.path": "",
        "data.win.system.eventID": "",
    })

# SSH brute force (Go scanner)
for i in range(100):
    ip = random.choice(SSH_SCANNERS)
    offset = random.randint(0, 1200)
    rows.append({
        "@timestamp": ts(offset),
        "rule.id": "5710",
        "rule.description": "sshd: brute force trying to get access to the system.",
        "rule.groups": "sshd",
        "data.level": "alert",
        "data.ui": "",
        "data.srcip": "",
        "data.src_ip": ip,
        "data.action": "denied",
        "data.dstip": "10.0.0.5",
        "data.srccountry": "China",
        "rule.mitre.id": "T1110.001",
        "rule.mitre.tactic": "Credential Access",
        "rule.mitre.technique": "Brute Force",
        "agent.name": "VGIL_LINUX",
        "is_false_positive": "false",
        "data.alert.signature": "ET INFO SSH-2.0-Go version string Observed",
        "data.dest_ip": "10.0.0.5",
        "data.dest_port": "22",
        "syscheck.path": "",
        "data.win.system.eventID": "",
    })

# PostgreSQL scan
for i in range(55):
    offset = random.randint(180, 900)
    rows.append({
        "@timestamp": ts(offset),
        "rule.id": "86601",
        "rule.description": "Suricata: Alert - ET SCAN Suspicious inbound to PostgreSQL port 5432",
        "rule.groups": "suricata",
        "data.level": "warning",
        "data.ui": "",
        "data.srcip": "",
        "data.src_ip": "85.11.167.232",
        "data.action": "blocked",
        "data.dstip": "",
        "data.srccountry": "Netherlands",
        "rule.mitre.id": "T1046",
        "rule.mitre.tactic": "Reconnaissance",
        "rule.mitre.technique": "Network Service Scanning",
        "agent.name": "VGIL_IDS",
        "is_false_positive": "false",
        "data.alert.signature": "ET SCAN Suspicious inbound to PostgreSQL port 5432",
        "data.dest_ip": "164.52.194.98",
        "data.dest_port": "5432",
        "syscheck.path": "",
        "data.win.system.eventID": "",
    })

# Internal URL blocks
for i in range(204):
    offset = random.randint(0, 1200)
    hosts = ["z-m-gateway.facebook.com","edge-mqtt.facebook.com","b-graph.facebook.com","edge-mqtt-fallback.facebook.com"]
    rows.append({
        "@timestamp": ts(offset),
        "rule.id": "62103",
        "rule.description": "Fortigate: Blocked URL.",
        "rule.groups": "firewall",
        "data.level": "warning",
        "data.ui": "192.168.1.111",
        "data.srcip": "192.168.1.111",
        "data.src_ip": "",
        "data.action": "blocked",
        "data.dstip": "31.13.93.1",
        "data.url": random.choice(hosts),   # the actual blocked domain (was being dropped)
        "data.srccountry": "India",
        "rule.mitre.id": "",
        "rule.mitre.tactic": "",
        "rule.mitre.technique": "",
        "agent.name": "VGIL_FW",
        "is_false_positive": "false",
        "data.alert.signature": "",
        "data.dest_ip": "",
        "data.dest_port": "443",
        "syscheck.path": "",
        "data.win.system.eventID": "",
    })

# Dshield known malicious
dshield_ips = ["198.235.24.176","205.210.31.66","205.210.31.252","167.94.146.44","147.185.132.70"]
for i in range(22):
    ip = random.choice(dshield_ips)
    offset = random.randint(100, 900)
    rows.append({
        "@timestamp": ts(offset),
        "rule.id": "86601",
        "rule.description": "Suricata: Alert - ET DROP Dshield Block Listed Source group 1",
        "rule.groups": "suricata",
        "data.level": "alert",
        "data.ui": "",
        "data.srcip": "",
        "data.src_ip": ip,
        "data.action": "blocked",
        "data.dstip": "",
        "data.srccountry": "United States",
        "rule.mitre.id": "",
        "rule.mitre.tactic": "",
        "rule.mitre.technique": "",
        "agent.name": "VGIL_IDS",
        "is_false_positive": "false",
        "data.alert.signature": "ET DROP Dshield Block Listed Source group 1",
        "data.dest_ip": "164.52.194.98",
        "data.dest_port": str(random.choice([80,443,3389,22])),
        "syscheck.path": "",
        "data.win.system.eventID": "",
    })

# Windows privilege escalation
for i in range(9):
    offset = random.randint(0, 1200)
    rows.append({
        "@timestamp": ts(offset),
        "rule.id": "92209",
        "rule.description": "Windows: Privilege escalation attempt",
        "rule.groups": "windows",
        "data.level": "alert",
        "data.ui": "",
        "data.srcip": "192.168.1.50",
        "data.src_ip": "",
        "data.action": "detected",
        "data.dstip": "",
        "data.srccountry": "India",
        "rule.mitre.id": "T1548",
        "rule.mitre.tactic": "Privilege Escalation",
        "rule.mitre.technique": "Abuse Elevation Control Mechanism",
        "agent.name": "SocSRV_15",
        "is_false_positive": "false",
        "data.alert.signature": "",
        "data.dest_ip": "",
        "data.dest_port": "",
        "syscheck.path": "",
        "data.win.system.eventID": "4672",
    })

# Sort by timestamp
rows.sort(key=lambda r: r["@timestamp"])

# union of every key across rows (some rows carry data.url, others don't)
fieldnames = list(dict.fromkeys(k for r in rows for k in r.keys()))
with open("sample_logs.csv","w",newline="",encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(rows)

print(f"Generated {len(rows)} log rows → sample_logs.csv")
