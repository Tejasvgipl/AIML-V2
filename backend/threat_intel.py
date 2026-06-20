"""
CyberSentinel — Threat-Intel & ATT&CK knowledge layer
=====================================================
A curated, offline MITRE ATT&CK knowledge base focused on the techniques a
**banking SIEM** actually sees, plus a retrieval layer that grounds the AI:
given an alert (threat_type / MITRE id / keywords) it returns the matching
technique docs — summary, banking context, detection, real-world mitigations,
and how organisations elsewhere respond ("how the world solves this").

No external service or vector DB required: ATT&CK technique IDs are exact keys,
so id + keyword retrieval is precise and deterministic. The structure is
embedding-ready if semantic search is added later (see retrieve_for_alert).
"""
from __future__ import annotations

# Canonical ATT&CK enterprise tactic order — used to lay an entity's alerts out
# along the kill chain (lower index = earlier in the intrusion lifecycle).
TACTIC_ORDER = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact",
]


def tactic_rank(tactic: str) -> int:
    try:
        return TACTIC_ORDER.index((tactic or "").strip())
    except ValueError:
        return len(TACTIC_ORDER)  # unknown tactics sort last


# ── Knowledge base ─────────────────────────────────────────────────────────────
# Keyed by ATT&CK technique id. `aliases` lets a threat_type or keyword resolve
# to the technique without an exact id match.

KB: dict[str, dict] = {
    "T1110": {
        "technique_id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
        "aliases": ["brute_force", "ssh_bruteforce", "vpn_bruteforce", "authentication_failed", "brute"],
        "summary": "Adversaries systematically guess credentials against an auth service "
                   "(SSH, RDP, VPN, web login) until one works.",
        "bank_context": "The most common precursor to fraud in banking estates — internet-facing "
                        "VPN/RDP gateways and employee SSO are hammered from botnets, often as a "
                        "prelude to account takeover and wire fraud.",
        "detection": "Spike in failed logons per source IP / per target account, many accounts from "
                     "one IP (password spray), or one account from many IPs (credential stuffing).",
        "mitigations": [
            {"id": "M1032", "name": "Multi-factor Authentication", "detail": "MFA on all remote access and privileged accounts neutralises a correct password guess."},
            {"id": "M1036", "name": "Account Use Policies", "detail": "Lockout/back-off after N failures; throttle auth attempts."},
            {"id": "M1027", "name": "Password Policies", "detail": "Long unique passwords + banned-password lists defeat dictionary guessing."},
            {"id": "M1037", "name": "Filter Network Traffic", "detail": "Geo/ASN-fence management interfaces; block known-bad source ranges at the edge."},
        ],
        "world_response": "Banks and CERTs respond by forcing MFA, auto-locking sprayed accounts, "
                          "rate-limiting at the WAF/VPN, and pushing offending source ranges to a "
                          "blocklist shared across the sector (FS-ISAC). Public guidance: CISA "
                          "'Brute Force' and NCSC password-spray advisories.",
        "references": ["https://attack.mitre.org/techniques/T1110/"],
    },
    "T1078": {
        "technique_id": "T1078",
        "name": "Valid Accounts",
        "tactic": "Defense Evasion",
        "aliases": ["login_success", "valid_account", "account_takeover", "ato"],
        "summary": "Adversaries use legitimate credentials to log in, blending with normal activity.",
        "bank_context": "A successful login right after a brute-force burst, from a new country/ASN or "
                        "at an unusual hour, is the classic account-takeover signature that precedes "
                        "fraudulent transfers.",
        "detection": "login_success that follows failures from the same IP; impossible-travel; first-"
                     "seen geo/device for the account; logon outside the user's baseline hours.",
        "mitigations": [
            {"id": "M1032", "name": "Multi-factor Authentication", "detail": "Step-up MFA on anomalous logins blocks use of stolen passwords."},
            {"id": "M1036", "name": "Account Use Policies", "detail": "Conditional access by geo/device; disable dormant accounts."},
            {"id": "M1018", "name": "User Account Management", "detail": "Least privilege so a stolen account can't reach crown-jewel systems."},
        ],
        "world_response": "On a suspected takeover, SOCs immediately invalidate sessions, force a "
                          "password reset + MFA re-enrolment, and review recent transactions for fraud. "
                          "This is the core of FFIEC and PSD2 strong-customer-authentication guidance.",
        "references": ["https://attack.mitre.org/techniques/T1078/"],
    },
    "T1021": {
        "technique_id": "T1021",
        "name": "Remote Services (RDP/SSH/SMB)",
        "tactic": "Lateral Movement",
        "aliases": ["rdp_relay", "rdp", "remote desktop", "lateral", "smb"],
        "summary": "Adversaries pivot between internal hosts over RDP, SSH or SMB using valid or "
                   "relayed credentials.",
        "bank_context": "Once inside, attackers hop from a beachhead workstation toward domain "
                        "controllers and payment/SWIFT systems via RDP — the path seen in most "
                        "bank-network intrusions.",
        "detection": "One host opening RDP/SMB to many internal hosts; RDP from non-admin subnets; "
                     "service/winlogon spawning unexpected children (process lineage).",
        "mitigations": [
            {"id": "M1042", "name": "Disable or Remove Feature", "detail": "Turn RDP off where unused; restrict to a jump host."},
            {"id": "M1030", "name": "Network Segmentation", "detail": "Segment payment/SWIFT zones; block lateral RDP/SMB between user subnets."},
            {"id": "M1032", "name": "Multi-factor Authentication", "detail": "MFA on RDP/jump hosts stops reuse of relayed creds."},
        ],
        "world_response": "Responders isolate the source host, block east-west RDP/SMB at the segment "
                          "firewall, and hunt for the same toolset on peer hosts. CISA's RDP hardening "
                          "and lateral-movement guidance is the common reference.",
        "references": ["https://attack.mitre.org/techniques/T1021/"],
    },
    "T1133": {
        "technique_id": "T1133",
        "name": "External Remote Services",
        "tactic": "Initial Access",
        "aliases": ["vpn", "openvpn", "ipsec", "external_remote"],
        "summary": "Adversaries abuse internet-facing remote services (VPN, Citrix, RDP gateway) to "
                   "gain a foothold.",
        "bank_context": "VPN concentrators are the front door for remote staff and a prime target; a "
                        "successful VPN auth from a brute-forced or stolen credential is initial access.",
        "detection": "VPN auth success after brute force; concurrent VPN sessions for one account from "
                     "different geos; logins from hosting/Tor ASNs.",
        "mitigations": [
            {"id": "M1032", "name": "Multi-factor Authentication", "detail": "MFA on the VPN is the single highest-value control."},
            {"id": "M1035", "name": "Limit Access to Resource Over Network", "detail": "Restrict VPN to managed devices / known geographies."},
        ],
        "world_response": "Orgs enforce MFA + device posture on VPN, terminate suspicious tunnels, and "
                          "subscribe to ASN/Tor exit-node feeds to fence the gateway.",
        "references": ["https://attack.mitre.org/techniques/T1133/"],
    },
    "T1068": {
        "technique_id": "T1068",
        "name": "Privilege Escalation (Exploitation)",
        "tactic": "Privilege Escalation",
        "aliases": ["privilege_escalation", "privilege", "sudo", "escalation"],
        "summary": "Adversaries exploit a flaw or misconfiguration to gain higher privileges.",
        "bank_context": "Escalation to local admin / domain admin is the step that turns a single "
                        "compromised teller workstation into a path to the core banking platform.",
        "detection": "Unexpected sudo/SeDebug use, new admin-group membership, service binaries "
                     "spawning shells, kernel-exploit signatures.",
        "mitigations": [
            {"id": "M1051", "name": "Update Software", "detail": "Patch the exploited CVE; prioritise privilege-escalation bugs."},
            {"id": "M1026", "name": "Privileged Account Management", "detail": "Just-in-time admin, tiered admin model, no standing domain admin."},
            {"id": "M1038", "name": "Execution Prevention", "detail": "Application control blocks the exploit/tooling from running."},
        ],
        "world_response": "Teams patch, rotate privileged credentials, and rebuild the affected host; "
                          "domain-admin compromise triggers a full AD recovery playbook (Microsoft / CISA).",
        "references": ["https://attack.mitre.org/techniques/T1068/"],
    },
    "T1046": {
        "technique_id": "T1046",
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "aliases": ["recon_scan", "db_scan", "scan", "nmap", "portscan", "recon"],
        "summary": "Adversaries scan for open ports/services to map targets (often databases).",
        "bank_context": "Scanning of database ports (MySQL/Postgres/Mongo/MSSQL) inside the network is "
                        "a reconnaissance step toward customer-data theft.",
        "detection": "One source touching many distinct ports/hosts in a short window; sequential "
                     "port hits; DB ports probed from non-application subnets.",
        "mitigations": [
            {"id": "M1030", "name": "Network Segmentation", "detail": "Databases reachable only from app tier; deny direct user-subnet access."},
            {"id": "M1037", "name": "Filter Network Traffic", "detail": "Block/deny scan sources; honeytokens to detect probing."},
        ],
        "world_response": "SOCs correlate the scan to a single actor, block the source, and check whether "
                          "any probed service responded — scanning alone is low-severity but a strong "
                          "early-warning when paired with later stages.",
        "references": ["https://attack.mitre.org/techniques/T1046/"],
    },
    "T1190": {
        "technique_id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "aliases": ["web_attack", "sql_injection", "xss", "web", "attack"],
        "summary": "Adversaries exploit a web app/API flaw (SQLi, deserialization, auth bypass) to "
                   "gain access.",
        "bank_context": "Online-banking portals and APIs are continuously probed; a successful SQLi or "
                        "auth bypass can expose customer records directly.",
        "detection": "WAF signatures (SQLi/XSS), 500s spiking on one endpoint, anomalous query strings, "
                     "app errors referencing SQL.",
        "mitigations": [
            {"id": "M1050", "name": "Exploit Protection", "detail": "WAF in blocking mode; virtual-patch the vulnerable route."},
            {"id": "M1051", "name": "Update Software", "detail": "Patch the framework/component; fix the input validation."},
            {"id": "M1016", "name": "Vulnerability Scanning", "detail": "Continuously scan public apps; pen-test before release."},
        ],
        "world_response": "Responders virtual-patch at the WAF, take the route offline if needed, and "
                          "review logs for successful exploitation + data access. OWASP + PCI-DSS 6.x "
                          "drive the standard response.",
        "references": ["https://attack.mitre.org/techniques/T1190/"],
    },
    "T1486": {
        "technique_id": "T1486",
        "name": "Data Encrypted for Impact (Ransomware)",
        "tactic": "Impact",
        "aliases": ["ransom", "ransomware"],
        "summary": "Adversaries encrypt data to disrupt operations and extort payment.",
        "bank_context": "Ransomware against a bank threatens availability of core systems and customer "
                        "access — a board-level, regulator-reportable event.",
        "detection": "Mass file modifications (FIM/syscheck) in a short window, shadow-copy deletion, "
                     "known ransomware file hashes, abnormal write rates.",
        "mitigations": [
            {"id": "M1053", "name": "Data Backup", "detail": "Offline, tested, immutable backups are the decisive control."},
            {"id": "M1040", "name": "Behavior Prevention on Endpoint", "detail": "EDR ransomware-rollback / mass-encryption blocking."},
            {"id": "M1030", "name": "Network Segmentation", "detail": "Contain blast radius; isolate backup network."},
        ],
        "world_response": "Banks invoke incident response + BCP, isolate affected segments, restore from "
                          "immutable backups, and notify regulators. CISA #StopRansomware is the playbook.",
        "references": ["https://attack.mitre.org/techniques/T1486/"],
    },
    "T1204": {
        "technique_id": "T1204",
        "name": "User Execution / Malware",
        "tactic": "Execution",
        "aliases": ["malware", "virus", "trojan"],
        "summary": "Malicious code runs on a host, often after a user opens a lure or a dropper executes.",
        "bank_context": "Commodity malware/info-stealers on staff endpoints harvest the very credentials "
                        "used in later account-takeover and lateral movement.",
        "detection": "Known-bad hashes, suspicious process lineage (office app → script → shell), "
                     "beaconing, AV/EDR detections.",
        "mitigations": [
            {"id": "M1038", "name": "Execution Prevention", "detail": "Application allow-listing blocks unsigned/unknown binaries."},
            {"id": "M1017", "name": "User Training", "detail": "Phishing-resistant culture reduces initial execution."},
            {"id": "M1049", "name": "Antivirus/Antimalware", "detail": "EDR for detection + automated containment."},
        ],
        "world_response": "SOCs isolate the host via EDR, pull the sample for analysis, and sweep the "
                          "estate for the same IOCs; credentials used on the host are rotated.",
        "references": ["https://attack.mitre.org/techniques/T1204/"],
    },
    "T1071": {
        "technique_id": "T1071",
        "name": "Application Layer Protocol (C2) / Known-bad IOC",
        "tactic": "Command and Control",
        "aliases": ["known_malicious", "blacklist", "known_bad", "threat_intel", "ioc", "c2"],
        "summary": "Compromised hosts talk to attacker infrastructure over common protocols; matches "
                   "against known-bad indicators.",
        "bank_context": "A host beaconing to a flagged IP/domain means an active foothold — high "
                        "priority because it implies the earlier stages already succeeded.",
        "detection": "Traffic to threat-intel IOC lists, beacon periodicity, DNS to newly-registered "
                     "or flagged domains.",
        "mitigations": [
            {"id": "M1031", "name": "Network Intrusion Prevention", "detail": "Block C2 IOCs at egress; sinkhole flagged domains."},
            {"id": "M1037", "name": "Filter Network Traffic", "detail": "Default-deny egress; allow-list known destinations."},
        ],
        "world_response": "Responders block the IOC at egress, isolate the beaconing host, and share the "
                          "indicator with the sector (FS-ISAC) so peers can pre-emptively block it.",
        "references": ["https://attack.mitre.org/techniques/T1071/"],
    },
}

# threat_type (watcher classifier) → primary ATT&CK technique id.
THREAT_TO_TECHNIQUE = {
    "ssh_bruteforce": "T1110",
    "vpn_bruteforce": "T1110",
    "brute_force": "T1110",
    "rdp_relay": "T1021",
    "privilege_escalation": "T1068",
    "db_scan": "T1046",
    "recon_scan": "T1046",
    "web_attack": "T1190",
    "malware": "T1204",
    "known_malicious": "T1071",
    "login_success": "T1078",
}

# Secondary techniques worth surfacing alongside the primary one.
THREAT_SECONDARY = {
    "vpn_bruteforce": ["T1133"],
    "rdp_relay": ["T1110"],
}

# Build an alias index for keyword resolution.
_ALIAS_INDEX: dict[str, str] = {}
for _tid, _entry in KB.items():
    _ALIAS_INDEX[_tid.lower()] = _tid
    _ALIAS_INDEX[_entry["name"].lower()] = _tid
    for _a in _entry.get("aliases", []):
        _ALIAS_INDEX[_a.lower()] = _tid


def lookup_technique(tid: str) -> dict | None:
    """Exact technique lookup. Accepts sub-technique ids (T1110.001 → T1110)."""
    if not tid:
        return None
    tid = tid.strip().upper()
    if tid in KB:
        return KB[tid]
    base = tid.split(".")[0]
    return KB.get(base)


def _resolve_ids(threat_type: str = "", mitre_id: str = "", keywords: str = "") -> list[str]:
    """Resolve an alert to ordered, de-duplicated technique ids."""
    ids: list[str] = []

    def _add(tid: str | None):
        if tid and tid in KB and tid not in ids:
            ids.append(tid)

    # 1) explicit MITRE id(s) on the alert (may be comma/space separated)
    for raw in (mitre_id or "").replace(";", ",").replace(" ", ",").split(","):
        ent = lookup_technique(raw)
        if ent:
            _add(ent["technique_id"])

    # 2) classifier threat_type → technique (+ secondaries)
    tt = (threat_type or "").strip().lower()
    _add(THREAT_TO_TECHNIQUE.get(tt))
    for sec in THREAT_SECONDARY.get(tt, []):
        _add(sec)

    # 3) keyword/alias fallback
    hay = f"{threat_type} {keywords}".lower()
    for alias, tid in _ALIAS_INDEX.items():
        if alias and alias in hay:
            _add(tid)

    return ids


def retrieve_for_alert(threat_type: str = "", mitre_id: str = "",
                       tactic: str = "", keywords: str = "", limit: int = 3) -> list[dict]:
    """Return the most relevant KB entries for an alert (ordered by relevance).

    Deterministic id/alias retrieval today; the same signature can back an
    embedding search later without changing callers.
    """
    ids = _resolve_ids(threat_type, mitre_id, keywords)
    return [KB[i] for i in ids[:limit]]


def format_grounding(entries: list[dict]) -> str:
    """Render retrieved KB entries into a compact citation block for the LLM."""
    if not entries:
        return "No matching ATT&CK technique in the knowledge base."
    blocks = []
    for e in entries:
        mits = "; ".join(f"{m['id']} {m['name']} — {m['detail']}" for m in e.get("mitigations", []))
        blocks.append(
            f"[{e['technique_id']} {e['name']} | tactic: {e['tactic']}]\n"
            f"Summary: {e['summary']}\n"
            f"Banking context: {e['bank_context']}\n"
            f"Detection: {e['detection']}\n"
            f"Mitigations: {mits}\n"
            f"How the world responds: {e['world_response']}\n"
            f"Reference: {', '.join(e.get('references', []))}"
        )
    return "\n\n".join(blocks)
