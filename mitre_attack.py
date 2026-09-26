"""
MITRE ATT&CK Mapping Module
---------------------------
Lightweight, offline technique registry used by the Autonomous Tier-1 SOC Analyst.
Covers the techniques relevant to the five synthetic scenarios plus common
enterprise detections. All data is derived from the public MITRE ATT&CK knowledge
base (enterprise matrix) and is intentionally limited to what the prototype needs.
"""

from __future__ import annotations
from typing import Dict, List, Any, Optional


# ---------------------------------------------------------------------------
# Technique Registry (subset of Enterprise ATT&CK)
# ---------------------------------------------------------------------------

TECHNIQUES: Dict[str, Dict[str, Any]] = {

    # ---- Initial Access ----
    "T1566": {
        "id": "T1566",
        "name": "Phishing",
        "tactic": "Initial Access",
        "tactic_id": "TA0001",
        "url": "https://attack.mitre.org/techniques/T1566/",
        "description": "Adversaries send phishing messages to gain access to victim systems.",
        "platforms": ["Windows", "macOS", "Linux", "Office 365", "Google Workspace"],
        "detection": "Email gateway logs, user reports, URL/attachment detonation.",
    },
    "T1566.001": {
        "id": "T1566.001",
        "name": "Spearphishing Attachment",
        "tactic": "Initial Access",
        "tactic_id": "TA0001",
        "url": "https://attack.mitre.org/techniques/T1566/001/",
        "description": "Adversaries send spearphishing emails with a malicious attachment.",
        "platforms": ["Windows", "macOS", "Linux", "Office 365"],
        "detection": "Attachment sandbox verdict, file-hash reputation, macro analysis.",
    },
    "T1566.002": {
        "id": "T1566.002",
        "name": "Spearphishing Link",
        "tactic": "Initial Access",
        "tactic_id": "TA0001",
        "url": "https://attack.mitre.org/techniques/T1566/002/",
        "description": "Adversaries send spearphishing emails with a malicious link.",
        "platforms": ["Windows", "macOS", "Linux", "Office 365", "SaaS"],
        "detection": "URL rewriting, link analysis, credential-harvest page detection.",
    },

    # ---- Execution ----
    "T1059": {
        "id": "T1059",
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "tactic_id": "TA0002",
        "url": "https://attack.mitre.org/techniques/T1059/",
        "description": "Adversaries abuse command and script interpreters to execute commands.",
        "platforms": ["Windows", "macOS", "Linux", "Network"],
        "detection": "Process creation, command-line logging, script block logging.",
    },
    "T1059.001": {
        "id": "T1059.001",
        "name": "PowerShell",
        "tactic": "Execution",
        "tactic_id": "TA0002",
        "url": "https://attack.mitre.org/techniques/T1059/001/",
        "description": "Adversaries abuse PowerShell to execute commands and scripts.",
        "platforms": ["Windows"],
        "detection": "PowerShell logging (ScriptBlock, Module), EDR process trees, encoded-command detection.",
    },
    "T1204": {
        "id": "T1204",
        "name": "User Execution",
        "tactic": "Execution",
        "tactic_id": "TA0002",
        "url": "https://attack.mitre.org/techniques/T1204/",
        "description": "Adversaries rely on user interaction to execute malicious code.",
        "platforms": ["Windows", "macOS", "Linux"],
        "detection": "User-initiated process creation, browser/download telemetry.",
    },
    "T1204.002": {
        "id": "T1204.002",
        "name": "Malicious File",
        "tactic": "Execution",
        "tactic_id": "TA0002",
        "url": "https://attack.mitre.org/techniques/T1204/002/",
        "description": "Adversaries rely on a user opening a malicious file to gain execution.",
        "platforms": ["Windows", "macOS", "Linux"],
        "detection": "File reputation, sandbox detonation, user-download correlation.",
    },

    # ---- Persistence / Defense Evasion (common companions) ----
    "T1027": {
        "id": "T1027",
        "name": "Obfuscated Files or Information",
        "tactic": "Defense Evasion",
        "tactic_id": "TA0005",
        "url": "https://attack.mitre.org/techniques/T1027/",
        "description": "Adversaries obfuscate code or files to avoid detection.",
        "platforms": ["Windows", "macOS", "Linux"],
        "detection": "Entropy analysis, Base64/encoded command detection, unpacking.",
    },

    # ---- Command and Control ----
    "T1071": {
        "id": "T1071",
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "tactic_id": "TA0011",
        "url": "https://attack.mitre.org/techniques/T1071/",
        "description": "Adversaries use application-layer protocols for C2.",
        "platforms": ["Windows", "macOS", "Linux", "Network"],
        "detection": "Proxy/firewall logs, unusual protocol usage, beaconing.",
    },
    "T1071.001": {
        "id": "T1071.001",
        "name": "Web Protocols",
        "tactic": "Command and Control",
        "tactic_id": "TA0011",
        "url": "https://attack.mitre.org/techniques/T1071/001/",
        "description": "Adversaries use HTTP/HTTPS for C2 communication.",
        "platforms": ["Windows", "macOS", "Linux", "Network"],
        "detection": "Proxy logs, TLS inspection, destination reputation, JA3/JA4.",
    },
    "T1071.004": {
        "id": "T1071.004",
        "name": "DNS",
        "tactic": "Command and Control",
        "tactic_id": "TA0011",
        "url": "https://attack.mitre.org/techniques/T1071/004/",
        "description": "Adversaries use DNS for C2 communication.",
        "platforms": ["Windows", "macOS", "Linux", "Network"],
        "detection": "DNS query volume, entropy of subdomains, NXDOMAIN ratio, TXT queries.",
    },
    "T1105": {
        "id": "T1105",
        "name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "tactic_id": "TA0011",
        "url": "https://attack.mitre.org/techniques/T1105/",
        "description": "Adversaries transfer tools or files from an external system into a compromised environment.",
        "platforms": ["Windows", "macOS", "Linux"],
        "detection": "Download cradles (IWR/IEX), unusual process network activity, file-write after network.",
    },

    # ---- Exfiltration ----
    "T1048": {
        "id": "T1048",
        "name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
        "tactic_id": "TA0010",
        "url": "https://attack.mitre.org/techniques/T1048/",
        "description": "Adversaries exfiltrate data over a protocol other than the primary C2 channel.",
        "platforms": ["Windows", "macOS", "Linux", "Network"],
        "detection": "Protocol anomaly, volume thresholds, destination analysis.",
    },
    "T1048.003": {
        "id": "T1048.003",
        "name": "Exfiltration Over Unencrypted Non-C2 Protocol",
        "tactic": "Exfiltration",
        "tactic_id": "TA0010",
        "url": "https://attack.mitre.org/techniques/T1048/003/",
        "description": "Adversaries exfiltrate data over an unencrypted, non-C2 protocol such as DNS or FTP.",
        "platforms": ["Windows", "macOS", "Linux", "Network"],
        "detection": "DNS tunneling indicators (entropy, length, query rate), FTP volume spikes.",
    },

    # ---- Collection (supporting) ----
    "T1005": {
        "id": "T1005",
        "name": "Data from Local System",
        "tactic": "Collection",
        "tactic_id": "TA0009",
        "url": "https://attack.mitre.org/techniques/T1005/",
        "description": "Adversaries search local system sources to find files of interest.",
        "platforms": ["Windows", "macOS", "Linux"],
        "detection": "File-access patterns, unusual process file enumeration.",
    },
}


# Tactic ordering for matrix-style display
TACTIC_ORDER = [
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]


def get_technique(tech_id: str) -> Optional[Dict[str, Any]]:
    """Return full technique record or None."""
    return TECHNIQUES.get(tech_id)


def enrich_techniques(tech_ids: List[str]) -> List[Dict[str, Any]]:
    """
    Given a list of technique IDs (e.g. ["T1059.001", "T1105"]),
    return a list of enriched dictionaries ready for UI / notes.
    Unknown IDs are still returned with a minimal stub.
    """
    seen = set()
    enriched: List[Dict[str, Any]] = []
    for tid in tech_ids:
        if not tid or tid in seen:
            continue
        seen.add(tid)
        rec = TECHNIQUES.get(tid)
        if rec:
            enriched.append(dict(rec))  # shallow copy
        else:
            # Parent technique fallback (e.g. T1059.001 → try T1059)
            parent = tid.split(".")[0] if "." in tid else None
            parent_rec = TECHNIQUES.get(parent) if parent else None
            enriched.append({
                "id": tid,
                "name": parent_rec["name"] + " (sub-technique)" if parent_rec else tid,
                "tactic": parent_rec["tactic"] if parent_rec else "Unknown",
                "tactic_id": parent_rec.get("tactic_id", "") if parent_rec else "",
                "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/",
                "description": parent_rec["description"] if parent_rec else "Technique not in local registry.",
                "platforms": parent_rec.get("platforms", []) if parent_rec else [],
                "detection": parent_rec.get("detection", "") if parent_rec else "",
            })
    return enriched


def group_by_tactic(enriched: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """Group enriched techniques by tactic name, preserving TACTIC_ORDER."""
    groups: Dict[str, List[Dict[str, Any]]] = {}
    for t in enriched:
        tactic = t.get("tactic", "Unknown")
        groups.setdefault(tactic, []).append(t)
    # ordered dict
    ordered = {}
    for tac in TACTIC_ORDER:
        if tac in groups:
            ordered[tac] = groups.pop(tac)
    # any remaining (Unknown etc.)
    ordered.update(groups)
    return ordered


def format_mitre_markdown(enriched: List[Dict[str, Any]]) -> str:
    """Produce clean Markdown section for working notes."""
    if not enriched:
        return "- None definitive\n"
    lines = []
    grouped = group_by_tactic(enriched)
    for tactic, techs in grouped.items():
        lines.append(f"**{tactic}**")
        for t in techs:
            lines.append(f"- [`{t['id']}`]({t['url']}) – **{t['name']}**")
            if t.get("description"):
                lines.append(f"  - _{t['description'][:140]}{'…' if len(t.get('description','')) > 140 else ''}_")
        lines.append("")
    return "\n".join(lines)


def get_primary_tactic(enriched: List[Dict[str, Any]]) -> str:
    """Return the highest-priority tactic present (for badge / summary)."""
    if not enriched:
        return "N/A"
    for tac in TACTIC_ORDER:
        for t in enriched:
            if t.get("tactic") == tac:
                return tac
    return enriched[0].get("tactic", "N/A")