"""
Tool definitions for the Autonomous Tier-1 SOC Analyst.
All tools return realistic mock dictionaries. No external network calls.
Designed to be drop-in compatible with LangChain @tool / StructuredTool.
"""

from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
import base64
import re
import math
from collections import Counter


# ---------------------------------------------------------------------------
# Input schemas (for documentation / future LangChain binding)
# ---------------------------------------------------------------------------

class IPLookupInput(BaseModel):
    ip: str = Field(..., description="IPv4 address to enrich (e.g. 198.51.100.24)")


class DNSLookupInput(BaseModel):
    domain: str = Field(..., description="Domain or FQDN to check (defanged or clean)")


class ScriptParseInput(BaseModel):
    payload: str = Field(..., description="Raw or base64-encoded PowerShell / script content")


class UserChangeInput(BaseModel):
    user: str = Field(..., description="sAMAccountName or UPN")
    asset: str = Field(..., description="Hostname or asset identifier")


class EmailPhishInput(BaseModel):
    sender: str
    headers: Dict[str, str]
    urls: List[str]
    attachment_hash: str


class RiskMatrixInput(BaseModel):
    intel_score: float = Field(..., ge=0, le=100)
    asset_criticality: str = Field(..., description="Low | Medium | High | Critical")
    is_authorized_activity: bool


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------

def lookup_ip_threat_intel(ip: str) -> Dict[str, Any]:
    """
    Simulated VirusTotal / AlienVault OTX enrichment.
    Returns reputation, malicious detections, related campaigns, and MITRE mapping.
    """
    # Deterministic mock based on well-known documentation / reserved ranges
    known_malicious = {
        "198.51.100.24": {
            "reputation": "Malicious",
            "score": 92,
            "detections": 47,
            "engines_total": 68,
            "categories": ["C2", "Malware Distribution"],
            "first_seen": "2025-11-03",
            "last_seen": "2026-09-25",
            "related_campaigns": ["CobaltStrike-Stager-2026Q3"],
            "mitre": ["T1071.001", "T1105"],
            "geo": "Unknown (Tor exit / bulletproof)",
            "notes": "Known C2 infrastructure used by multiple ransomware affiliates."
        },
        "203.0.113.55": {
            "reputation": "Suspicious",
            "score": 71,
            "detections": 19,
            "engines_total": 68,
            "categories": ["Phishing", "Spam"],
            "first_seen": "2026-08-12",
            "last_seen": "2026-09-26",
            "related_campaigns": ["CEO-Fraud-Spoof-2026"],
            "mitre": ["T1566.002"],
            "geo": "AS-PLACEHOLDER",
            "notes": "Frequently observed as mail-from for executive spoof campaigns."
        }
    }

    if ip in known_malicious:
        return {
            "ip": ip,
            "status": "success",
            "source": "Simulated-VT/OTX",
            **known_malicious[ip]
        }

    # Default: clean / private / unknown
    if ip.startswith(("10.", "192.168.", "172.")):
        return {
            "ip": ip,
            "status": "success",
            "source": "Simulated-VT/OTX",
            "reputation": "Clean (Internal/Private)",
            "score": 5,
            "detections": 0,
            "engines_total": 68,
            "categories": [],
            "notes": "RFC 1918 address – no external reputation data."
        }

    return {
        "ip": ip,
        "status": "success",
        "source": "Simulated-VT/OTX",
        "reputation": "Unknown / Low Confidence",
        "score": 18,
        "detections": 1,
        "engines_total": 68,
        "categories": [],
        "notes": "No strong malicious consensus."
    }


def lookup_dns_internal(domain: str) -> Dict[str, Any]:
    """
    Simulated BlueCat DDI / internal DNS entropy & tunneling detector.
    """
    # Clean the defanged form for analysis
    clean = domain.replace("[.]", ".").lower().strip(".")

    # Simple Shannon entropy of the leftmost label
    label = clean.split(".")[0] if clean else ""
    if not label:
        entropy = 0.0
    else:
        counts = Counter(label)
        length = len(label)
        entropy = -sum((c / length) * math.log2(c / length) for c in counts.values())

    high_entropy = entropy > 3.5
    tunneling_indicators = high_entropy or len(label) > 30 or "txt" in clean

    # Known benign internal
    if any(x in clean for x in ["contoso.example", "internal", "corp"]):
        return {
            "domain": domain,
            "clean_domain": clean,
            "status": "success",
            "source": "Simulated-BlueCat-DDI",
            "is_internal": True,
            "entropy_score": round(entropy, 2),
            "tunneling_score": 8,
            "verdict": "Benign Internal",
            "notes": "Resolves within corporate DNS zones."
        }

    if "example.com" in clean or high_entropy:
        return {
            "domain": domain,
            "clean_domain": clean,
            "status": "success",
            "source": "Simulated-BlueCat-DDI",
            "is_internal": False,
            "entropy_score": round(entropy, 2),
            "tunneling_score": 87 if high_entropy else 42,
            "query_volume_anomaly": True,
            "verdict": "Suspicious – Possible DNS Tunneling",
            "mitre": ["T1048.003", "T1071.004"],
            "notes": "High entropy subdomain + elevated query rate consistent with DNS exfiltration."
        }

    return {
        "domain": domain,
        "clean_domain": clean,
        "status": "success",
        "source": "Simulated-BlueCat-DDI",
        "is_internal": False,
        "entropy_score": round(entropy, 2),
        "tunneling_score": 15,
        "verdict": "No strong tunneling indicators",
        "notes": "Domain appears ordinary."
    }


def parse_script_payload(payload: str) -> Dict[str, Any]:
    """
    PowerShell / Base64 decoder + lightweight AST-style analysis.
    Detects download cradles, encoded commands, and suspicious cmdlets.
    """
    result: Dict[str, Any] = {
        "status": "success",
        "source": "Simulated-Script-Parser",
        "is_encoded": False,
        "decoded_preview": None,
        "suspicious_indicators": [],
        "mitre": [],
        "risk_score": 10
    }

    # Detect -Enc / -EncodedCommand pattern
    enc_match = re.search(r"(?:-enc|-encodedcommand)\s+([A-Za-z0-9+/=]{20,})", payload, re.I)
    if enc_match:
        result["is_encoded"] = True
        b64 = enc_match.group(1)
        try:
            # PowerShell uses UTF-16LE for -Enc
            decoded = base64.b64decode(b64).decode("utf-16-le", errors="replace")
            result["decoded_preview"] = decoded[:500]
            payload_to_scan = decoded
        except Exception:
            result["decoded_preview"] = "<decode failed>"
            payload_to_scan = payload
    else:
        payload_to_scan = payload

    # Indicator hunting
    indicators = []
    lower = payload_to_scan.lower()

    if "downloadstring" in lower or "downloadfile" in lower or "invoke-webrequest" in lower:
        indicators.append("Download cradle (IEX / DownloadString / IWR)")
        result["mitre"].append("T1059.001")
        result["mitre"].append("T1105")
        result["risk_score"] += 40

    if "frombase64string" in lower or "-enc" in lower:
        indicators.append("Base64 decoding observed")
        result["risk_score"] += 15

    if "bypass" in lower or "-nop" in lower or "-noni" in lower or "-w hidden" in lower:
        indicators.append("Execution policy / window style bypass flags")
        result["risk_score"] += 20

    if "backup" in lower or "approved" in lower or "retention" in lower:
        indicators.append("Possible legitimate admin / backup script")
        result["risk_score"] = max(5, result["risk_score"] - 30)

    if re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", lower):
        indicators.append("Hard-coded IP in URL (possible C2)")
        result["risk_score"] += 25
        result["mitre"].append("T1071.001")

    result["suspicious_indicators"] = indicators
    result["risk_score"] = min(100, result["risk_score"])
    result["verdict"] = (
        "Highly Suspicious – Download Cradle / C2 Pattern"
        if result["risk_score"] >= 70
        else "Suspicious"
        if result["risk_score"] >= 40
        else "Likely Benign / Administrative"
    )
    return result


def verify_user_and_change_request(user: str, asset: str) -> Dict[str, Any]:
    """
    Simulated ServiceNow Change Management + Okta / AD verification.
    """
    # Hard-coded authorized scenario for the benign alert
    authorized = {
        "user": "m.patel",
        "asset": "SRV-APP-PROD-11",
        "ticket": "CHG0039102",
        "title": "Scheduled Production Database Backup Window",
        "state": "Implement",
        "start": "2026-09-26T01:00:00Z",
        "end": "2026-09-26T04:00:00Z",
        "assigned_to": "m.patel",
        "approval": "Approved by Change Advisory Board"
    }

    user_l = user.lower().split("@")[0]
    asset_l = asset.lower()

    if user_l == authorized["user"] and asset_l == authorized["asset"].lower():
        return {
            "status": "success",
            "source": "Simulated-ServiceNow + Okta",
            "user_exists": True,
            "user_role": "Senior Systems Administrator",
            "is_authorized": True,
            "change_ticket": authorized,
            "notes": "Active approved change request covers the observed activity and timeframe."
        }

    # Default: no matching change
    return {
        "status": "success",
        "source": "Simulated-ServiceNow + Okta",
        "user_exists": True,
        "user_role": "Unknown / Standard",
        "is_authorized": False,
        "change_ticket": None,
        "notes": "No active approved change request found for this user/asset combination."
    }


def analyze_email_phishing(
    sender: str,
    headers: Dict[str, str],
    urls: List[str],
    attachment_hash: str
) -> Dict[str, Any]:
    """
    Full email phishing analysis chain:
    - Header auth (SPF/DKIM/DMARC)
    - URL sandbox / homoglyph check
    - Attachment detonation score
    """
    auth_results = headers.get("Authentication-Results", "").lower()
    spf = "fail" if "spf=fail" in auth_results else "pass" if "spf=pass" in auth_results else "none"
    dkim = "fail" if "dkim=fail" in auth_results else "pass" if "dkim=pass" in auth_results else "none"
    dmarc = "fail" if "dmarc=fail" in auth_results else "pass" if "dmarc=pass" in auth_results else "none"

    auth_score = 0
    if spf == "fail":
        auth_score += 30
    if dkim == "fail":
        auth_score += 25
    if dmarc == "fail":
        auth_score += 25

    # Homoglyph / suspicious URL detection
    url_findings = []
    for u in urls:
        clean = u.replace("[.]", ".").lower()
        if "micros0ft" in clean or "rnicrosoft" in clean or "paypa1" in clean:
            url_findings.append({
                "url": u,
                "verdict": "Homoglyph / Typosquat",
                "risk": 90,
                "notes": "Looks like microsoft.com but uses digit zero / other substitution."
            })
        elif any(x in clean for x in ["login", "sso", "payroll", "secure"]):
            url_findings.append({
                "url": u,
                "verdict": "Credential Harvest Pattern",
                "risk": 75,
                "notes": "Login/SSO path on non-corporate domain."
            })
        else:
            url_findings.append({"url": u, "verdict": "Unknown", "risk": 30})

    # Attachment
    att_score = 85 if attachment_hash and len(attachment_hash) == 64 else 10
    att_verdict = "Suspicious – Encrypted archive with high entropy name" if att_score > 50 else "Benign"

    overall = min(100, auth_score + max((f["risk"] for f in url_findings), default=0) // 2 + att_score // 3)

    return {
        "status": "success",
        "source": "Simulated-Proofpoint + URL Sandbox + Detonation",
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
        "auth_score": auth_score,
        "url_analysis": url_findings,
        "attachment": {
            "sha256": attachment_hash,
            "detonation_score": att_score,
            "verdict": att_verdict,
            "notes": "Encrypted ZIP commonly used to bypass content filters."
        },
        "overall_phish_score": overall,
        "verdict": "High Confidence Phishing" if overall >= 70 else "Suspicious" if overall >= 40 else "Likely Benign",
        "mitre": ["T1566.002", "T1204.002"] if overall >= 70 else []
    }


def calculate_risk_matrix(
    intel_score: float,
    asset_criticality: str,
    is_authorized_activity: bool
) -> Dict[str, Any]:
    """
    Composite risk score (0-100) following a simplified NIST / FAIR-inspired matrix.
    """
    crit_map = {"Low": 0.4, "Medium": 0.7, "High": 0.9, "Critical": 1.0}
    multiplier = crit_map.get(asset_criticality, 0.7)

    if is_authorized_activity:
        final = max(5, intel_score * 0.15)  # heavily suppressed
        band = "Low – Authorized"
    else:
        final = min(100, intel_score * multiplier + (10 if asset_criticality in ("High", "Critical") else 0))
        if final >= 80:
            band = "Critical"
        elif final >= 60:
            band = "High"
        elif final >= 35:
            band = "Medium"
        else:
            band = "Low"

    return {
        "status": "success",
        "intel_score": intel_score,
        "asset_criticality": asset_criticality,
        "is_authorized_activity": is_authorized_activity,
        "composite_risk_score": round(final, 1),
        "risk_band": band,
        "recommendation": (
            "Escalate + Contain" if final >= 70 and not is_authorized_activity
            else "Monitor / Tune" if final < 35
            else "Investigate further"
        )
    }


# ---------------------------------------------------------------------------
# Convenience registry (for agent)
# ---------------------------------------------------------------------------

TOOL_REGISTRY = {
    "lookup_ip_threat_intel": lookup_ip_threat_intel,
    "lookup_dns_internal": lookup_dns_internal,
    "parse_script_payload": parse_script_payload,
    "verify_user_and_change_request": verify_user_and_change_request,
    "analyze_email_phishing": analyze_email_phishing,
    "calculate_risk_matrix": calculate_risk_matrix,
}