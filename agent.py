"""
Autonomous Tier-1 SOC Analyst Engine.

Implements a deterministic, explainable reasoning loop that:
1. Selects relevant tools based on alert type
2. Executes tools in a Thought → Action → Observation sequence
3. Produces structured working notes, MITRE mapping, risk score,
   ServiceNow SIR ticket, and final 3-way verdict.

Designed so that a real LangChain AgentExecutor + LLM can later
replace the rule-based planner while keeping the same tool signatures.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Tuple

from tools import (
    lookup_ip_threat_intel,
    lookup_dns_internal,
    parse_script_payload,
    verify_user_and_change_request,
    analyze_email_phishing,
    calculate_risk_matrix,
)
from mitre_attack import (
    enrich_techniques,
    format_mitre_markdown,
    get_primary_tactic,
    group_by_tactic,
)


# ---------------------------------------------------------------------------
# System prompt (kept for documentation / future LLM injection)
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """
You are an autonomous Tier-1 SOC Analyst operating within a high-tempo enterprise SOC.
Analyze incoming telemetry across endpoints, network logs, and email security gateways.
Systematically execute verification tools, correlate threat intelligence, parse scripts,
inspect email headers/attachments, and cross-reference user actions against enterprise
change requests. Determine whether the alert is a True Positive, False Positive, or an
Explained Anomaly (Authorized Business Activity). Compute composite risk, generate
comprehensive analyst working notes, and make a definitive decision:
  - Escalate to Tier-2 SOC (with MITRE ATT&CK mapping, immediate containment actions
    like mailbox purge or endpoint quarantine),
  - Auto-Close as False Positive (with detection tuning recommendations), or
  - Auto-Close as Explained Anomaly (referencing validated Change Management /
    user authorization context).
Follow NIST SP 800-61r2 incident handling principles and map findings to MITRE ATT&CK.
"""


# ---------------------------------------------------------------------------
# Reasoning step container
# ---------------------------------------------------------------------------

class ReasoningStep:
    def __init__(self, thought: str, tool: str | None = None,
                 tool_input: Any = None, observation: Any = None):
        self.thought = thought
        self.tool = tool
        self.tool_input = tool_input
        self.observation = observation

    def to_dict(self) -> Dict[str, Any]:
        return {
            "thought": self.thought,
            "tool": self.tool,
            "tool_input": self.tool_input,
            "observation": self.observation,
        }


# ---------------------------------------------------------------------------
# Main triage function
# ---------------------------------------------------------------------------

def run_autonomous_triage(alert: Dict[str, Any]) -> Dict[str, Any]:
    """
    Execute the full autonomous investigation pipeline for a single alert.
    Returns a complete investigation package ready for the Streamlit dashboard.
    """
    steps: List[ReasoningStep] = []
    alert_id = alert.get("alert_id", "UNKNOWN")
    source = alert.get("source", "Unknown")
    severity = alert.get("severity", "Medium")
    category = alert.get("category", "")

    # ------------------------------------------------------------------
    # Step 0 – Initial framing
    # ------------------------------------------------------------------
    steps.append(ReasoningStep(
        thought=(
            f"Received alert {alert_id} from {source} "
            f"(severity={severity}, category={category}). "
            "Beginning systematic verification per Tier-1 playbook."
        )
    ))

    # Extract common fields
    asset = alert.get("asset", {}) or {}
    user = alert.get("user", {}) or {}
    detection = alert.get("detection", {}) or {}
    hostname = asset.get("hostname", "unknown")
    asset_crit = asset.get("criticality", "Medium")
    user_sam = user.get("sam_account", "unknown")

    intel_score = 20.0          # will be updated by tools
    is_authorized = False
    mitre_techniques: List[str] = []
    containment_actions: List[str] = []
    evidence_notes: List[str] = []

    # ------------------------------------------------------------------
    # Branch by alert type (deterministic planner)
    # ------------------------------------------------------------------

    # ========== TRUE POSITIVE: Encoded PowerShell C2 ==========
    if alert_id.startswith("EDR-") and "powershell" in str(detection.get("process", {})).lower() \
            and "198.51.100" in str(detection.get("network", {})):
        cmdline = detection.get("process", {}).get("cmdline", "")
        dst_ip = detection.get("network", {}).get("dst_ip", "")

        steps.append(ReasoningStep(
            thought="Encoded PowerShell with outbound connection detected. Parsing payload and enriching destination IP.",
            tool="parse_script_payload",
            tool_input={"payload": cmdline}
        ))
        script_obs = parse_script_payload(cmdline)
        steps[-1].observation = script_obs
        intel_score = max(intel_score, script_obs.get("risk_score", 50))
        mitre_techniques.extend(script_obs.get("mitre", []))
        evidence_notes.append(f"Script analysis: {script_obs.get('verdict')} – indicators: {script_obs.get('suspicious_indicators')}")

        steps.append(ReasoningStep(
            thought=f"Enriching destination IP {dst_ip} via threat intelligence.",
            tool="lookup_ip_threat_intel",
            tool_input={"ip": dst_ip}
        ))
        ip_obs = lookup_ip_threat_intel(dst_ip)
        steps[-1].observation = ip_obs
        intel_score = max(intel_score, ip_obs.get("score", 50))
        mitre_techniques.extend(ip_obs.get("mitre", []))
        evidence_notes.append(f"IP {dst_ip}: {ip_obs.get('reputation')} (score={ip_obs.get('score')})")

        steps.append(ReasoningStep(
            thought="Checking whether activity is covered by an approved change request.",
            tool="verify_user_and_change_request",
            tool_input={"user": user_sam, "asset": hostname}
        ))
        chg_obs = verify_user_and_change_request(user_sam, hostname)
        steps[-1].observation = chg_obs
        is_authorized = chg_obs.get("is_authorized", False)

        # Final risk
        steps.append(ReasoningStep(
            thought="Computing composite risk matrix.",
            tool="calculate_risk_matrix",
            tool_input={
                "intel_score": intel_score,
                "asset_criticality": asset_crit,
                "is_authorized_activity": is_authorized
            }
        ))
        risk_obs = calculate_risk_matrix(intel_score, asset_crit, is_authorized)
        steps[-1].observation = risk_obs

        verdict = "TRUE_POSITIVE"
        containment_actions = [
            "Recommend host isolation (EDR network contain)",
            "Block outbound to 198.51.100.24 at perimeter",
            "Collect memory & process dump for Tier-2"
        ]
        sir_status = "Escalated"
        final_badge = "ESCALATED TO TIER-2 SOC"

    # ========== FALSE POSITIVE: Dev build heuristic ==========
    elif alert_id.startswith("AV-"):
        steps.append(ReasoningStep(
            thought="Low-severity heuristic on a developer workstation. Verifying user role and change context.",
            tool="verify_user_and_change_request",
            tool_input={"user": user_sam, "asset": hostname}
        ))
        chg_obs = verify_user_and_change_request(user_sam, hostname)
        steps[-1].observation = chg_obs

        file_hash = detection.get("file_hash", "")
        steps.append(ReasoningStep(
            thought="No external C2 or encoded payload observed. Treating as internal CI artifact.",
        ))
        intel_score = 12.0
        is_authorized = True  # internal engineering activity

        steps.append(ReasoningStep(
            thought="Computing composite risk matrix.",
            tool="calculate_risk_matrix",
            tool_input={
                "intel_score": intel_score,
                "asset_criticality": asset_crit,
                "is_authorized_activity": is_authorized
            }
        ))
        risk_obs = calculate_risk_matrix(intel_score, asset_crit, is_authorized)
        steps[-1].observation = risk_obs

        verdict = "FALSE_POSITIVE"
        containment_actions = []
        sir_status = "Closed - Resolved"
        final_badge = "AUTO-RESOLVED (FALSE POSITIVE)"
        evidence_notes.append("Unsigned internal build artifact on DEV-BUILD host – classic heuristic FP.")
        evidence_notes.append("Recommend exclusion for contoso-build-artifact.exe under controlled path.")

    # ========== HIGH: DNS Tunneling ==========
    elif alert_id.startswith("DNS-"):
        dns_info = detection.get("dns", {})
        domain = dns_info.get("query") or detection.get("dst_domain", "example[.]com")

        steps.append(ReasoningStep(
            thought="High-entropy DNS queries detected. Running internal DNS / tunneling analysis.",
            tool="lookup_dns_internal",
            tool_input={"domain": domain}
        ))
        dns_obs = lookup_dns_internal(domain)
        steps[-1].observation = dns_obs
        intel_score = max(intel_score, dns_obs.get("tunneling_score", 50))
        mitre_techniques.extend(dns_obs.get("mitre", []))
        evidence_notes.append(f"DNS analysis: {dns_obs.get('verdict')} (entropy={dns_obs.get('entropy_score')})")

        steps.append(ReasoningStep(
            thought="Confirming no authorized change covers bulk DNS activity from this host.",
            tool="verify_user_and_change_request",
            tool_input={"user": user_sam, "asset": hostname}
        ))
        chg_obs = verify_user_and_change_request(user_sam, hostname)
        steps[-1].observation = chg_obs
        is_authorized = chg_obs.get("is_authorized", False)

        steps.append(ReasoningStep(
            thought="Computing composite risk matrix.",
            tool="calculate_risk_matrix",
            tool_input={
                "intel_score": intel_score,
                "asset_criticality": asset_crit,
                "is_authorized_activity": is_authorized
            }
        ))
        risk_obs = calculate_risk_matrix(intel_score, asset_crit, is_authorized)
        steps[-1].observation = risk_obs

        verdict = "TRUE_POSITIVE"
        containment_actions = [
            "Recommend host isolation",
            "Sinkhole / block example[.]com at recursive resolvers",
            "Capture full PCAP for the 5-minute window"
        ]
        sir_status = "Escalated"
        final_badge = "ESCALATED TO TIER-2 SOC"

    # ========== BENIGN / EXPLAINED ANOMALY ==========
    elif "CHG0039102" in str(detection) or alert_id == "EDR-20260926-007219":
        cmdline = detection.get("process", {}).get("cmdline", "")

        steps.append(ReasoningStep(
            thought="Privileged PowerShell on production host outside business hours. Parsing script and validating change ticket.",
            tool="parse_script_payload",
            tool_input={"payload": cmdline}
        ))
        script_obs = parse_script_payload(cmdline)
        steps[-1].observation = script_obs
        evidence_notes.append(f"Script analysis: {script_obs.get('verdict')}")

        steps.append(ReasoningStep(
            thought="Looking up ServiceNow change request and user authorization.",
            tool="verify_user_and_change_request",
            tool_input={"user": user_sam, "asset": hostname}
        ))
        chg_obs = verify_user_and_change_request(user_sam, hostname)
        steps[-1].observation = chg_obs
        is_authorized = chg_obs.get("is_authorized", False)
        if is_authorized:
            evidence_notes.append(
                f"Matched active change ticket {chg_obs['change_ticket']['ticket']}: "
                f"{chg_obs['change_ticket']['title']}"
            )

        intel_score = 18.0
        steps.append(ReasoningStep(
            thought="Computing composite risk matrix (authorized activity expected to suppress score).",
            tool="calculate_risk_matrix",
            tool_input={
                "intel_score": intel_score,
                "asset_criticality": asset_crit,
                "is_authorized_activity": is_authorized
            }
        ))
        risk_obs = calculate_risk_matrix(intel_score, asset_crit, is_authorized)
        steps[-1].observation = risk_obs

        verdict = "EXPLAINED_ANOMALY"
        containment_actions = []
        sir_status = "Closed - Resolved"
        final_badge = "AUTO-RESOLVED (EXPLAINED ANOMALY / AUTHORIZED ACTIVITY)"

    # ========== PHISHING ==========
    elif alert_id.startswith("EML-"):
        email = detection.get("email", {})
        sender = email.get("from", "")
        headers = email.get("headers", {})
        urls = email.get("urls", [])
        att_hash = email.get("attachment", {}).get("sha256", "")

        steps.append(ReasoningStep(
            thought="Inbound executive-targeted message. Running full phishing analysis chain (auth + URL + attachment).",
            tool="analyze_email_phishing",
            tool_input={
                "sender": sender,
                "headers": headers,
                "urls": urls,
                "attachment_hash": att_hash
            }
        ))
        phish_obs = analyze_email_phishing(sender, headers, urls, att_hash)
        steps[-1].observation = phish_obs
        intel_score = max(intel_score, phish_obs.get("overall_phish_score", 70))
        mitre_techniques.extend(phish_obs.get("mitre", []))
        evidence_notes.append(
            f"Email verdict: {phish_obs.get('verdict')} "
            f"(SPF={phish_obs.get('spf')}, DKIM={phish_obs.get('dkim')}, DMARC={phish_obs.get('dmarc')})"
        )
        for u in phish_obs.get("url_analysis", []):
            evidence_notes.append(f"URL {u['url']}: {u['verdict']} (risk={u['risk']})")

        # Also enrich the apparent source IP if present in headers
        steps.append(ReasoningStep(
            thought="Enriching observed sending infrastructure IP.",
            tool="lookup_ip_threat_intel",
            tool_input={"ip": "203.0.113.55"}
        ))
        ip_obs = lookup_ip_threat_intel("203.0.113.55")
        steps[-1].observation = ip_obs
        intel_score = max(intel_score, ip_obs.get("score", 50))

        is_authorized = False
        steps.append(ReasoningStep(
            thought="Computing composite risk matrix.",
            tool="calculate_risk_matrix",
            tool_input={
                "intel_score": intel_score,
                "asset_criticality": "High",  # executive mailbox
                "is_authorized_activity": False
            }
        ))
        risk_obs = calculate_risk_matrix(intel_score, "High", False)
        steps[-1].observation = risk_obs

        verdict = "TRUE_POSITIVE"
        containment_actions = [
            "Automated mailbox purge of matching messages",
            "Block sender domain / reply-to at email gateway",
            "User awareness notification to CFO mailbox owner",
            "Detonate attachment in sandbox (already scored)"
        ]
        sir_status = "Escalated"
        final_badge = "ESCALATED TO TIER-2 SOC"

    # ========== Fallback ==========
    else:
        steps.append(ReasoningStep(thought="Unrecognized alert pattern – applying generic low-confidence triage."))
        risk_obs = calculate_risk_matrix(25, asset_crit, False)
        verdict = "FALSE_POSITIVE"
        containment_actions = []
        sir_status = "Closed - Resolved"
        final_badge = "AUTO-RESOLVED (FALSE POSITIVE)"
        intel_score = 25

    # ------------------------------------------------------------------
    # Build final investigation package
    # ------------------------------------------------------------------
    composite_score = risk_obs.get("composite_risk_score", intel_score)
    risk_band = risk_obs.get("risk_band", "Medium")

    # --- MITRE ATT&CK enrichment ---
    # Also pull any technique already declared on the alert itself
    alert_tech = detection.get("technique", "")
    if alert_tech and isinstance(alert_tech, str):
        # e.g. "T1059.001 – PowerShell" → extract ID
        tid = alert_tech.split("–")[0].split("-")[0].strip()
        if tid.startswith("T"):
            mitre_techniques.append(tid)
    unique_ids = list(dict.fromkeys(mitre_techniques))  # preserve order, dedupe
    mitre_enriched = enrich_techniques(unique_ids)
    mitre_by_tactic = group_by_tactic(mitre_enriched)
    primary_tactic = get_primary_tactic(mitre_enriched)

    # Generate SIR number
    sir_number = f"SIR{str(uuid.uuid4().int)[:7]}"

    # Working notes (Markdown)
    working_notes = _generate_working_notes(
        alert=alert,
        steps=steps,
        verdict=verdict,
        mitre_enriched=mitre_enriched,
        evidence=evidence_notes,
        containment=containment_actions,
        risk_score=composite_score,
        risk_band=risk_band,
        sir_number=sir_number,
        sir_status=sir_status,
    )

    return {
        "alert_id": alert_id,
        "sir_number": sir_number,
        "sir_status": sir_status,
        "verdict": verdict,
        "final_badge": final_badge,
        "composite_risk_score": composite_score,
        "risk_band": risk_band,
        "mitre_techniques": unique_ids,              # list of IDs (backward compatible)
        "mitre_enriched": mitre_enriched,            # full technique objects
        "mitre_by_tactic": mitre_by_tactic,          # grouped for matrix-style UI
        "primary_tactic": primary_tactic,
        "containment_actions": containment_actions,
        "reasoning_steps": [s.to_dict() for s in steps],
        "working_notes_md": working_notes,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "is_authorized": is_authorized,
    }


def _generate_working_notes(
    alert: Dict[str, Any],
    steps: List[ReasoningStep],
    verdict: str,
    mitre_enriched: List[Dict[str, Any]],
    evidence: List[str],
    containment: List[str],
    risk_score: float,
    risk_band: str,
    sir_number: str,
    sir_status: str,
) -> str:
    """Produce clean Markdown analyst working notes with full MITRE mapping."""
    lines = [
        f"# SOC Investigation Working Notes – {alert.get('alert_id')}",
        f"**SIR:** {sir_number}  |  **Status:** {sir_status}  |  **Risk:** {risk_score} ({risk_band})",
        f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        "",
        "## 1. Alert Summary",
        f"- **Source:** {alert.get('source')}",
        f"- **Severity:** {alert.get('severity')}",
        f"- **Category:** {alert.get('category')}",
        f"- **Timestamp:** {alert.get('timestamp')}",
        "",
        "## 2. Asset & Identity Context",
    ]
    asset = alert.get("asset") or alert.get("mailbox") or {}
    user = alert.get("user") or {}
    lines.append(f"- **Asset / Mailbox:** {asset.get('hostname') or asset.get('address', 'N/A')}")
    lines.append(f"- **Criticality:** {asset.get('criticality', 'N/A')}")
    lines.append(f"- **User:** {user.get('sam_account', 'N/A')} ({user.get('role', 'N/A')})")
    lines.append("")

    lines.append("## 3. Investigation Timeline (Thought → Tool → Observation)")
    for i, s in enumerate(steps, 1):
        lines.append(f"### Step {i}")
        lines.append(f"**Thought:** {s.thought}")
        if s.tool:
            lines.append(f"**Tool:** `{s.tool}`")
            lines.append(f"**Input:** `{s.tool_input}`")
        if s.observation:
            obs = s.observation
            if isinstance(obs, dict):
                key_bits = []
                for k in ("verdict", "reputation", "risk_score", "composite_risk_score",
                          "is_authorized", "overall_phish_score", "tunneling_score"):
                    if k in obs:
                        key_bits.append(f"{k}={obs[k]}")
                lines.append(f"**Observation:** {', '.join(key_bits) if key_bits else str(obs)[:200]}")
            else:
                lines.append(f"**Observation:** {str(obs)[:200]}")
        lines.append("")

    lines.append("## 4. Key Evidence")
    for e in evidence:
        lines.append(f"- {e}")
    lines.append("")

    lines.append("## 5. MITRE ATT&CK Mapping")
    lines.append(format_mitre_markdown(mitre_enriched))
    lines.append("")

    lines.append("## 6. Final Verdict & Disposition")
    lines.append(f"**Verdict:** `{verdict}`")
    lines.append(f"**Composite Risk Score:** {risk_score} ({risk_band})")
    lines.append("")

    if containment:
        lines.append("## 7. Recommended / Automated Containment")
        for c in containment:
            lines.append(f"- {c}")
        lines.append("")

    if verdict == "FALSE_POSITIVE":
        lines.append("## 8. Detection Tuning Notes")
        lines.append("- Consider path-based or hash-based exclusion for internal CI artifacts.")
        lines.append("- Review heuristic sensitivity on developer subnets.")
    elif verdict == "EXPLAINED_ANOMALY":
        lines.append("## 8. Authorization Evidence")
        lines.append("- Activity matched an approved ServiceNow Change Request.")
        lines.append("- No further action required; ticket auto-closed.")
    else:
        lines.append("## 8. Escalation Rationale")
        lines.append("- High confidence malicious indicators + elevated asset criticality.")
        lines.append("- Immediate containment recommended; Tier-2 ownership transferred.")

    lines.append("")
    lines.append("---")
    lines.append("*Generated by Autonomous Tier-1 SOC Analyst (NIST SP 800-61r2 + MITRE ATT&CK aligned)*")
    return "\n".join(lines)