# Autonomous GenAI Tier-1 SOC Analyst & Incident Response Simulator

Offline, production-style prototype of an autonomous Tier-1 SOC analyst that ingests synthetic multi-source telemetry, runs a tool-augmented reasoning loop, maps findings to MITRE ATT&CK, scores risk, and auto-dispositions incidents.

**Standards:** MITRE ATT&CK · NIST SP 800-61r2  
**Data:** 100% synthetic / defanged indicators (no real corporate data)

---

## Features

- 5 synthetic alert scenarios (EDR PowerShell→C2, AV heuristic FP, DNS tunneling, authorized change, CEO phishing)
- 6 investigation tools (IP intel, DNS/entropy, PowerShell parser, change-request verification, email phishing analysis, risk matrix)
- Thought → Tool → Observation → Verdict reasoning trace
- Enriched MITRE ATT&CK mapping (technique, tactic, description, platforms, detection guidance)
- Composite risk score (0–100) and 3-way disposition:
  - Escalate to Tier-2 (with containment actions)
  - Auto-resolve as False Positive (with tuning notes)
  - Auto-close as Explained Anomaly (authorized activity)
- Dark-mode Streamlit SOC dashboard

---

## Quick Start

```bash
git clone https://github.com/SoumyadeepNath1998/SOC-analyst-simulator-V2.git
cd SOC-analyst-simulator-V2
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS/Linux
source .venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
