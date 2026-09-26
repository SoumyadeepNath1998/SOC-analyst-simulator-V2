"""
Autonomous GenAI Tier-1 SOC Analyst & Incident Response Simulator
Streamlit Dark-Mode Dashboard

Run:
    streamlit run app.py
"""

import streamlit as st
import json
from mock_alerts import get_alert, list_alert_keys, get_alert_display_name
from agent import run_autonomous_triage, SYSTEM_PROMPT

# ---------------------------------------------------------------------------
# Page config & custom CSS (dark SOC theme)
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="Autonomous Tier-1 SOC Analyst",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
    /* Dark SOC theme overrides */
    .stApp {
        background-color: #0e1117;
        color: #e0e0e0;
    }
    .block-container {
        padding-top: 1.5rem;
        padding-bottom: 2rem;
    }
    /* Severity badges */
    .badge-critical { background:#c0392b; color:white; padding:3px 10px; border-radius:4px; font-weight:600; }
    .badge-high     { background:#e67e22; color:white; padding:3px 10px; border-radius:4px; font-weight:600; }
    .badge-medium   { background:#f1c40f; color:#1a1a1a; padding:3px 10px; border-radius:4px; font-weight:600; }
    .badge-low      { background:#27ae60; color:white; padding:3px 10px; border-radius:4px; font-weight:600; }
    /* Verdict badges */
    .verdict-escalated { background:#c0392b; color:white; padding:6px 14px; border-radius:6px; font-size:1.05rem; font-weight:700; }
    .verdict-fp        { background:#27ae60; color:white; padding:6px 14px; border-radius:6px; font-size:1.05rem; font-weight:700; }
    .verdict-benign    { background:#1abc9c; color:white; padding:6px 14px; border-radius:6px; font-size:1.05rem; font-weight:700; }
    /* Cards */
    .soc-card {
        background: #1a1f2e;
        border: 1px solid #2a3040;
        border-radius: 8px;
        padding: 1rem 1.2rem;
        margin-bottom: 0.8rem;
    }
    .metric-label { font-size:0.8rem; color:#8899aa; text-transform:uppercase; letter-spacing:0.5px; }
    .metric-value { font-size:1.4rem; font-weight:700; color:#e0e0e0; }
    /* Risk meter */
    .risk-bar-bg {
        background:#2a3040; border-radius:6px; height:18px; width:100%;
    }
    .risk-bar-fill {
        height:18px; border-radius:6px;
        background: linear-gradient(90deg, #27ae60, #f1c40f, #e67e22, #c0392b);
    }
    /* Sidebar */
    section[data-testid="stSidebar"] {
        background-color: #11151f;
    }
    h1, h2, h3 { color: #e8eef7 !important; }
    .stExpander {
        background-color: #1a1f2e;
        border: 1px solid #2a3040;
    }
</style>
""", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------

with st.sidebar:
    st.markdown("## 🛡️ Autonomous Tier-1 SOC")
    st.caption("GenAI Incident Response Simulator")
    st.markdown("---")

    alert_keys = list_alert_keys()
    display_names = {k: get_alert_display_name(k) for k in alert_keys}

    selected_display = st.selectbox(
        "Select Synthetic Telemetry",
        options=list(display_names.values()),
        index=0,
    )
    # reverse lookup
    selected_key = next(k for k, v in display_names.items() if v == selected_display)

    st.markdown("")
    run_button = st.button("🚀 Ingest & Trigger Autonomous Triage", type="primary", use_container_width=True)

    st.markdown("---")
    st.markdown("### Configuration")
    mock_mode = st.toggle("Mock / Offline Mode", value=True, help="Uses deterministic tool responses – no external LLM required.")
    show_system_prompt = st.checkbox("Show Agent System Prompt", value=False)

    st.markdown("---")
    st.markdown("**Standards Alignment**")
    st.caption("MITRE ATT&CK • NIST SP 800-61r2")
    st.caption("100% Synthetic / Defanged Telemetry")

# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------

st.markdown("# Autonomous GenAI Tier-1 SOC Analyst")
st.markdown("**Incident Response Simulator** — Tool-augmented reasoning • Risk scoring • Automated disposition")

if show_system_prompt:
    with st.expander("Agent System Prompt"):
        st.code(SYSTEM_PROMPT, language="text")

# ---------------------------------------------------------------------------
# Main logic
# ---------------------------------------------------------------------------

if "last_result" not in st.session_state:
    st.session_state.last_result = None
    st.session_state.last_alert = None

if run_button:
    alert = get_alert(selected_key)
    with st.spinner("Autonomous agent executing investigation tools…"):
        result = run_autonomous_triage(alert)
    st.session_state.last_result = result
    st.session_state.last_alert = alert

# ---------------------------------------------------------------------------
# Dashboard (3-column layout)
# ---------------------------------------------------------------------------

if st.session_state.last_result is None:
    st.info("Select a telemetry scenario from the sidebar and click **Ingest & Trigger Autonomous Triage** to begin.")
    st.markdown("### Available Scenarios")
    for k in alert_keys:
        st.markdown(f"- {get_alert_display_name(k)}")
else:
    alert = st.session_state.last_alert
    result = st.session_state.last_result

    col1, col2, col3 = st.columns([1.1, 1.3, 1.2], gap="medium")

    # ================================================================
    # COLUMN 1 – Telemetry Ingestion
    # ================================================================
    with col1:
        st.markdown("### 📥 Telemetry Ingestion")

        sev = alert.get("severity", "Medium")
        sev_class = {
            "Critical": "badge-critical",
            "High": "badge-high",
            "Medium": "badge-medium",
            "Low": "badge-low",
        }.get(sev, "badge-medium")

        st.markdown(f"""
        <div class="soc-card">
            <div class="metric-label">Alert ID</div>
            <div class="metric-value" style="font-size:1.1rem">{alert.get('alert_id')}</div>
            <div style="margin-top:8px">
                <span class="{sev_class}">{sev}</span>
                &nbsp;<span style="color:#8899aa">{alert.get('source')}</span>
            </div>
            <div style="margin-top:6px;color:#a0aec0;font-size:0.85rem">
                {alert.get('category')} · {alert.get('timestamp')}
            </div>
        </div>
        """, unsafe_allow_html=True)

        # Asset / Mailbox card
        asset = alert.get("asset") or alert.get("mailbox") or {}
        user = alert.get("user") or {}
        st.markdown(f"""
        <div class="soc-card">
            <div class="metric-label">Asset / Mailbox</div>
            <div class="metric-value" style="font-size:1.05rem">{asset.get('hostname') or asset.get('address', 'N/A')}</div>
            <div style="color:#a0aec0;font-size:0.85rem;margin-top:4px">
                Criticality: <b>{asset.get('criticality', 'N/A')}</b><br>
                Owner / User: {user.get('sam_account', 'N/A')} ({user.get('role', '')})
            </div>
        </div>
        """, unsafe_allow_html=True)

        # Raw JSON
        with st.expander("Raw Alert JSON", expanded=False):
            st.json(alert)

    # ================================================================
    # COLUMN 2 – Agent Live Reasoning Trace
    # ================================================================
    with col2:
        st.markdown("### 🧠 Agent Reasoning Trace")
        st.caption("Thought → Tool Execution → Observation")

        for i, step in enumerate(result["reasoning_steps"], 1):
            label = f"Step {i}: {step['thought'][:70]}{'…' if len(step['thought']) > 70 else ''}"
            with st.expander(label, expanded=(i <= 2)):
                st.markdown(f"**Thought**  \n{step['thought']}")
                if step.get("tool"):
                    st.markdown(f"**Tool**  \n`{step['tool']}`")
                    st.markdown("**Input**")
                    st.code(json.dumps(step.get("tool_input"), indent=2), language="json")
                if step.get("observation"):
                    st.markdown("**Observation**")
                    st.json(step["observation"])

    # ================================================================
    # COLUMN 3 – ServiceNow SIR & Action Deck
    # ================================================================
    with col3:
        st.markdown("### 🎫 ServiceNow SIR & Action Deck")

        # Verdict badge
        verdict = result["verdict"]
        badge_html = {
            "TRUE_POSITIVE": f'<span class="verdict-escalated">{result["final_badge"]}</span>',
            "FALSE_POSITIVE": f'<span class="verdict-fp">{result["final_badge"]}</span>',
            "EXPLAINED_ANOMALY": f'<span class="verdict-benign">{result["final_badge"]}</span>',
        }.get(verdict, result["final_badge"])

        st.markdown(f"""
        <div class="soc-card">
            <div class="metric-label">Incident Number</div>
            <div class="metric-value">{result['sir_number']}</div>
            <div style="margin-top:10px">{badge_html}</div>
            <div style="margin-top:8px;color:#a0aec0;font-size:0.85rem">
                SLA Status: <b>{result['sir_status']}</b>
            </div>
        </div>
        """, unsafe_allow_html=True)

        # Risk score meter
        score = result["composite_risk_score"]
        pct = min(100, max(0, score))
        st.markdown(f"""
        <div class="soc-card">
            <div class="metric-label">Composite Risk Score</div>
            <div class="metric-value">{score} <span style="font-size:0.9rem;color:#8899aa">/ 100 ({result['risk_band']})</span></div>
            <div class="risk-bar-bg" style="margin-top:8px">
                <div class="risk-bar-fill" style="width:{pct}%"></div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        # Containment actions
        if result["containment_actions"]:
            st.markdown("""
            <div class="soc-card">
                <div class="metric-label">Containment Actions</div>
            """, unsafe_allow_html=True)
            for action in result["containment_actions"]:
                st.markdown(f"- 🔒 {action}")
            st.markdown("</div>", unsafe_allow_html=True)
        else:
            st.markdown("""
            <div class="soc-card">
                <div class="metric-label">Containment Actions</div>
                <div style="color:#27ae60">None required – auto-resolved</div>
            </div>
            """, unsafe_allow_html=True)

        # ---- MITRE ATT&CK Mapping (enriched) ----
        st.markdown("#### 🗺️ MITRE ATT&CK Mapping")
        mitre_enriched = result.get("mitre_enriched") or []
        primary_tactic = result.get("primary_tactic", "N/A")

        if mitre_enriched:
            st.markdown(
                f'<div class="soc-card"><span class="metric-label">Primary Tactic</span><br>'
                f'<span class="metric-value" style="font-size:1.1rem">{primary_tactic}</span></div>',
                unsafe_allow_html=True,
            )

            # Grouped by tactic for matrix-style view
            mitre_by_tactic = result.get("mitre_by_tactic") or {}
            for tactic, techs in mitre_by_tactic.items():
                with st.expander(f"**{tactic}** ({len(techs)})", expanded=True):
                    for t in techs:
                        st.markdown(
                            f"""
                            <div style="background:#151a27;border-left:3px solid #e67e22;padding:8px 12px;margin-bottom:8px;border-radius:0 6px 6px 0">
                                <a href="{t.get('url','#')}" target="_blank" style="color:#5dade2;text-decoration:none;font-weight:700">
                                    {t.get('id')}
                                </a>
                                &nbsp;–&nbsp;<b>{t.get('name')}</b><br>
                                <span style="color:#a0aec0;font-size:0.82rem">{t.get('description','')[:160]}{'…' if len(t.get('description',''))>160 else ''}</span><br>
                                <span style="color:#8899aa;font-size:0.75rem">Platforms: {', '.join(t.get('platforms', [])[:4])}</span>
                            </div>
                            """,
                            unsafe_allow_html=True,
                        )
                        if t.get("detection"):
                            st.caption(f"Detection guidance: {t['detection']}")
        else:
            st.markdown(
                '<div class="soc-card" style="color:#27ae60">No MITRE techniques mapped (benign / false-positive path)</div>',
                unsafe_allow_html=True,
            )

        # Working notes
        st.markdown("#### Analyst Working Notes")
        st.markdown(result["working_notes_md"])

# ---------------------------------------------------------------------------
# Footer
# ---------------------------------------------------------------------------
st.markdown("---")
st.caption(
    "Autonomous GenAI Tier-1 SOC Analyst Prototype  •  "
    "MITRE ATT&CK + NIST SP 800-61r2 aligned  •  "
    "100% synthetic/defanged telemetry  •  "
    "No real corporate data used"
)