"""
LogSentinel AI — Streamlit Dashboard

A premium threat intelligence interface for security analysts. Implements log ingestion
file uploads, agent queries, timeline traces, and analytical charts.
Built in Phase 8.
"""

import datetime
import os
from typing import Dict, Any, List

import pandas as pd
import streamlit as st

# Components
from components.styles import inject_custom_css, get_severity_badge
from components.utils import APIClient

# Page configuration
st.set_page_config(
    page_title="LogSentinel AI — Threat Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Apply premium styles
inject_custom_css()

# ==============================================================================
# SIDEBAR: Backend Connection Status
# ==============================================================================
st.sidebar.markdown("<h2 style='margin-bottom:0;'>🛡️ LogSentinel AI</h2>", unsafe_allow_html=True)
st.sidebar.markdown("<p style='color:#94A3B8; font-size:0.8rem;'>SecOps AI Log Analyst Agent</p>", unsafe_allow_html=True)
st.sidebar.divider()

st.sidebar.subheader("API Connections")

# Get defaults from environment
DEFAULT_URL = os.getenv("API_BASE_URL", "http://localhost:8080")
DEFAULT_KEY = os.getenv("API_KEY", "")

api_url = st.sidebar.text_input("FastAPI Endpoint URL", value=DEFAULT_URL)
api_key = st.sidebar.text_input("API Access Key (X-API-Key)", value=DEFAULT_KEY, type="password")

# Instantiate API client
client = APIClient(base_url=api_url, api_key=api_key)

# Health Check
health = client.check_health()
is_healthy = health.get("status") == "healthy"

# Connection Status Cards
if is_healthy:
    st.sidebar.markdown(
        '<div class="metric-card" style="padding:12px; border-color:rgba(16,185,129,0.3);">'
        '<span class="pulse-dot pulse-green"></span>'
        '<span style="color:#10B981; font-weight:700; font-size:0.9rem;">SOC Agent Online</span>'
        '</div>',
        unsafe_allow_html=True
    )
    
    # Detail connections
    db_ok = health.get("postgres") == "connected"
    chroma_ok = health.get("chromadb") == "connected"
    openai_ok = health.get("openai") == "reachable"
    
    col1, col2 = st.sidebar.columns(2)
    with col1:
        st.caption("PostgreSQL")
        st.markdown(f"{'🟢 Connected' if db_ok else '🔴 Offline'}")
        
        st.caption("ChromaDB")
        st.markdown(f"{'🟢 Connected' if chroma_ok else '🔴 Offline'}")
    with col2:
        st.caption("OpenAI API")
        st.markdown(f"{'🟢 Reachable' if openai_ok else '🔴 Offline'}")
else:
    err_msg = health.get("error", "Unreachable")
    st.sidebar.markdown(
        f'<div class="metric-card" style="padding:12px; border-color:rgba(239,68,68,0.3);">'
        f'<span class="pulse-dot pulse-red"></span>'
        f'<span style="color:#EF4444; font-weight:700; font-size:0.9rem;">Backend Offline</span>'
        f'<p style="font-size:0.75rem; color:#94A3B8; margin-top:5px; margin-bottom:0;">{err_msg}</p>'
        f'</div>',
        unsafe_allow_html=True
    )

st.sidebar.divider()
st.sidebar.caption("System Environment: Python 3.14.0 | ChromaDB 1.0 | PostgreSQL 16")

# ==============================================================================
# MAIN DASHBOARD PANELS
# ==============================================================================
st.title("Threat Intelligence Control Center")

tab_ingest, tab_analyse, tab_reports, tab_analytics = st.tabs([
    "📥 Ingest Logs", 
    "🔍 AI Threat Agent", 
    "📋 Forensic Incident Audit", 
    "📊 Security Analytics"
])

# ------------------------------------------------------------------------------
# TAB 1: Log Ingestion
# ------------------------------------------------------------------------------
with tab_ingest:
    st.header("Raw Security Log Ingestion")
    st.write("Upload server, authentication, or network log files to parse, window into 15-minute intervals, and embed in the ChromaDB vector store.")

    col_upload, col_help = st.columns([2, 1])

    with col_upload:
        uploaded_file = st.file_uploader("Select raw log file...", type=["log", "txt", "out"])
        log_source = st.selectbox(
            "Log Format Source",
            options=["auto", "apache", "auth", "syslog"],
            format_func=lambda x: "Auto-Detect Format" if x == "auto" else f"{x.upper()} Server Logs"
        )
        
        btn_upload = st.button("Ingest Log File", disabled=(uploaded_file is None or not is_healthy))

        if btn_upload and uploaded_file is not None:
            with st.spinner("Parsing format, aligning window timeframes, and building embeddings..."):
                file_bytes = uploaded_file.read()
                result = client.upload_log(uploaded_file.name, file_bytes, log_source)
                
                if result.get("status") == "success":
                    st.success("Log Ingestion Complete!")
                    
                    # Highlight stats
                    c1, c2, c3 = st.columns(3)
                    with c1:
                        st.metric("Source Detected", str(result.get("log_source")).upper())
                    with c2:
                        st.metric("Entries Parsed", result.get("entries_parsed", 0))
                    with c3:
                        st.metric("Vector Chunks", result.get("chunks_created", 0))
                else:
                    st.error(f"Ingestion failed: {result.get('error', 'Unknown Error')}")

    with col_help:
        st.markdown(
            """
            <div class="metric-card" style="margin-top:25px;">
            <h4>Supported formats</h4>
            <ul>
                <li><strong>Apache logs</strong>: Standard Combined HTTP formats. Detects SQL injections, web exploits, and paths scans.</li>
                <li><strong>Auth logs</strong>: Linux sshd authentication traces. Identifies SSH brute forces, invalid logins, and successful privilege escalation.</li>
                <li><strong>Syslog logs</strong>: Kernel, service events, and UFW firewall block lists. Detects packet floods and resource warnings.</li>
            </ul>
            </div>
            """,
            unsafe_allow_html=True
        )

# ------------------------------------------------------------------------------
# TAB 2: Threat Analysis Agent
# ------------------------------------------------------------------------------
with tab_analyse:
    st.header("AI Security Analyst Agent (ReAct Loop)")
    st.write("Trigger our LLM security agent to execute information-gathering actions, correlate indicators of compromise, and build threat timelines.")

    # Preset prompts
    presets = [
        "Select query preset...",
        "Analyze authentication logs for SSH brute force attempts and successful logouts.",
        "Check HTTP logs for SQL injection indicators, remote code execution attacks, and directory probing.",
        "Trace network firewall anomalies and kernel service state changes.",
        "Reconstruct any multi-stage intrusion chains across all logs."
    ]
    preset_query = st.selectbox("Prompt Presets", options=presets)
    
    # Target query input
    default_text = "" if preset_query == presets[0] else preset_query
    query_text = st.text_area("Analysis Goal / Query", value=default_text, height=80, 
                             placeholder="Search indicators of compromise, e.g., 'Find invalid user attempts and trace any subsequent privilege escalation'")

    col_f1, col_f2, col_f3 = st.columns(3)
    with col_f1:
        log_source_sel = st.selectbox("Filter Log Source", options=["auto", "apache", "auth", "syslog"], key="analyse_log_source")
    with col_f2:
        max_chunks_sel = st.slider("Max Chunks to Fetch", min_value=1, max_value=15, value=5)
    with col_f3:
        st.write("") # placeholder alignment

    btn_analyse = st.button("Trigger Threat Analysis", disabled=(not query_text or not is_healthy))

    if btn_analyse:
        with st.spinner("AI agent active: Gathers logs, correlates entities, and runs verification loops..."):
            report = client.trigger_analysis(
                query=query_text,
                log_source=log_source_sel,
                max_chunks=max_chunks_sel
            )
            
            if "status" in report and report["status"] == "error":
                st.error(f"Analysis Agent Error: {report.get('error')}")
            else:
                # Render results in structured intelligence view
                st.markdown("### Incident Report Results")
                
                # Check detection state
                threat_detected = report.get("threat_detected", False)
                state_badge = (
                    '<span style="background-color:rgba(239,68,68,0.2); color:#F87171; border:1px solid #EF4444; '
                    'padding:5px 12px; border-radius:15px; font-weight:700;">🚨 SECURITY THREAT DETECTED</span>'
                    if threat_detected else
                    '<span style="background-color:rgba(16,185,129,0.2); color:#34D399; border:1px solid #10B981; '
                    'padding:5px 12px; border-radius:15px; font-weight:700;">🟢 SECURE / NO ACTIVE THREAT</span>'
                )
                st.markdown(state_badge, unsafe_allow_html=True)
                st.write("")

                # Metrics block
                m_col1, m_col2, m_col3 = st.columns(3)
                with m_col1:
                    st.markdown(
                        f'<div class="metric-card">'
                        f'<div class="metric-title">Threat Classification</div>'
                        f'<div class="metric-value" style="font-size:1.4rem;">{report.get("threat_type") or "N/A"}</div>'
                        f'</div>',
                        unsafe_allow_html=True
                    )
                with m_col2:
                    st.markdown(
                        f'<div class="metric-card">'
                        f'<div class="metric-title">Severity Level</div>'
                        f'<div style="margin-top:5px;">{get_severity_badge(report.get("severity", "NONE"))}</div>'
                        f'</div>',
                        unsafe_allow_html=True
                    )
                with m_col3:
                    st.markdown(
                        f'<div class="metric-card">'
                        f'<div class="metric-title">AI Confidence Score</div>'
                        f'<div class="metric-value">{int(report.get("confidence_score", 0.0) * 100)}%</div>'
                        f'</div>',
                        unsafe_allow_html=True
                    )

                # Summary details
                st.markdown("#### Executive Summary")
                st.info(report.get("summary", "No summary provided."))

                # Action details
                st.markdown("#### Recommended Mitigation Response")
                st.markdown(
                    f'<div class="action-box">'
                    f'<strong>Mitigation Response Plan:</strong><br/>{report.get("recommended_action", "No recommendations.")}'
                    f'</div>',
                    unsafe_allow_html=True
                )
                
                # Mitre Timeline events mapping
                timeline = report.get("timeline", [])
                st.markdown("#### Chronological Security Attack Trace")
                if not timeline:
                    st.write("No timeline events generated.")
                else:
                    for idx, event in enumerate(timeline):
                        # Stage class
                        stage_slug = str(event.get("stage", "none")).lower().replace(" ", "-")
                        st.markdown(
                            f'<div class="timeline-card stage-{stage_slug}">'
                            f'<span class="stage-badge badge-{stage_slug}">{event.get("stage")}</span>'
                            f'<strong style="color:#F1F5F9;">{event.get("timestamp")}</strong>'
                            f'<p style="margin-top:6px; color:#E2E8F0; font-size:0.9rem;">{event.get("significance")}</p>'
                            f'<code style="font-size:0.8rem; color:#94A3B8; background-color:#0F172A; padding:2px 6px; border-radius:4px;">Log Line: {event.get("log_line")}</code>'
                            f'</div>',
                            unsafe_allow_html=True
                        )

# ------------------------------------------------------------------------------
# TAB 3: Incident Reports History & Forensics
# ------------------------------------------------------------------------------
with tab_reports:
    st.header("Forensic Incident Audit Trail")
    st.write("Audit past incident reports, trace forensic message trees, and inspect exact log context retrieved by the analyst agent.")

    # Retrieve all reports
    reports = client.list_reports(limit=100)
    
    if not reports:
        st.write("No incident reports found. Trigger an analysis on Tab 2 to generate logs.")
    else:
        # Build DataFrame for easy tabular view
        reports_data = []
        for r in reports:
            reports_data.append({
                "Incident ID": r.get("id"),
                "Created At": r.get("created_at"),
                "Threat Detected": "🚨 Yes" if r.get("threat_detected") else "🟢 No",
                "Threat Type": r.get("threat_type") or "None",
                "Severity": r.get("severity", "NONE").upper(),
                "Confidence": f"{int(r.get('confidence_score', 0) * 100)}%",
                "Summary": r.get("summary")
            })
        
        df_reports = pd.DataFrame(reports_data)
        st.dataframe(
            df_reports[["Created At", "Threat Detected", "Threat Type", "Severity", "Confidence", "Summary"]],
            use_container_width=True
        )

        st.divider()
        st.subheader("Select Incident for Deep-Dive Forensics")
        
        # Selectbox to load full analysis details
        report_options = {r.get("id"): f"{r.get('created_at')} - {r.get('threat_type') or 'Clean'} ({r.get('severity')})" for r in reports}
        selected_id = st.selectbox("Choose Report UUID", options=list(report_options.keys()), format_func=lambda x: report_options[x])

        if selected_id:
            # Fetch specific report details
            report_detail = client.get_report(selected_id)
            if report_detail:
                # Layout incident summary
                st.markdown(f"### Report Details: `{selected_id}`")
                
                col_det1, col_det2 = st.columns([2, 1])
                with col_det1:
                    st.markdown("#### Summary")
                    st.info(report_detail.get("summary"))
                    st.markdown("#### Action Plan")
                    st.warning(report_detail.get("recommended_action"))
                with col_det2:
                    st.write("")
                    st.markdown(f"**Threat State:** {'🚨 Detected' if report_detail.get('threat_detected') else '🟢 None'}")
                    st.markdown(f"**Type:** {report_detail.get('threat_type') or 'N/A'}")
                    st.markdown(f"**Severity:** `{report_detail.get('severity')}`")
                    st.markdown(f"**Confidence:** `{int(report_detail.get('confidence_score', 0) * 100)}%`")
                
                # Load agent trace and logs analyses
                analyses = client.get_analyses(selected_id)
                if analyses:
                    st.write("")
                    st.subheader("Forensic Agent Artifacts")
                    
                    # Renders serialized message logs
                    with st.expander("🛠️ View Agent Decision Trace (ReAct Step-by-Step History)"):
                        st.write("Below is the exact chronological conversation trace of the LLM agent selecting search tools to gather evidence:")
                        for analysis_run in analyses:
                            raw_responses = analysis_run.get("raw_response", [])
                            for idx, msg in enumerate(raw_responses):
                                role = msg.get("role", "system").upper()
                                content = msg.get("content", "")
                                
                                # Render bubbles
                                if role == "SYSTEM":
                                    st.markdown(f"🤖 **Agent Prompt System Template:**")
                                    st.markdown(f"<div class='trace-box'>{content}</div>", unsafe_allow_html=True)
                                elif role == "ASSISTANT":
                                    st.markdown(f"🧠 **Agent Thought / Action Selection:**")
                                    # Format tool calls if present
                                    tool_calls = msg.get("tool_calls", [])
                                    if tool_calls:
                                        st.markdown(f"<div class='trace-box' style='color:#FB923C;'>Calls Tools: {tool_calls}</div>", unsafe_allow_html=True)
                                    else:
                                        st.markdown(f"<div class='trace-box' style='color:#60A5FA;'>{content}</div>", unsafe_allow_html=True)
                                elif role == "TOOL":
                                    st.markdown(f"🔌 **Tool Output Result:**")
                                    st.markdown(f"<div class='trace-box' style='color:#34D399;'>{content}</div>", unsafe_allow_html=True)
                                else:
                                    st.markdown(f"👤 **User Query:**")
                                    st.markdown(f"<div class='trace-box' style='color:#F8FAFC;'>{content}</div>", unsafe_allow_html=True)
                                st.write("")

                    # Show raw log dumps
                    with st.expander("📁 View Retrieved Raw Log Content"):
                        st.write("This log content was retrieved from the database vectors by the security analyst agent during search cycles:")
                        for analysis_run in analyses:
                            retrieved = analysis_run.get("logs_retrieved", "")
                            st.markdown(f"<div class='log-box'>{retrieved}</div>", unsafe_allow_html=True)

# ------------------------------------------------------------------------------
# TAB 4: SOC Analytics
# ------------------------------------------------------------------------------
with tab_analytics:
    st.header("Executive Security Analytics Dashboard")
    st.write("Review real-time dashboards mapping metric volumes, threat distributions, and agent confidence ranges.")

    reports_analytics = client.list_reports(limit=200)
    
    if not reports_analytics:
        st.write("No report metrics available. Populate the system on Tab 2.")
    else:
        # Build metric collections
        total_runs = len(reports_analytics)
        threat_count = sum(1 for r in reports_analytics if r.get("threat_detected"))
        threat_rate = (threat_count / total_runs) * 100 if total_runs > 0 else 0.0
        
        severities = [r.get("severity", "NONE").upper() for r in reports_analytics]
        df_sev = pd.DataFrame(severities, columns=["Severity"])
        sev_counts = df_sev["Severity"].value_counts()
        
        avg_confidence = sum(r.get("confidence_score", 0.0) for r in reports_analytics) / total_runs if total_runs > 0 else 0.0

        # KPI metric columns
        ak1, ak2, ak3, ak4 = st.columns(4)
        with ak1:
            st.markdown(
                f'<div class="metric-card">'
                f'<div class="metric-title">Total Agent Runs</div>'
                f'<div class="metric-value">{total_runs}</div>'
                f'</div>',
                unsafe_allow_html=True
            )
        with ak2:
            st.markdown(
                f'<div class="metric-card">'
                f'<div class="metric-title">Threat Incidents</div>'
                f'<div class="metric-value" style="color:#F87171;">{threat_count}</div>'
                f'</div>',
                unsafe_allow_html=True
            )
        with ak3:
            st.markdown(
                f'<div class="metric-card">'
                f'<div class="metric-title">Incident Attack Rate</div>'
                f'<div class="metric-value">{threat_rate:.1f}%</div>'
                f'</div>',
                unsafe_allow_html=True
            )
        with ak4:
            st.markdown(
                f'<div class="metric-card">'
                f'<div class="metric-title">Average Confidence</div>'
                f'<div class="metric-value">{int(avg_confidence * 100)}%</div>'
                f'</div>',
                unsafe_allow_html=True
            )

        # Charts layout
        st.write("")
        c_col1, c_col2 = st.columns(2)
        with c_col1:
            st.subheader("Severity Levels Distribution")
            st.bar_chart(sev_counts)
        with c_col2:
            st.subheader("Agent Detection Breakdown")
            df_threat_split = pd.DataFrame([
                {"State": "Threats", "Count": threat_count},
                {"State": "Normal / Secure", "Count": total_runs - threat_count}
            ]).set_index("State")
            st.bar_chart(df_threat_split)
