"""
LogSentinel AI — Dashboard Styles & Custom CSS Injections

Applies custom premium themes, glassmorphic layout wrappers, severity colors,
and animated keyframes for status widgets. Built in Phase 8.
"""

import streamlit as st


def inject_custom_css():
    """Inject premium CSS styling overrides into the Streamlit interface."""
    css = """
    <style>
    /* Global styles and main layout styling */
    .stApp {
        background: linear-gradient(135deg, #0F172A 0%, #1E293B 100%);
        color: #F8FAFC;
    }

    /* Card Layouts with glassmorphism */
    .metric-card {
        background: rgba(30, 41, 59, 0.7);
        border: 1px solid rgba(255, 255, 255, 0.05);
        border-radius: 12px;
        padding: 20px;
        margin-bottom: 15px;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
    }

    .metric-title {
        color: #94A3B8;
        font-size: 0.85rem;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        font-weight: 600;
        margin-bottom: 5px;
    }

    .metric-value {
        color: #F8FAFC;
        font-size: 1.8rem;
        font-weight: 700;
    }

    /* Severity badges */
    .badge {
        padding: 4px 10px;
        border-radius: 6px;
        font-size: 0.75rem;
        font-weight: 700;
        text-transform: uppercase;
        display: inline-block;
        margin-bottom: 5px;
    }
    
    .badge-critical {
        background-color: rgba(239, 68, 68, 0.2);
        color: #F87171;
        border: 1px solid rgba(239, 68, 68, 0.4);
    }
    .badge-high {
        background-color: rgba(249, 115, 22, 0.2);
        color: #FB923C;
        border: 1px solid rgba(249, 115, 22, 0.4);
    }
    .badge-medium {
        background-color: rgba(245, 158, 11, 0.2);
        color: #FBBF24;
        border: 1px solid rgba(245, 158, 11, 0.4);
    }
    .badge-low {
        background-color: rgba(59, 130, 246, 0.2);
        color: #60A5FA;
        border: 1px solid rgba(59, 130, 246, 0.4);
    }
    .badge-none {
        background-color: rgba(100, 116, 139, 0.2);
        color: #94A3B8;
        border: 1px solid rgba(100, 116, 139, 0.4);
    }

    /* Attack tracer stages cards */
    .timeline-card {
        background: rgba(15, 23, 42, 0.6);
        border-radius: 8px;
        padding: 12px 16px;
        margin-bottom: 10px;
        border-left: 5px solid #475569;
    }

    .stage-reconnaissance {
        border-left-color: #3B82F6 !important; /* Blue */
    }
    .stage-access-attempt {
        border-left-color: #F59E0B !important; /* Amber */
    }
    .stage-initial-access {
        border-left-color: #EF4444 !important; /* Red */
    }
    .stage-privilege-escalation {
        border-left-color: #8B5CF6 !important; /* Purple */
    }
    .stage-none {
        border-left-color: #64748B !important; /* Slate */
    }

    .stage-badge {
        font-size: 0.7rem;
        padding: 2px 6px;
        border-radius: 4px;
        font-weight: 700;
        margin-right: 8px;
        color: #FFFFFF;
        text-transform: uppercase;
    }

    .badge-reconnaissance { background-color: #3B82F6; }
    .badge-access-attempt { background-color: #F59E0B; }
    .badge-initial-access { background-color: #EF4444; }
    .badge-privilege-escalation { background-color: #8B5CF6; }
    .badge-none { background-color: #64748B; }

    /* Pulse animation for connections */
    @keyframes pulse {
        0% { transform: scale(0.95); opacity: 0.5; }
        50% { transform: scale(1.05); opacity: 1; }
        100% { transform: scale(0.95); opacity: 0.5; }
    }
    .pulse-dot {
        height: 10px;
        width: 10px;
        border-radius: 50%;
        display: inline-block;
        margin-right: 8px;
        vertical-align: middle;
    }
    .pulse-green {
        background-color: #10B981;
        box-shadow: 0 0 8px #10B981;
        animation: pulse 2s infinite ease-in-out;
    }
    .pulse-red {
        background-color: #EF4444;
        box-shadow: 0 0 8px #EF4444;
        animation: pulse 2s infinite ease-in-out;
    }

    /* Action box */
    .action-box {
        background-color: rgba(16, 185, 129, 0.1);
        border: 1px solid rgba(16, 185, 129, 0.3);
        border-radius: 8px;
        padding: 15px;
        margin-top: 15px;
        color: #E6F4EA;
    }

    /* Logs view card code block styling */
    .log-box {
        font-family: 'Courier New', Courier, monospace;
        font-size: 0.85rem;
        background-color: #0B0F19;
        color: #10B981;
        padding: 15px;
        border-radius: 6px;
        border: 1px solid rgba(16, 185, 129, 0.2);
        max-height: 300px;
        overflow-y: auto;
        white-space: pre-wrap;
    }

    /* Trace box */
    .trace-box {
        font-family: 'Courier New', Courier, monospace;
        font-size: 0.85rem;
        background-color: #0F172A;
        color: #94A3B8;
        padding: 15px;
        border-radius: 6px;
        border: 1px solid rgba(255, 255, 255, 0.1);
        max-height: 400px;
        overflow-y: auto;
    }
    </style>
    """
    st.markdown(css, unsafe_allow_html=True)


def get_severity_badge(severity: str) -> str:
    """Return an HTML badge element based on threat severity."""
    sev = severity.upper()
    if "CRITICAL" in sev:
        return f'<span class="badge badge-critical">Critical</span>'
    elif "HIGH" in sev:
        return f'<span class="badge badge-high">High</span>'
    elif "MEDIUM" in sev:
        return f'<span class="badge badge-medium">Medium</span>'
    elif "LOW" in sev:
        return f'<span class="badge badge-low">Low</span>'
    else:
        return f'<span class="badge badge-none">None</span>'
