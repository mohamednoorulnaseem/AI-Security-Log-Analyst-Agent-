"""
LogSentinel AI — Incident Report Schema

Pydantic models that define the structured output of the agent.
Every analysis produces an IncidentReport that is:
  - Machine-parseable (stored as JSON in PostgreSQL)
  - Human-readable (displayed in Streamlit dashboard)
  - Consistently shaped (no missing fields, ever)

The LLM is forced to produce output matching this schema
via LangChain's structured output feature.
"""

from typing import Literal, Optional
from pydantic import BaseModel, Field


class TimelineEvent(BaseModel):
    """A single event in the attack timeline.

    Each event links a specific log line to its security significance.
    This is the evidence chain — it lets an analyst verify the agent's
    reasoning by tracing back to the original log data.
    """
    timestamp: str = Field(
        description="ISO 8601 timestamp of the event"
    )
    log_line: str = Field(
        description="The original log line (verbatim from source)"
    )
    significance: str = Field(
        description=(
            "Why this event matters in the security context. "
            "Example: 'Fifth consecutive failed SSH login from same IP — "
            "indicates brute force attempt reaching critical threshold'"
        )
    )


class IncidentReport(BaseModel):
    """Structured incident report produced by the security analyst agent.

    This is the core output schema. Every field is required and typed
    so that downstream consumers (API, dashboard, PostgreSQL) can
    rely on a consistent shape.
    """
    summary: str = Field(
        description=(
            "Plain English summary of what happened, written for a "
            "security analyst who hasn't seen the raw logs. 2-4 sentences. "
            "Include the key facts: who, what, when, from where."
        )
    )

    threat_detected: bool = Field(
        description="True if any security threat was identified in the analysed logs"
    )

    threat_type: Optional[str] = Field(
        default=None,
        description=(
            "Classification of the threat. Examples: 'Brute Force SSH Attack', "
            "'SQL Injection Attempt', 'Port Scanning', 'Privilege Escalation', "
            "'Denial of Service', 'Lateral Movement', 'Data Exfiltration Attempt'. "
            "None if no threat detected."
        )
    )

    severity: Literal["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"] = Field(
        description=(
            "Severity rating. "
            "NONE = no threat. "
            "LOW = reconnaissance or information gathering, no impact. "
            "MEDIUM = failed attack attempt, blocked by controls. "
            "HIGH = successful attack step, requires investigation. "
            "CRITICAL = confirmed breach, active exploitation, or data exposure."
        )
    )

    timeline: list[TimelineEvent] = Field(
        default_factory=list,
        description=(
            "Chronological sequence of relevant log events with their "
            "security significance. Include all events that contributed "
            "to the threat assessment, not just the suspicious ones. "
            "Normal events that provide context are valuable too."
        )
    )

    recommended_action: str = Field(
        description=(
            "Specific, actionable recommendation. Not generic advice. "
            "Example: 'Block IP 203.0.113.42 at the firewall and audit "
            "all sessions from this IP in the last 24 hours' instead of "
            "'Monitor the situation'."
        )
    )

    confidence_score: float = Field(
        ge=0.0,
        le=1.0,
        description=(
            "Confidence in the threat assessment (0.0 to 1.0). "
            "0.0 = pure guess, 0.5 = some indicators but inconclusive, "
            "0.8 = strong evidence, 1.0 = definitive proof. "
            "Be calibrated: 5 failed logins from one IP is ~0.85, "
            "a single 404 is ~0.1."
        )
    )


class AnalysisRequest(BaseModel):
    """Input to the security analyst agent.

    Defines what the agent should analyse — either a free-form query
    or a time range (or both).
    """
    query: str = Field(
        default="Analyse all available logs for security threats",
        description="Natural language query describing what to analyse"
    )
    start_time: Optional[str] = Field(
        default=None,
        description="Start of time range to analyse (ISO 8601)"
    )
    end_time: Optional[str] = Field(
        default=None,
        description="End of time range to analyse (ISO 8601)"
    )
    log_source: Optional[str] = Field(
        default=None,
        description="Filter by log source: 'apache', 'auth', 'syslog', or None for all"
    )
    max_chunks: int = Field(
        default=10,
        description="Maximum number of log chunks to retrieve for analysis"
    )
