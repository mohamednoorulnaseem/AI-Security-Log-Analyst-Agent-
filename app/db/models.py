"""
LogSentinel AI — SQLAlchemy Models

Database table definitions:
  - reports: Stores generated incident reports
  - raw_analyses: Stores every agent run with full metadata

Built in Phase 6.
"""

import datetime
import uuid
from typing import Any, Optional

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, JSON, String, Text, Uuid
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Declarative base class for all database models."""

    pass


class IncidentReportModel(Base):
    """Database model for security incident reports."""

    __tablename__ = "reports"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid, primary_key=True, default=uuid.uuid4
    )
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.datetime.now(datetime.UTC),
        nullable=False,
    )
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    threat_detected: Mapped[bool] = mapped_column(Boolean, nullable=False)
    threat_type: Mapped[Optional[str]] = mapped_column(
        String(100), nullable=True
    )
    severity: Mapped[str] = mapped_column(
        String(20), nullable=False
    )  # NONE, LOW, MEDIUM, HIGH, CRITICAL
    timeline: Mapped[Any] = mapped_column(
        JSON, nullable=False
    )  # List of TimelineEvent dicts
    recommended_action: Mapped[str] = mapped_column(Text, nullable=False)
    confidence_score: Mapped[float] = mapped_column(Float, nullable=False)

    # Relationship to analyses
    analyses: Mapped[list["RawAnalysisModel"]] = relationship(
        "RawAnalysisModel",
        back_populates="report",
    )


class RawAnalysisModel(Base):
    """Database model for raw agent analysis executions."""

    __tablename__ = "raw_analyses"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid, primary_key=True, default=uuid.uuid4
    )
    report_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid, ForeignKey("reports.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.datetime.now(datetime.UTC),
        nullable=False,
    )
    query: Mapped[str] = mapped_column(Text, nullable=False)
    start_time: Mapped[Optional[str]] = mapped_column(
        String(50), nullable=True
    )
    end_time: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    log_source: Mapped[Optional[str]] = mapped_column(
        String(50), nullable=True
    )
    raw_response: Mapped[Any] = mapped_column(
        JSON, nullable=False
    )  # Full agent message list
    logs_retrieved: Mapped[str] = mapped_column(
        Text, nullable=False
    )  # Text representation of logs retrieved
    duration_seconds: Mapped[Optional[float]] = mapped_column(
        Float, nullable=True
    )

    # Relationship to report
    report: Mapped[Optional[IncidentReportModel]] = relationship(
        "IncidentReportModel", back_populates="analyses"
    )

