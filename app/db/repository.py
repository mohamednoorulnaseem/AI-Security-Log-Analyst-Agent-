"""
LogSentinel AI — Database Repository

CRUD operations for reports and analyses.
Abstracts SQLAlchemy queries behind clean async functions.
Built in Phase 6.
"""

import uuid
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.agent.schemas import IncidentReport
from app.db.models import IncidentReportModel, RawAnalysisModel


async def create_report(
    session: AsyncSession, report: IncidentReport
) -> IncidentReportModel:
    """Save a generated incident report to the database.

    Args:
        session: Active SQLAlchemy AsyncSession.
        report: IncidentReport Pydantic schema model.

    Returns:
        The created database model instance.
    """
    # Convert Pydantic timeline events to dictionaries for JSON storage
    timeline_data = [event.model_dump() for event in report.timeline]

    db_report = IncidentReportModel(
        summary=report.summary,
        threat_detected=report.threat_detected,
        threat_type=report.threat_type,
        severity=report.severity,
        timeline=timeline_data,
        recommended_action=report.recommended_action,
        confidence_score=report.confidence_score,
    )

    session.add(db_report)
    await session.commit()
    await session.refresh(db_report)
    return db_report


async def get_report_by_id(
    session: AsyncSession, report_id: uuid.UUID
) -> Optional[IncidentReportModel]:
    """Retrieve an incident report by its primary key UUID.

    Args:
        session: Active SQLAlchemy AsyncSession.
        report_id: UUID of the report.

    Returns:
        The database model instance, or None if not found.
    """
    return await session.get(IncidentReportModel, report_id)


async def list_reports(
    session: AsyncSession, limit: int = 50, offset: int = 0
) -> list[IncidentReportModel]:
    """Retrieve a list of incident reports, ordered by created_at descending.

    Args:
        session: Active SQLAlchemy AsyncSession.
        limit: Maximum number of records to return.
        offset: Number of records to skip.

    Returns:
        List of database model instances.
    """
    query = (
        select(IncidentReportModel)
        .order_by(IncidentReportModel.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    result = await session.execute(query)
    return list(result.scalars().all())


async def create_raw_analysis(
    session: AsyncSession,
    query: str,
    raw_response: Any,
    logs_retrieved: str,
    report_id: Optional[uuid.UUID] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    log_source: Optional[str] = None,
    duration_seconds: Optional[float] = None,
) -> RawAnalysisModel:
    """Save an agent execution trace and metadata to the database.

    Args:
        session: Active SQLAlchemy AsyncSession.
        query: User input query.
        raw_response: Full message list representation (JSON).
        logs_retrieved: Full text representation of raw logs searched.
        report_id: Optional UUID FK referencing reports.id.
        start_time: Optional analysis window start ISO string.
        end_time: Optional analysis window end ISO string.
        log_source: Optional log source filtered.
        duration_seconds: Time taken to run the agent in seconds.

    Returns:
        The created database model instance.
    """
    db_analysis = RawAnalysisModel(
        report_id=report_id,
        query=query,
        start_time=start_time,
        end_time=end_time,
        log_source=log_source,
        raw_response=raw_response,
        logs_retrieved=logs_retrieved,
        duration_seconds=duration_seconds,
    )

    session.add(db_analysis)
    await session.commit()
    await session.refresh(db_analysis)
    return db_analysis


async def get_raw_analysis_by_id(
    session: AsyncSession, analysis_id: uuid.UUID
) -> Optional[RawAnalysisModel]:
    """Retrieve a raw analysis run by its primary key UUID.

    Args:
        session: Active SQLAlchemy AsyncSession.
        analysis_id: UUID of the analysis run.

    Returns:
        The database model instance, or None if not found.
    """
    return await session.get(RawAnalysisModel, analysis_id)

