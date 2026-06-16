"""
LogSentinel AI — Database Unit Tests

Tests database model structure, relationships, and repository methods
using an in-memory SQLite database via aiosqlite.
"""

import uuid
import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.agent.schemas import IncidentReport, TimelineEvent
from app.db import repository
from app.db.models import Base


@pytest_asyncio.fixture(scope="function")
async def async_db_session():
    """Fixture that initializes an in-memory SQLite database and yields an AsyncSession."""
    # Use in-memory SQLite for fast database unit testing
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", future=True)

    # Create tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Sessionmaker
    TestingSessionLocal = async_sessionmaker(
        bind=engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    async with TestingSessionLocal() as session:
        yield session

    # Cleanup
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest.mark.asyncio
async def test_create_and_get_report(async_db_session):
    """Saving and retrieving an IncidentReport works correctly."""
    # Create Pydantic IncidentReport schema
    pydantic_report = IncidentReport(
        summary="Brute force attack detected on auth logs.",
        threat_detected=True,
        threat_type="Brute Force SSH Attack",
        severity="HIGH",
        timeline=[
            TimelineEvent(
                timestamp="2026-06-15T02:15:00",
                log_line="Failed password for root from 203.0.113.42",
                significance="Failed attempt 1",
            )
        ],
        recommended_action="Block IP 203.0.113.42",
        confidence_score=0.9,
    )

    # Save via repository
    db_report = await repository.create_report(
        async_db_session, pydantic_report
    )
    assert db_report.id is not None
    assert db_report.summary == pydantic_report.summary
    assert db_report.timeline[0]["timestamp"] == "2026-06-15T02:15:00"

    # Retrieve via repository
    retrieved = await repository.get_report_by_id(
        async_db_session, db_report.id
    )
    assert retrieved is not None
    assert retrieved.id == db_report.id
    assert retrieved.threat_type == "Brute Force SSH Attack"
    assert retrieved.severity == "HIGH"


@pytest.mark.asyncio
async def test_list_reports(async_db_session):
    """list_reports returns reports ordered by created_at descending."""
    pydantic_report_1 = IncidentReport(
        summary="Threat 1",
        threat_detected=True,
        severity="LOW",
        timeline=[],
        recommended_action="Monitor",
        confidence_score=0.4,
    )
    pydantic_report_2 = IncidentReport(
        summary="Threat 2",
        threat_detected=True,
        severity="MEDIUM",
        timeline=[],
        recommended_action="Block",
        confidence_score=0.7,
    )

    # Save reports
    report1 = await repository.create_report(
        async_db_session, pydantic_report_1
    )
    report2 = await repository.create_report(
        async_db_session, pydantic_report_2
    )

    # Retrieve list
    reports = await repository.list_reports(async_db_session, limit=10)
    assert len(reports) == 2
    # Verify descending ordering: report2 (created second) should be first
    assert reports[0].id == report2.id
    assert reports[1].id == report1.id


@pytest.mark.asyncio
async def test_create_and_get_raw_analysis(async_db_session):
    """create_raw_analysis saves and retrieves execution metadata."""
    pydantic_report = IncidentReport(
        summary="SQL Injection Threat",
        threat_detected=True,
        threat_type="SQL Injection Attempt",
        severity="MEDIUM",
        timeline=[],
        recommended_action="Check WAF rules",
        confidence_score=0.8,
    )
    db_report = await repository.create_report(
        async_db_session, pydantic_report
    )

    # Create raw analysis
    raw_msgs = [
        {"role": "user", "content": "Analyze logs"},
        {"role": "assistant", "content": "I found a threat"},
    ]
    logs_context = "45.33.32.156 - - HTTP GET /search?q=UNION SELECT"

    db_analysis = await repository.create_raw_analysis(
        session=async_db_session,
        query="Analyze logs",
        raw_response=raw_msgs,
        logs_retrieved=logs_context,
        report_id=db_report.id,
        start_time="2026-06-15T02:00:00",
        end_time="2026-06-15T02:15:00",
        log_source="apache",
        duration_seconds=3.45,
    )

    assert db_analysis.id is not None
    assert db_analysis.report_id == db_report.id
    assert db_analysis.log_source == "apache"
    assert db_analysis.duration_seconds == 3.45
    assert db_analysis.raw_response[0]["role"] == "user"

    # Retrieve and check relationship
    retrieved = await repository.get_raw_analysis_by_id(
        async_db_session, db_analysis.id
    )
    assert retrieved is not None
    assert retrieved.id == db_analysis.id
    assert retrieved.report is not None
    assert retrieved.report.id == db_report.id


@pytest.mark.asyncio
async def test_cascade_delete_behavior(async_db_session):
    """Deleting a report cascades correctly (FK set to null in raw_analyses)."""
    pydantic_report = IncidentReport(
        summary="Threat to delete",
        threat_detected=True,
        severity="LOW",
        timeline=[],
        recommended_action="Delete",
        confidence_score=0.5,
    )
    db_report = await repository.create_report(
        async_db_session, pydantic_report
    )

    db_analysis = await repository.create_raw_analysis(
        session=async_db_session,
        query="Query info",
        raw_response=[],
        logs_retrieved="Logs raw text",
        report_id=db_report.id,
    )

    # Delete the report
    await async_db_session.delete(db_report)
    await async_db_session.commit()

    # Re-retrieve raw analysis to verify its report_id was set to NULL (ON DELETE SET NULL behavior)
    retrieved_analysis = await repository.get_raw_analysis_by_id(
        async_db_session, db_analysis.id
    )
    assert retrieved_analysis is not None
    assert retrieved_analysis.report_id is None
