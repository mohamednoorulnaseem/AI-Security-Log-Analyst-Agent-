"""
LogSentinel AI — Report Endpoints

Handles: GET /reports, GET /reports/{id}
Lists and retrieves generated incident reports.
Built in Phase 7.
"""

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth import get_api_key
from app.api.models.responses import IncidentReportResponse, RawAnalysisResponse
from app.db import repository
from app.db.connection import get_db_session
from app.db.models import RawAnalysisModel

router = APIRouter()


@router.get("", response_model=list[IncidentReportResponse], dependencies=[Depends(get_api_key)])
async def list_incident_reports(
    limit: int = 50,
    offset: int = 0,
    db: AsyncSession = Depends(get_db_session),
):
    """Retrieve a list of generated incident reports (ordered by created_at descending)."""
    reports = await repository.list_reports(db, limit=limit, offset=offset)
    return reports


@router.get("/{report_id}", response_model=IncidentReportResponse, dependencies=[Depends(get_api_key)])
async def get_incident_report(
    report_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
):
    """Retrieve details for a single incident report by its UUID."""
    report = await repository.get_report_by_id(db, report_id)
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident report with ID {report_id} not found.",
        )
    return report


@router.get("/{report_id}/analyses", response_model=list[RawAnalysisResponse], dependencies=[Depends(get_api_key)])
async def get_report_analyses_history(
    report_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
):
    """Retrieve the raw LLM agent analysis traces and metadata associated with an incident report."""
    # Verify report exists
    report = await repository.get_report_by_id(db, report_id)
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident report with ID {report_id} not found.",
        )

    # Query analyses
    query = select(RawAnalysisModel).where(
        RawAnalysisModel.report_id == report_id
    )
    result = await db.execute(query)
    analyses = list(result.scalars().all())
    return analyses


