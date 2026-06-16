"""
LogSentinel AI — API Response Models

Pydantic models for outgoing API responses.
Built in Phase 7.
"""

import datetime
from typing import Any, Optional
import uuid

from pydantic import BaseModel, Field



class IngestionResponse(BaseModel):
    """Response schema returned after successful log file upload and ingestion."""

    status: str = Field("success", description="Status of the ingestion operation")
    log_source: str = Field(..., description="Format of the ingested logs (e.g. 'apache', 'auth', 'syslog')")
    entries_parsed: int = Field(..., description="Number of log entries successfully parsed")
    skipped_lines: int = Field(..., description="Number of lines skipped during parsing")
    chunks_created: int = Field(..., description="Number of 15-minute log chunks created and stored in ChromaDB")


class HealthResponse(BaseModel):
    """Response schema returned by the /health check endpoint."""

    status: str = Field(..., description="Overall health status: 'healthy' or 'unhealthy'")
    postgres: str = Field(..., description="PostgreSQL database health status: 'connected' or 'disconnected'")
    chromadb: str = Field(..., description="ChromaDB vector store health status: 'connected' or 'disconnected'")
    openai: str = Field(..., description="OpenAI API health status: 'reachable' or 'unreachable'")


class IncidentReportResponse(BaseModel):
    """Pydantic schema representing a persisted security incident report."""

    id: uuid.UUID
    created_at: datetime.datetime
    summary: str
    threat_detected: bool
    threat_type: Optional[str]
    severity: str
    timeline: list[Any]
    recommended_action: str
    confidence_score: float

    model_config = {
        "from_attributes": True
    }


class RawAnalysisResponse(BaseModel):
    """Pydantic schema representing a persisted agent execution trace."""

    id: uuid.UUID
    report_id: Optional[uuid.UUID]
    created_at: datetime.datetime
    query: str
    start_time: Optional[str]
    end_time: Optional[str]
    log_source: Optional[str]
    raw_response: list[Any]
    logs_retrieved: str
    duration_seconds: Optional[float]

    model_config = {
        "from_attributes": True
    }


