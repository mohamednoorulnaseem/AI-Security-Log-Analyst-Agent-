"""
LogSentinel AI — API Integration Tests

Tests health checks, log file uploading, triggering log analysis,
and listing/getting reports using FastAPI's TestClient and mocks.
"""

import datetime
from unittest.mock import AsyncMock, MagicMock, patch
import uuid

from fastapi import status
from fastapi.testclient import TestClient
import pytest

from app.agent.schemas import IncidentReport, TimelineEvent
from app.config import settings
from app.db.connection import get_db_session
from app.db.models import IncidentReportModel, RawAnalysisModel
from app.main import app


@pytest.fixture(autouse=True)
def setup_test_settings():
    """Setup consistency credentials for API Key authentication tests."""
    settings.api_key = "test-secret-api-key"
    settings.openai_api_key = "test-openai-key"


@pytest.fixture
def mock_db_session():
    """Create a mock AsyncSession."""
    return MagicMock()


@pytest.fixture
def client(mock_db_session):
    """Create a FastAPI test client with database session overrides."""
    app.dependency_overrides[get_db_session] = lambda: mock_db_session
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def test_root_endpoint(client):
    """Root endpoint is accessible without authentication."""
    response = client.get("/")
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["service"] == "LogSentinel AI"


def test_auth_failure_missing_key(client):
    """Routes requiring auth fail if the X-API-Key header is missing."""
    response = client.get("/reports")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "Invalid or missing API key" in response.json()["detail"]


def test_auth_failure_incorrect_key(client):
    """Routes requiring auth fail if the X-API-Key header is incorrect."""
    headers = {"X-API-Key": "wrong-key"}
    response = client.get("/reports", headers=headers)
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "Invalid or missing API key" in response.json()["detail"]


def test_health_check_endpoint(client, mock_db_session):
    """Health check runs successfully and reports status."""
    mock_db_session.execute = AsyncMock()

    with patch("app.api.routes.health.LogEmbedder") as MockEmbedder:
        mock_embedder_instance = MagicMock()
        mock_embedder_instance.chroma_client.heartbeat.return_value = 123
        MockEmbedder.return_value = mock_embedder_instance

        response = client.get("/health")
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["status"] == "healthy"
        assert response.json()["postgres"] == "connected"
        assert response.json()["chromadb"] == "connected"


@patch("app.api.routes.logs.detect_and_parse")
@patch("app.api.routes.logs.chunk_by_time")
@patch("app.api.routes.logs.LogEmbedder")
def test_logs_upload_success(MockEmbedder, MockChunk, MockParse, client):
    """Uploading a log file parses, chunks, embeds, and returns ingestion counts."""
    # Setup mock parser outputs
    MockParse.return_value = ([{"timestamp": "2026-06-15T02:00:00"}], [], "auth")
    # Setup mock chunker outputs
    mock_chunk = MagicMock()
    MockChunk.return_value = [mock_chunk]

    # Setup mock embedder
    mock_embedder_instance = MagicMock()
    MockEmbedder.return_value = mock_embedder_instance

    headers = {"X-API-Key": "test-secret-api-key"}
    files = {"file": ("auth.log", b"test log file content", "text/plain")}

    response = client.post("/logs/upload", headers=headers, files=files)

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["status"] == "success"
    assert data["log_source"] == "auth"
    assert data["entries_parsed"] == 1
    assert data["chunks_created"] == 1

    # Verify embedder was triggered
    mock_embedder_instance.embed_and_store.assert_called_once_with([mock_chunk])


@patch("app.api.routes.analyse.SecurityAnalystAgent")
@patch("app.api.routes.analyse.repository")
def test_trigger_analysis_success(
    MockRepository, MockAgentClass, client, mock_db_session
):
    """Triggering analysis executes agent and returns structured IncidentReport."""
    # Mock the analyst agent instance
    mock_agent_instance = MagicMock()

    # Mock IncidentReport output
    mock_report = IncidentReport(
        summary="A security breach was traced.",
        threat_detected=True,
        threat_type="SQL Injection",
        severity="HIGH",
        timeline=[
            TimelineEvent(
                timestamp="2026", log_line="raw", significance="sig"
            )
        ],
        recommended_action="Block IP",
        confidence_score=0.9,
    )
    mock_agent_instance.analyze.return_value = mock_report
    mock_agent_instance.last_messages = [
        MagicMock(
            __class__=MagicMock(__name__="SystemMessage"), content="system info"
        ),
        MagicMock(
            __class__=MagicMock(__name__="ToolMessage"), content="tool result"
        ),
    ]
    MockAgentClass.return_value = mock_agent_instance

    # Mock database repository calls
    mock_db_report = MagicMock(id=uuid.uuid4())
    MockRepository.create_report = AsyncMock(return_value=mock_db_report)
    MockRepository.create_raw_analysis = AsyncMock()

    headers = {"X-API-Key": "test-secret-api-key"}
    payload = {
        "query": "Find SQL injection attempts",
        "log_source": "apache",
        "max_chunks": 5,
    }

    response = client.post("/analyse", headers=headers, json=payload)

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["threat_detected"] is True
    assert data["threat_type"] == "SQL Injection"
    assert data["severity"] == "HIGH"

    # Verify repository persist was triggered
    MockRepository.create_report.assert_called_once_with(
        mock_db_session, mock_report
    )
    MockRepository.create_raw_analysis.assert_called_once()


@patch("app.api.routes.reports.repository")
def test_list_reports_success(MockRepository, client, mock_db_session):
    """Listing reports retrieves records from repository."""
    mock_report = IncidentReportModel(
        id=uuid.uuid4(),
        summary="Summary report list test",
        severity="LOW",
        threat_detected=False,
        threat_type=None,
        timeline=[],
        recommended_action="none",
        confidence_score=0.5,
        created_at=datetime.datetime.now(datetime.UTC),
    )

    MockRepository.list_reports = AsyncMock(return_value=[mock_report])

    headers = {"X-API-Key": "test-secret-api-key"}
    response = client.get("/reports", headers=headers)

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert len(data) == 1
    assert data[0]["summary"] == "Summary report list test"


@patch("app.api.routes.reports.repository")
def test_get_report_by_id_success(MockRepository, client, mock_db_session):
    """Getting a report by ID retrieves it from repository."""
    mock_report = IncidentReportModel(
        id=uuid.uuid4(),
        summary="Single report test",
        severity="MEDIUM",
        threat_detected=True,
        threat_type="Brute Force",
        timeline=[],
        recommended_action="isolate",
        confidence_score=0.8,
        created_at=datetime.datetime.now(datetime.UTC),
    )
    MockRepository.get_report_by_id = AsyncMock(return_value=mock_report)

    headers = {"X-API-Key": "test-secret-api-key"}
    response = client.get(f"/reports/{mock_report.id}", headers=headers)

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["summary"] == "Single report test"
    MockRepository.get_report_by_id.assert_called_once_with(mock_db_session, mock_report.id)


@patch("app.api.routes.reports.repository")
def test_get_report_analyses_history_success(MockRepository, client, mock_db_session):
    """Getting analyses history retrieves records from DB execution."""
    mock_report = IncidentReportModel(
        id=uuid.uuid4(),
        summary="Report for history",
        severity="HIGH",
        threat_detected=True,
        threat_type="XSS",
        timeline=[],
        recommended_action="block",
        confidence_score=0.9,
        created_at=datetime.datetime.now(datetime.UTC),
    )
    MockRepository.get_report_by_id = AsyncMock(return_value=mock_report)

    # Mock DB execution for analyses
    mock_analysis = RawAnalysisModel(
        id=uuid.uuid4(),
        query="find threat",
        raw_response=[],
        logs_retrieved="some logs",
        report_id=mock_report.id,
        start_time=None,
        end_time=None,
        log_source="syslog",
        duration_seconds=1.5,
        created_at=datetime.datetime.now(datetime.UTC),
    )

    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = [mock_analysis]
    mock_db_session.execute = AsyncMock(return_value=mock_result)

    headers = {"X-API-Key": "test-secret-api-key"}
    response = client.get(f"/reports/{mock_report.id}/analyses", headers=headers)

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert len(data) == 1
    assert data[0]["query"] == "find threat"
