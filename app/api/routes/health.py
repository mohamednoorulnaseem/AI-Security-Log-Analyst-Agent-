"""
LogSentinel AI — Health Check Endpoint

Handles: GET /health
Confirms all services (PostgreSQL, ChromaDB, OpenAI) are reachable.
Built in Phase 7.
"""

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.models.responses import HealthResponse
from app.config import settings
from app.db.connection import get_db_session
from app.ingestion.embedder import LogEmbedder

router = APIRouter()


@router.get("", response_model=HealthResponse)
async def health_check(
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    """Check the health of the API, PostgreSQL database, ChromaDB, and OpenAI.

    Returns a detailed health status for each subsystem.
    """
    # 1. Check PostgreSQL
    postgres_status = "connected"
    try:
        await db.execute(select(1))
    except Exception:
        postgres_status = "disconnected"

    # 2. Check ChromaDB
    chromadb_status = "connected"
    try:
        # Initialize embedder using settings
        embedder = LogEmbedder(
            openai_api_key=settings.openai_api_key or "dummy-key",
            embedding_model=settings.openai_embedding_model,
            chroma_host=settings.chroma_host,
            chroma_port=settings.chroma_port,
            collection_name=settings.chroma_collection_name,
        )
        embedder.chroma_client.heartbeat()
    except Exception:
        chromadb_status = "disconnected"

    # 3. Check OpenAI configuration
    # NOTE: This only checks if an API key is configured, not whether it is
    # valid or whether OpenAI's API is reachable. A real connectivity check
    # would require an API call (and cost money on every health check).
    openai_status = "configured"
    if not settings.openai_api_key:
        openai_status = "not_configured"

    overall_status = (
        "healthy"
        if postgres_status == "connected"
        and chromadb_status == "connected"
        and openai_status == "configured"
        else "unhealthy"
    )

    return {
        "status": overall_status,
        "postgres": postgres_status,
        "chromadb": chromadb_status,
        "openai": openai_status,
    }

