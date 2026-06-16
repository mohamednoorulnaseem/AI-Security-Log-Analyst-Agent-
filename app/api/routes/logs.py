"""
LogSentinel AI — Log Upload Endpoints

Handles: POST /logs/upload
Accepts raw log files, triggers the ingestion pipeline.
Built in Phase 7.
"""

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status

from app.api.auth import get_api_key
from app.api.models.responses import IngestionResponse
from app.config import settings
from app.ingestion.chunker import chunk_by_time
from app.ingestion.embedder import LogEmbedder
from app.ingestion.parser import detect_and_parse

router = APIRouter()


@router.post(
    "/upload",
    response_model=IngestionResponse,
    dependencies=[Depends(get_api_key)],
)
async def upload_log_file(
    file: UploadFile = File(..., description="Raw log file to upload"),
) -> dict:
    """Accept raw log files, parse, chunk, and embed them in ChromaDB.

    Accepts syslog, auth log, or Apache access log. Format is auto-detected.
    """
    if not settings.openai_api_key:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OPENAI_API_KEY is not configured on the server. Cannot embed log files.",
        )

    # Verify file size
    max_size_bytes = settings.max_log_file_size_mb * 1024 * 1024

    try:
        content_bytes = await file.read()
        if len(content_bytes) > max_size_bytes:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"Log file exceeds the maximum size limit of {settings.max_log_file_size_mb}MB.",
            )

        content_text = content_bytes.decode("utf-8", errors="ignore")
    except Exception as e:
        if isinstance(e, HTTPException):
            raise
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to read or decode file contents: {str(e)}",
        )

    # 1. Parse logs
    entries, skipped, detected_format = detect_and_parse(content_text)
    if not entries:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No valid log entries could be parsed from the uploaded file.",
        )

    # 2. Chunk logs into time-based windows
    chunks = chunk_by_time(
        entries=entries,
        log_source=detected_format,
        window_minutes=settings.log_chunk_window_minutes,
    )
    if not chunks:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to generate time-based chunks (verify timestamps format).",
        )

    # 3. Embed and store in ChromaDB
    try:
        embedder = LogEmbedder(
            openai_api_key=settings.openai_api_key,
            embedding_model=settings.openai_embedding_model,
            chroma_host=settings.chroma_host,
            chroma_port=settings.chroma_port,
            collection_name=settings.chroma_collection_name,
        )
        embedder.embed_and_store(chunks)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"ChromaDB embedding failed: {str(e)}",
        )

    return {
        "status": "success",
        "log_source": detected_format,
        "entries_parsed": len(entries),
        "skipped_lines": len(skipped),
        "chunks_created": len(chunks),
    }

