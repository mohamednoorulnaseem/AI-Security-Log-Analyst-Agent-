"""
LogSentinel AI — API Key Authentication

Simple API key auth via X-API-Key header.
Built in Phase 7.
"""

from fastapi import HTTPException, Security, status
from fastapi.security.api_key import APIKeyHeader

from app.config import settings

API_KEY_NAME = "X-API-Key"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)


async def get_api_key(api_key: str = Security(api_key_header)) -> str:
    """Validate the incoming request's API Key against settings.api_key.

    Args:
        api_key: The API Key fetched from the X-API-Key header.

    Returns:
        The validated API key string.

    Raises:
        HTTPException: 401 Unauthorized if key is invalid or missing.
    """
    if not api_key or api_key != settings.api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key in X-API-Key header.",
        )
    return api_key

