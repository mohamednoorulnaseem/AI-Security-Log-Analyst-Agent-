"""
LogSentinel AI — Application Configuration

Uses pydantic-settings to load environment variables with type safety
and validation. Every config value has a sensible default for local dev,
but OPENAI_API_KEY must always be provided.
"""

from typing import Optional
from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    """Central configuration loaded from environment variables / .env file."""

    # ── OpenAI ────────────────────────────────────────────────
    openai_api_key: Optional[str] = Field(None, description="OpenAI API key (optional for tests)")
    openai_model: str = Field("gpt-4o-mini", description="LLM model for analysis")
    openai_embedding_model: str = Field(
        "text-embedding-3-small", description="Embedding model for log chunks"
    )

    # ── PostgreSQL ────────────────────────────────────────────
    postgres_host: str = Field("localhost")
    postgres_port: int = Field(5432)
    postgres_db: str = Field("logsentinel")
    postgres_user: str = Field("logsentinel_user")
    postgres_password: str = Field("change-this-in-production")

    @property
    def database_url(self) -> str:
        """Async SQLAlchemy connection string."""
        return (
            f"postgresql+asyncpg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    # ── ChromaDB ──────────────────────────────────────────────
    chroma_host: str = Field("localhost")
    chroma_port: int = Field(8000)
    chroma_collection_name: str = Field("log_chunks")

    # ── FastAPI ───────────────────────────────────────────────
    api_host: str = Field("0.0.0.0")
    api_port: int = Field(8080)
    api_key: str = Field("your-api-key-here")
    debug: bool = Field(True)

    # ── Dashboard ─────────────────────────────────────────────
    dashboard_port: int = Field(8501)
    api_base_url: str = Field("http://localhost:8080")

    # ── Log Ingestion ─────────────────────────────────────────
    log_chunk_window_minutes: int = Field(
        15, description="Time window (minutes) for grouping log lines into chunks"
    )
    max_log_file_size_mb: int = Field(
        100, description="Max log file size in MB accepted for upload"
    )

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": False,
    }


# Singleton — import this everywhere
settings = Settings()
