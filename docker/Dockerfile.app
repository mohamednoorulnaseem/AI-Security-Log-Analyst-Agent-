# ============================================================
# LogSentinel AI — FastAPI Application Dockerfile
# ============================================================
# Multi-stage build: install deps in builder, copy only what's
# needed into the slim runtime image. Keeps image ~200MB.

FROM python:3.12-slim AS builder

WORKDIR /build

# Install build dependencies for psycopg2 and other C extensions
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libpq-dev && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ── Runtime Stage ─────────────────────────────────────────────
FROM python:3.12-slim

WORKDIR /app

# Runtime dependency for psycopg2
RUN apt-get update && \
    apt-get install -y --no-install-recommends libpq5 curl && \
    rm -rf /var/lib/apt/lists/*

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application code
COPY app/ ./app/
COPY scripts/ ./scripts/
COPY alembic.ini ./
COPY alembic/ ./alembic/
COPY docker/entrypoint.sh /app/entrypoint.sh

# Create data directory for log uploads and make entrypoint script executable
RUN mkdir -p /app/data/logs && chmod +x /app/entrypoint.sh

EXPOSE 8080

ENTRYPOINT ["/app/entrypoint.sh"]
