"""
LogSentinel AI — FastAPI Application Entry Point

This is the ASGI application that uvicorn serves.
Phase 7: Mounts the API endpoints and CORS configuration.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import analyse, health, logs, reports

app = FastAPI(
    title="LogSentinel AI",
    description=(
        "AI-powered security log analyst agent. "
        "Ingests raw server logs, detects anomalies, classifies threats, "
        "traces attack patterns, and generates structured incident reports."
    ),
    version="0.1.0",
)

# CORS configuration to allow local dashboard connections
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API endpoints routers
app.include_router(health.router, prefix="/health", tags=["health"])
app.include_router(logs.router, prefix="/logs", tags=["logs"])
app.include_router(analyse.router, prefix="/analyse", tags=["analysis"])
app.include_router(reports.router, prefix="/reports", tags=["reports"])


@app.get("/", tags=["root"])
async def root():
    """Root endpoint — confirms the service is running."""
    return {
        "service": "LogSentinel AI",
        "version": "0.1.0",
        "status": "running",
    }

