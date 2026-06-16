"""
LogSentinel AI — Analysis Endpoints

Handles: POST /analyse
Triggers the LLM agent to analyse log chunks within a time range.
Built in Phase 7.
"""

import time
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.agent.analyst import SecurityAnalystAgent
from app.agent.schemas import IncidentReport
from app.api.auth import get_api_key
from app.api.models.requests import AnalysisRequest
from app.db import repository
from app.db.connection import get_db_session

router = APIRouter()


def serialize_messages(messages: list) -> list[dict[str, Any]]:
    """Serialize LangChain conversation message history to JSON-compatible list."""
    serialized = []
    for msg in messages:
        role = "user"
        msg_type = msg.__class__.__name__
        if msg_type == "SystemMessage":
            role = "system"
        elif msg_type == "AIMessage":
            role = "assistant"
        elif msg_type == "ToolMessage":
            role = "tool"

        msg_dict: dict[str, Any] = {"role": role, "content": msg.content}
        if hasattr(msg, "tool_calls") and msg.tool_calls:
            msg_dict["tool_calls"] = msg.tool_calls
        if hasattr(msg, "tool_call_id") and msg.tool_call_id:
            msg_dict["tool_call_id"] = msg.tool_call_id
        serialized.append(msg_dict)
    return serialized


def extract_logs_retrieved(messages: list) -> str:
    """Assemble all logs retrieved by the agent's tool calls into a single string context."""
    retrieved = []
    for msg in messages:
        if msg.__class__.__name__ == "ToolMessage":
            retrieved.append(msg.content)
    return "\n\n".join(retrieved) if retrieved else "No logs retrieved."


@router.post(
    "", response_model=IncidentReport, dependencies=[Depends(get_api_key)]
)
async def trigger_log_analysis(
    request: AnalysisRequest,
    db: AsyncSession = Depends(get_db_session),
) -> IncidentReport:
    """Trigger the LLM security analyst agent to analyze log chunks.

    Runs the agentic information-gathering loop, correlates threats,
    saves the final report and raw execution history to PostgreSQL,
    and returns the structured report.
    """
    start_time = time.perf_counter()

    try:
        agent = SecurityAnalystAgent()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to initialize SecurityAnalystAgent: {str(e)}",
        )

    try:
        report = agent.analyze(request)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Agent analysis failed: {str(e)}",
        )

    duration_seconds = time.perf_counter() - start_time

    # Persist report and analysis metadata to database
    try:
        db_report = await repository.create_report(db, report)

        serialized_trace = serialize_messages(agent.last_messages)
        logs_retrieved = extract_logs_retrieved(agent.last_messages)

        await repository.create_raw_analysis(
            session=db,
            query=request.query,
            raw_response=serialized_trace,
            logs_retrieved=logs_retrieved,
            report_id=db_report.id,
            start_time=request.start_time,
            end_time=request.end_time,
            log_source=request.log_source,
            duration_seconds=duration_seconds,
        )
    except Exception as e:
        # Log error but don't block the API from returning the generated report to the user
        import logging

        logger = logging.getLogger(__name__)
        logger.error("api_failed_to_persist_analysis_run: %s", str(e))

    return report

