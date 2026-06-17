"""
LogSentinel AI — Core Security Analyst Agent

LangChain agent that acts as a senior security analyst.
Retrieves relevant log chunks, analyses them for threats,
and generates structured incident reports.

Built in Phase 4.
"""

import logging
from typing import Optional

from langchain_openai import ChatOpenAI
from langchain_core.messages import SystemMessage, HumanMessage, ToolMessage

from app.config import settings
from app.ingestion.embedder import LogEmbedder
from app.agent.schemas import IncidentReport, AnalysisRequest
from app.agent.prompts import SECURITY_ANALYST_SYSTEM_PROMPT, ANALYSIS_HUMAN_PROMPT
from app.agent.tools import get_agent_tools

logger = logging.getLogger(__name__)


class SecurityAnalystAgent:
    """Security Analyst LLM Agent.

    Uses an agentic loop with log-querying tools to gather evidence,
    correlate events, and produce a structured incident report.
    """

    def __init__(
        self,
        openai_api_key: Optional[str] = None,
        model_name: Optional[str] = None,
        embedder: Optional[LogEmbedder] = None,
    ):
        """Initialize the agent.

        Args:
            openai_api_key: OpenAI API key. Defaults to settings.openai_api_key.
            model_name: Chat model to use. Defaults to settings.openai_model.
            embedder: Pre-initialized LogEmbedder. If None, initialized from settings.
        """
        self.openai_api_key = openai_api_key or settings.openai_api_key
        self.model_name = model_name or settings.openai_model

        if not self.openai_api_key:
            raise ValueError(
                "OpenAI API key is required to initialize SecurityAnalystAgent."
            )

        # Initialize embedder if not provided
        if embedder is not None:
            self.embedder = embedder
        else:
            self.embedder = LogEmbedder(
                openai_api_key=self.openai_api_key,
                embedding_model=settings.openai_embedding_model,
                chroma_host=settings.chroma_host
                if settings.chroma_host != "localhost"
                else None,
                chroma_port=settings.chroma_port,
                collection_name=settings.chroma_collection_name,
            )

        # Initialize core LLM
        if (
            self.model_name.startswith("gemini-")
            or (self.openai_api_key and self.openai_api_key.startswith("AIzaSy"))
            or "gemini" in settings.openai_api_base.lower()
        ):
            from langchain_google_genai import ChatGoogleGenerativeAI
            self.llm = ChatGoogleGenerativeAI(
                model=self.model_name,
                google_api_key=self.openai_api_key,
                temperature=0.0,
            )
        else:
            self.llm = ChatOpenAI(
                model=self.model_name,
                openai_api_key=self.openai_api_key,
                base_url=settings.openai_api_base,
                temperature=0.0,
            )

        # Bind tools to the LLM
        self.tools = get_agent_tools(self.embedder)
        self.llm_with_tools = self.llm.bind_tools(self.tools)

        # Structured output LLM
        self.structured_llm = self.llm.with_structured_output(IncidentReport)

        # Audit trace of the last run
        self.last_messages: list = []

        logger.info(
            "security_analyst_agent_initialized: model=%s tools=%d",
            self.model_name,
            len(self.tools),
        )

    def analyze(self, request: AnalysisRequest) -> IncidentReport:
        """Run analysis on the requested query and/or time range.

        Executes information gathering via tool-calling, then returns
        the final IncidentReport.
        """
        logger.info(
            "analysis_started: query='%s' time_range='%s' to '%s'",
            request.query,
            request.start_time or "None",
            request.end_time or "None",
        )

        # Build human prompt context
        time_range_desc = (
            f"{request.start_time or 'Any'} to {request.end_time or 'Any'}"
        )
        human_content = ANALYSIS_HUMAN_PROMPT.format(
            query=request.query,
            time_range=time_range_desc,
            log_data=(
                "Use your tools (search_logs_semantically, retrieve_logs_by_time_range, "
                "correlate_logs_by_ip) to retrieve relevant log chunks and identify threats."
            ),
        )

        # Initialize conversation messages
        messages = [
            SystemMessage(content=SECURITY_ANALYST_SYSTEM_PROMPT),
            HumanMessage(content=human_content),
        ]

        # Information gathering loop (max 5 turns)
        max_iterations = 5
        tool_call_count = 0

        for i in range(max_iterations):
            logger.info("agent_loop_turn: turn=%d/%d", i + 1, max_iterations)
            response = self.llm_with_tools.invoke(messages)
            messages.append(response)

            # Check if model wants to call tools
            if not response.tool_calls:
                logger.info("agent_loop_finished: no more tool calls requested")
                break

            # Execute the tool calls
            for tool_call in response.tool_calls:
                tool_name = tool_call["name"]
                tool_args = tool_call["args"]
                tool_call_id = tool_call["id"]

                logger.info(
                    "agent_tool_executing: name=%s args=%s id=%s",
                    tool_name,
                    tool_args,
                    tool_call_id,
                )

                # Locate matching tool
                tool_obj = next(
                    (t for t in self.tools if t.name == tool_name), None
                )
                if not tool_obj:
                    result = f"Error: Tool '{tool_name}' not found."
                else:
                    try:
                        # Invoke tool and convert response to string
                        result = tool_obj.invoke(tool_args)
                    except Exception as e:
                        logger.error(
                            "tool_execution_failed: name=%s error=%s",
                            tool_name,
                            str(e),
                        )
                        result = f"Error executing tool {tool_name}: {str(e)}"

                messages.append(
                    ToolMessage(
                        content=str(result),
                        tool_call_id=tool_call_id,
                    )
                )
                tool_call_count += 1

        # Final Formatting Step: Send the whole history to the structured LLM
        logger.info(
            "agent_formatting_report: messages=%d tools_called=%d",
            len(messages),
            tool_call_count,
        )

        final_prompt = (
            "You have completed your log analysis. Based on all the retrieved logs "
            "and information gathered above, please generate the final structured incident "
            "report matching the IncidentReport schema. Be detailed, precise, and ground "
            "your timeline events and severity strictly on the evidence in the retrieved logs."
        )
        messages.append(HumanMessage(content=final_prompt))

        try:
            report = self.structured_llm.invoke(messages)
            self.last_messages = messages
            logger.info(
                "incident_report_generated: threat_detected=%s severity=%s",
                report.threat_detected,
                report.severity,
            )
            return report
        except Exception as e:
            logger.error("incident_report_generation_failed: error=%s", str(e))
            self.last_messages = messages
            # Fallback report in case of formatting errors
            return IncidentReport(
                summary=f"Analysis failed due to error: {str(e)}",
                threat_detected=False,
                threat_type=None,
                severity="NONE",
                timeline=[],
                recommended_action="Investigate system error and retry analysis.",
                confidence_score=0.0,
            )

