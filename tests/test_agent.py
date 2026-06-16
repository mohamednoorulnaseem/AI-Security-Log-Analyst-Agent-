"""
LogSentinel AI — Agent Tests

Tests for the LLM security analyst agent.
Built in Phase 4.
"""

from unittest.mock import MagicMock
import pytest

from langchain_core.messages import AIMessage
from app.agent.analyst import SecurityAnalystAgent
from app.agent.schemas import AnalysisRequest, IncidentReport, TimelineEvent
from app.agent.tools import get_agent_tools
from app.ingestion.embedder import LogEmbedder


class TestAgentTools:
    """Unit tests for the custom agent tools."""

    @pytest.fixture
    def mock_embedder(self):
        """Create a mock LogEmbedder."""
        return MagicMock(spec=LogEmbedder)

    def test_search_logs_semantically(self, mock_embedder):
        """search_logs_semantically calls embedder.similarity_search."""
        mock_embedder.similarity_search.return_value = [
            {
                "content": "Log line 1\nLog line 2",
                "metadata": {
                    "log_source": "auth",
                    "start_time": "2026-06-15T02:00:00",
                    "end_time": "2026-06-15T02:15:00",
                },
            }
        ]

        tools = get_agent_tools(mock_embedder)
        search_tool = next(
            t for t in tools if t.name == "search_logs_semantically"
        )

        result = search_tool.invoke(
            {"query": "brute force", "log_source": "auth", "limit": 3}
        )

        assert "Result 1" in result
        assert "Log line 1" in result
        assert "Source: auth" in result
        mock_embedder.similarity_search.assert_called_once_with(
            query="brute force", k=3, filter_dict={"log_source": "auth"}
        )

    def test_search_logs_semantically_no_results(self, mock_embedder):
        """search_logs_semantically returns friendly message when no results found."""
        mock_embedder.similarity_search.return_value = []

        tools = get_agent_tools(mock_embedder)
        search_tool = next(
            t for t in tools if t.name == "search_logs_semantically"
        )

        result = search_tool.invoke({"query": "not found"})

        assert "No matching log chunks found." in result

    def test_retrieve_logs_by_time_range(self, mock_embedder):
        """retrieve_logs_by_time_range retrieves and filters chunks by timestamp."""
        # Setup mock chunks
        mock_embedder.get_chunks_by_metadata.return_value = [
            {
                "content": "Chunk outside range (early)",
                "metadata": {
                    "log_source": "auth",
                    "start_time": "2026-06-15T01:00:00",
                    "end_time": "2026-06-15T01:15:00",
                },
            },
            {
                "content": "Chunk inside range",
                "metadata": {
                    "log_source": "auth",
                    "start_time": "2026-06-15T02:00:00",
                    "end_time": "2026-06-15T02:15:00",
                },
            },
            {
                "content": "Chunk outside range (late)",
                "metadata": {
                    "log_source": "auth",
                    "start_time": "2026-06-15T03:00:00",
                    "end_time": "2026-06-15T03:15:00",
                },
            },
        ]

        tools = get_agent_tools(mock_embedder)
        time_tool = next(
            t for t in tools if t.name == "retrieve_logs_by_time_range"
        )

        result = time_tool.invoke(
            {
                "start_time": "2026-06-15T01:45:00",
                "end_time": "2026-06-15T02:30:00",
                "log_source": "auth",
            }
        )

        assert "Chunk inside range" in result
        assert "Chunk outside range" not in result
        mock_embedder.get_chunks_by_metadata.assert_called_once_with(
            filter_dict={"log_source": "auth"}, limit=100
        )

    def test_correlate_logs_by_ip(self, mock_embedder):
        """correlate_logs_by_ip calls embedder.get_chunks_containing_text."""
        mock_embedder.get_chunks_containing_text.return_value = [
            {
                "content": "Chunk containing IP 203.0.113.42",
                "metadata": {
                    "log_source": "auth",
                    "start_time": "2026-06-15T02:00:00",
                    "end_time": "2026-06-15T02:15:00",
                },
            }
        ]

        tools = get_agent_tools(mock_embedder)
        ip_tool = next(t for t in tools if t.name == "correlate_logs_by_ip")

        result = ip_tool.invoke({"ip_address": "203.0.113.42", "limit": 5})

        assert "Correlated Chunk 1" in result
        assert "Chunk containing IP 203.0.113.42" in result
        mock_embedder.get_chunks_containing_text.assert_called_once_with(
            search_text="203.0.113.42", limit=5
        )

    def test_trace_attack_chain_tool(self, mock_embedder):
        """trace_attack_chain calls tracer and returns formatted timeline."""
        mock_embedder.get_chunks_containing_text.return_value = [
            {
                "content": (
                    "Log chunk 1 | auth | 2026-06-15T02:00:00 to 2026-06-15T02:15:00 | 1 entries\n"
                    "---\n"
                    "[2026-06-15T02:15:00] SSH FAILED: user=root from 203.0.113.42 via password"
                ),
                "metadata": {"log_source": "auth"},
            }
        ]

        tools = get_agent_tools(mock_embedder)
        trace_tool = next(t for t in tools if t.name == "trace_attack_chain")

        result = trace_tool.invoke({"entity": "203.0.113.42", "limit": 10})

        assert "ATTACK CHAIN TRACE: 203.0.113.42" in result
        assert "SSH FAILED: user=root" in result
        assert "[ACCESS_ATTEMPT]" in result
        mock_embedder.get_chunks_containing_text.assert_called_once_with(
            search_text="203.0.113.42", limit=100
        )


class TestSecurityAnalystAgent:
    """Integration/unit tests for the SecurityAnalystAgent."""

    @pytest.fixture
    def mock_embedder(self):
        """Create a mock LogEmbedder."""
        return MagicMock(spec=LogEmbedder)

    def test_agent_initialization(self, mock_embedder):
        """Agent initializes successfully with provided mock embedder."""
        agent = SecurityAnalystAgent(
            openai_api_key="fake-key",
            model_name="gpt-4o-mini",
            embedder=mock_embedder,
        )
        assert agent.openai_api_key == "fake-key"
        assert agent.model_name == "gpt-4o-mini"
        assert agent.embedder == mock_embedder
        assert len(agent.tools) == 4

    def test_agent_analyze_no_threat(self, mock_embedder):
        """Agent performs analysis and formats final report with threat_detected=False."""
        agent = SecurityAnalystAgent(
            openai_api_key="fake-key",
            model_name="gpt-4o-mini",
            embedder=mock_embedder,
        )

        # Mock the tool calling LLM (simply returns no tool calls on the first turn)
        mock_llm_response = MagicMock(spec=AIMessage)
        mock_llm_response.tool_calls = []
        mock_llm_response.content = "I will formulate the report now."
        agent.llm_with_tools = MagicMock()
        agent.llm_with_tools.invoke.return_value = mock_llm_response

        # Mock the structured LLM formatter
        expected_report = IncidentReport(
            summary="All logs checked. No security threats or anomalies found.",
            threat_detected=False,
            threat_type=None,
            severity="NONE",
            timeline=[],
            recommended_action="Continue regular monitoring.",
            confidence_score=0.95,
        )
        agent.structured_llm = MagicMock()
        agent.structured_llm.invoke.return_value = expected_report

        # Run analysis
        req = AnalysisRequest(query="Check for threat", max_chunks=5)
        report = agent.analyze(req)

        # Verify calls and output
        assert report.threat_detected is False
        assert report.severity == "NONE"
        assert len(report.timeline) == 0
        agent.llm_with_tools.invoke.assert_called_once()
        agent.structured_llm.invoke.assert_called_once()

    def test_agent_analyze_with_tool_calls(self, mock_embedder):
        """Agent calls tools, receives tool output, then formats final IncidentReport."""
        agent = SecurityAnalystAgent(
            openai_api_key="fake-key",
            model_name="gpt-4o-mini",
            embedder=mock_embedder,
        )

        # Setup mock behavior:
        # Turn 1: LLM returns a tool call to search logs semantically.
        tool_call_id = "call_123"
        mock_tool_call_response = MagicMock(spec=AIMessage)
        mock_tool_call_response.content = ""
        mock_tool_call_response.tool_calls = [
            {
                "name": "search_logs_semantically",
                "args": {"query": "failed SSH", "limit": 2},
                "id": tool_call_id,
            }
        ]

        # Turn 2: LLM says "I have gathered the evidence, let's stop."
        mock_final_response = MagicMock(spec=AIMessage)
        mock_final_response.tool_calls = []
        mock_final_response.content = "Gathered enough logs."

        agent.llm_with_tools = MagicMock()
        agent.llm_with_tools.invoke.side_effect = [
            mock_tool_call_response,
            mock_final_response,
        ]

        # Setup mock embedder response for the search tool call
        mock_embedder.similarity_search.return_value = [
            {
                "content": "Jun 15 02:15:00 server sshd: Failed password for root from 203.0.113.42",
                "metadata": {
                    "log_source": "auth",
                    "start_time": "2026-06-15T02:00:00",
                    "end_time": "2026-06-15T02:15:00",
                },
            }
        ]

        # Mock structured LLM output
        expected_report = IncidentReport(
            summary="A brute force SSH attack was detected from IP 203.0.113.42.",
            threat_detected=True,
            threat_type="Brute Force SSH Attack",
            severity="MEDIUM",
            timeline=[
                TimelineEvent(
                    timestamp="2026-06-15T02:15:00",
                    log_line="Failed password for root from 203.0.113.42",
                    significance="Failed SSH login attempt.",
                )
            ],
            recommended_action="Block IP 203.0.113.42 at firewall.",
            confidence_score=0.85,
        )
        agent.structured_llm = MagicMock()
        agent.structured_llm.invoke.return_value = expected_report

        # Run analysis
        req = AnalysisRequest(query="Find failed logins")
        report = agent.analyze(req)

        # Assert results
        assert report.threat_detected is True
        assert report.threat_type == "Brute Force SSH Attack"
        assert report.severity == "MEDIUM"
        assert len(report.timeline) == 1
        assert report.timeline[0].timestamp == "2026-06-15T02:15:00"

        # Verify tool was called and model was invoked
        mock_embedder.similarity_search.assert_called_once()
        assert agent.llm_with_tools.invoke.call_count == 2
        agent.structured_llm.invoke.assert_called_once()

    def test_agent_analyze_failure_handling(self, mock_embedder):
        """Agent handles exceptions gracefully and returns a fallback IncidentReport."""
        agent = SecurityAnalystAgent(
            openai_api_key="fake-key",
            model_name="gpt-4o-mini",
            embedder=mock_embedder,
        )

        # Force structured LLM to raise an exception
        agent.llm_with_tools = MagicMock()
        agent.llm_with_tools.invoke.return_value = MagicMock(tool_calls=[])
        agent.structured_llm = MagicMock()
        agent.structured_llm.invoke.side_effect = Exception("API limit reached")

        req = AnalysisRequest(query="Crash me")
        report = agent.analyze(req)

        # Verify fallback report
        assert report.threat_detected is False
        assert "API limit reached" in report.summary
        assert report.severity == "NONE"
        assert len(report.timeline) == 0

