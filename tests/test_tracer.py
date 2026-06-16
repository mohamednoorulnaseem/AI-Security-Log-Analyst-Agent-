"""
LogSentinel AI — Tracer Unit Tests

Tests for the attack pattern tracing engine.
"""

from unittest.mock import MagicMock
import pytest

from app.agent.tracer import AttackTracer
from app.ingestion.embedder import LogEmbedder


class TestAttackTracer:
    """Unit tests for the AttackTracer class."""

    @pytest.fixture
    def mock_embedder(self):
        return MagicMock(spec=LogEmbedder)

    def test_trace_entity_sorting_and_deduplication(self, mock_embedder):
        """trace_entity sorts events chronologically and deduplicates duplicates."""
        # Return chunks out of order and containing duplicates
        mock_embedder.get_chunks_containing_text.return_value = [
            {
                "content": (
                    "Log chunk 1 | auth | 2026-06-15T02:00:00 to 2026-06-15T02:15:00 | 2 entries\n"
                    "---\n"
                    "[2026-06-15T02:15:00] SSH FAILED: user=root from 203.0.113.42 via password\n"
                    "[2026-06-15T02:10:00] SSH FAILED: user=root from 203.0.113.42 via password"
                ),
                "metadata": {"log_source": "auth"},
            },
            {
                "content": (
                    "Log chunk 2 | syslog | 2026-06-15T02:00:00 to 2026-06-15T02:15:00 | 2 entries\n"
                    "---\n"
                    "[2026-06-15T02:05:00] FIREWALL UFW BLOCK: 203.0.113.42 -> port 22\n"
                    "[2026-06-15T02:05:00] FIREWALL UFW BLOCK: 203.0.113.42 -> port 22"  # Duplicate
                ),
                "metadata": {"log_source": "syslog"},
            },
        ]

        tracer = AttackTracer(mock_embedder)
        result = tracer.trace_entity("203.0.113.42")

        assert result["entity"] == "203.0.113.42"
        events = result["events"]

        # Verify deduplication (only 3 unique events should remain: 02:05 block, 02:10 fail, 02:15 fail)
        assert len(events) == 3

        # Verify chronological sorting
        assert events[0]["timestamp"] == "2026-06-15T02:05:00"
        assert events[1]["timestamp"] == "2026-06-15T02:10:00"
        assert events[2]["timestamp"] == "2026-06-15T02:15:00"

        # Verify stage categorization
        assert events[0]["stage"] == "RECONNAISSANCE"
        assert events[1]["stage"] == "ACCESS_ATTEMPT"
        assert events[2]["stage"] == "ACCESS_ATTEMPT"

        assert result["stages_present"] == ["ACCESS_ATTEMPT", "RECONNAISSANCE"]

    def test_categorize_event_stages(self, mock_embedder):
        """_categorize_event maps messages to the correct attack stages."""
        tracer = AttackTracer(mock_embedder)

        # Privilege Escalation
        assert (
            tracer._categorize_event(
                "SUDO: root ran 'cat /etc/shadow' as root", "auth"
            )
            == "PRIVILEGE_ESCALATION"
        )
        assert (
            tracer._categorize_event("SU: root switched to postgres", "auth")
            == "PRIVILEGE_ESCALATION"
        )

        # Initial Access
        assert (
            tracer._categorize_event(
                "SSH accepted: user=root from 203.0.113.42 via publickey",
                "auth",
            )
            == "INITIAL_ACCESS"
        )
        assert (
            tracer._categorize_event(
                "[2026-06-15T02:15:00] HTTP POST /login from 203.0.113.42 -> 302",
                "apache",
            )
            == "INITIAL_ACCESS"
        )

        # Access Attempt
        assert (
            tracer._categorize_event(
                "SSH FAILED: user=root from 203.0.113.42 via password", "auth"
            )
            == "ACCESS_ATTEMPT"
        )
        assert (
            tracer._categorize_event(
                "HTTP GET /search?q=UNION SELECT from 203.0.113.42 -> 200",
                "apache",
            )
            == "ACCESS_ATTEMPT"
        )

        # Reconnaissance
        assert (
            tracer._categorize_event(
                "FIREWALL UFW BLOCK: 203.0.113.42 -> port 22", "syslog"
            )
            == "RECONNAISSANCE"
        )
        assert (
            tracer._categorize_event(
                "HTTP GET /wp-admin from 203.0.113.42 -> 403", "apache"
            )
            == "RECONNAISSANCE"
        )

        # None
        assert (
            tracer._categorize_event(
                "CRON: session opened for user root", "syslog"
            )
            == "NONE"
        )

    def test_format_trace_empty(self, mock_embedder):
        """format_trace returns friendly message for empty trace results."""
        tracer = AttackTracer(mock_embedder)
        trace_result = {
            "entity": "203.0.113.42",
            "events": [],
            "stages_present": [],
        }
        formatted = tracer.format_trace(trace_result)
        assert "No trace timeline could be reconstructed" in formatted

    def test_format_trace_with_warning(self, mock_embedder):
        """format_trace includes progression warning when multiple stages present."""
        tracer = AttackTracer(mock_embedder)
        trace_result = {
            "entity": "203.0.113.42",
            "events": [
                {
                    "timestamp": "2026-06-15T02:00:00",
                    "source": "syslog",
                    "stage": "RECONNAISSANCE",
                    "message": "FIREWALL UFW BLOCK: 203.0.113.42 -> port 22",
                },
                {
                    "timestamp": "2026-06-15T02:15:00",
                    "source": "auth",
                    "stage": "INITIAL_ACCESS",
                    "message": "SSH accepted: user=root from 203.0.113.42",
                },
            ],
            "stages_present": ["INITIAL_ACCESS", "RECONNAISSANCE"],
        }
        formatted = tracer.format_trace(trace_result)
        assert "=== ATTACK CHAIN TRACE: 203.0.113.42 ===" in formatted
        assert "FIREWALL UFW BLOCK" in formatted
        assert "WARNING: Multi-stage attack progression detected" in formatted
