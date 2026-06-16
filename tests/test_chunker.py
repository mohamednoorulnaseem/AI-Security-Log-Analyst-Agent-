"""
LogSentinel AI — Chunker Tests

Tests for time-based log chunking:
  - Basic windowing (entries group into correct 15-min windows)
  - Multiple windows (entries spanning > 15 minutes create multiple chunks)
  - Empty input handling
  - Chunk text formatting (human-readable output for embedding)
  - Metadata generation for ChromaDB
  - Entries with unparseable timestamps get skipped
  - Window alignment (windows start at clean 15-min boundaries)
"""

import pytest
from app.ingestion.chunker import chunk_by_time, LogChunk


# ══════════════════════════════════════════════════════════════
# Helper: create fake parsed log entries
# ══════════════════════════════════════════════════════════════

def _make_entry(timestamp: str, source_type: str = "apache", **kwargs) -> dict:
    """Create a minimal parsed log entry for testing."""
    entry = {
        "timestamp": timestamp,
        "source_type": source_type,
        "raw_line": f"test log line at {timestamp}",
    }
    entry.update(kwargs)
    return entry


# ══════════════════════════════════════════════════════════════
# Chunking Tests
# ══════════════════════════════════════════════════════════════

class TestChunkByTime:
    """Tests for the chunk_by_time function."""

    def test_single_window(self):
        """All entries within 15 minutes → single chunk."""
        entries = [
            _make_entry("2026-06-15T02:15:00", ip="192.168.1.1", method="GET", path="/", status=200, user_agent="Mozilla"),
            _make_entry("2026-06-15T02:16:00", ip="192.168.1.2", method="POST", path="/login", status=401, user_agent="curl"),
            _make_entry("2026-06-15T02:20:00", ip="192.168.1.3", method="GET", path="/admin", status=403, user_agent="Python"),
        ]
        chunks = chunk_by_time(entries, log_source="apache", window_minutes=15)

        assert len(chunks) == 1
        assert chunks[0].entry_count == 3
        assert chunks[0].log_source == "apache"
        assert chunks[0].chunk_index == 0

    def test_multiple_windows(self):
        """Entries spanning 45 minutes → 3 chunks with 15-min windows."""
        entries = [
            _make_entry("2026-06-15T02:00:00"),
            _make_entry("2026-06-15T02:05:00"),
            _make_entry("2026-06-15T02:15:00"),  # New window
            _make_entry("2026-06-15T02:25:00"),
            _make_entry("2026-06-15T02:30:00"),  # New window
            _make_entry("2026-06-15T02:40:00"),
        ]
        chunks = chunk_by_time(entries, log_source="apache", window_minutes=15)

        assert len(chunks) == 3
        assert chunks[0].entry_count == 2
        assert chunks[1].entry_count == 2
        assert chunks[2].entry_count == 2

    def test_empty_input(self):
        """No entries → no chunks."""
        chunks = chunk_by_time([], log_source="apache")
        assert chunks == []

    def test_custom_window_size(self):
        """5-minute windows should create more chunks."""
        entries = [
            _make_entry("2026-06-15T02:00:00"),
            _make_entry("2026-06-15T02:03:00"),
            _make_entry("2026-06-15T02:06:00"),  # New window at 5-min boundary
            _make_entry("2026-06-15T02:09:00"),
        ]
        chunks = chunk_by_time(entries, log_source="syslog", window_minutes=5)

        assert len(chunks) == 2
        assert chunks[0].entry_count == 2
        assert chunks[1].entry_count == 2

    def test_chunk_text_contains_entries(self):
        """Chunk text should contain human-readable representations."""
        entries = [
            _make_entry(
                "2026-06-15T02:15:00",
                source_type="apache",
                ip="10.0.0.1",
                method="GET",
                path="/secret",
                status=403,
                user_agent="sqlmap/1.5",
            ),
        ]
        chunks = chunk_by_time(entries, log_source="apache")

        assert len(chunks) == 1
        text = chunks[0].text
        # Text should contain key info for the embedding
        assert "10.0.0.1" in text
        assert "GET" in text
        assert "/secret" in text
        assert "403" in text

    def test_chunk_metadata(self):
        """Chunk metadata should be flat and contain required fields."""
        entries = [
            _make_entry("2026-06-15T02:15:00"),
            _make_entry("2026-06-15T02:20:00"),
        ]
        chunks = chunk_by_time(entries, log_source="auth")
        meta = chunks[0].to_metadata()

        assert "chunk_index" in meta
        assert "start_time" in meta
        assert "end_time" in meta
        assert "log_source" in meta
        assert meta["log_source"] == "auth"
        assert meta["entry_count"] == 2
        # All values should be primitive types (ChromaDB requirement)
        for v in meta.values():
            assert isinstance(v, (str, int, float, bool))

    def test_entries_sorted_by_time(self):
        """Out-of-order entries should be sorted before chunking."""
        entries = [
            _make_entry("2026-06-15T02:30:00"),  # Later
            _make_entry("2026-06-15T02:00:00"),  # Earlier
            _make_entry("2026-06-15T02:10:00"),  # Middle
        ]
        chunks = chunk_by_time(entries, log_source="apache", window_minutes=15)

        assert len(chunks) == 2
        # First chunk should contain the earlier entries
        assert chunks[0].start_time < chunks[1].start_time

    def test_skips_unparseable_timestamps(self):
        """Entries with bad timestamps are skipped, rest still chunks."""
        entries = [
            _make_entry("2026-06-15T02:15:00"),
            {"timestamp": "not-a-date", "source_type": "apache", "raw_line": "bad"},
            _make_entry("2026-06-15T02:20:00"),
        ]
        chunks = chunk_by_time(entries, log_source="apache")

        assert len(chunks) == 1
        assert chunks[0].entry_count == 2  # Bad entry skipped

    def test_auth_event_text_formatting(self):
        """Auth log entries should format with event type info."""
        entries = [
            _make_entry(
                "2026-06-15T02:15:00",
                source_type="auth",
                event_type="ssh_failed",
                user="root",
                ip="203.0.113.42",
                auth_method="password",
            ),
        ]
        chunks = chunk_by_time(entries, log_source="auth")
        text = chunks[0].text

        assert "SSH FAILED" in text
        assert "root" in text
        assert "203.0.113.42" in text

    def test_syslog_ufw_text_formatting(self):
        """UFW block entries should format with firewall info."""
        entries = [
            _make_entry(
                "2026-06-15T02:15:00",
                source_type="syslog",
                event_type="ufw_block",
                ip="45.33.32.156",
                port=22,
                service="ufw",
                message="[UFW BLOCK] ...",
            ),
        ]
        chunks = chunk_by_time(entries, log_source="syslog")
        text = chunks[0].text

        assert "FIREWALL" in text
        assert "45.33.32.156" in text
        assert "22" in text

    def test_timezone_aware_timestamps(self):
        """Entries with timezone info should chunk correctly."""
        entries = [
            _make_entry("2026-06-15T02:15:00+00:00"),
            _make_entry("2026-06-15T02:20:00+00:00"),
            _make_entry("2026-06-15T02:35:00+00:00"),  # Next window
        ]
        chunks = chunk_by_time(entries, log_source="apache", window_minutes=15)

        assert len(chunks) == 2

    def test_window_alignment(self):
        """Windows should align to clean boundaries (e.g., 02:00, 02:15, 02:30)."""
        entries = [
            _make_entry("2026-06-15T02:03:00"),  # Should be in 02:00-02:15 window
            _make_entry("2026-06-15T02:18:00"),  # Should be in 02:15-02:30 window
        ]
        chunks = chunk_by_time(entries, log_source="apache", window_minutes=15)

        assert len(chunks) == 2
        assert "02:00:00" in chunks[0].start_time
        assert "02:15:00" in chunks[0].end_time
        assert "02:15:00" in chunks[1].start_time
        assert "02:30:00" in chunks[1].end_time
