"""
LogSentinel AI — Log Chunker

Groups parsed log entries into time-based windows for embedding.

Why time-based chunking?
  - Security events are time-correlated (brute force = many failures in minutes)
  - Analysts think in time ranges ("what happened at 3am?")
  - Fixed-size text chunks would split attack sequences arbitrarily

Each chunk contains:
  - All log entries within the time window
  - A human-readable text representation (for embedding)
  - Metadata for filtered retrieval (start_time, end_time, source, index)

Default window: 15 minutes, configurable via LOG_CHUNK_WINDOW_MINUTES env var.
"""

import logging
from datetime import datetime, timedelta
from dataclasses import dataclass, field

from dateutil import parser as dateutil_parser

logger = logging.getLogger(__name__)


@dataclass
class LogChunk:
    """A time-windowed group of log entries ready for embedding.

    Attributes:
        chunk_index: Sequential index within this ingestion batch
        start_time: Window start (ISO 8601)
        end_time: Window end (ISO 8601)
        log_source: Format of the source logs ("apache" | "auth" | "syslog")
        entries: List of parsed log entry dicts in this window
        text: Human-readable representation for embedding
        entry_count: Number of log entries in this chunk
    """
    chunk_index: int
    start_time: str
    end_time: str
    log_source: str
    entries: list[dict] = field(default_factory=list)
    text: str = ""
    entry_count: int = 0

    def to_metadata(self) -> dict:
        """Return metadata dict for ChromaDB storage.

        ChromaDB metadata must be flat (no nested dicts/lists)
        and values must be str, int, float, or bool.
        """
        return {
            "chunk_index": self.chunk_index,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "log_source": self.log_source,
            "entry_count": self.entry_count,
        }


def _parse_timestamp(ts_str: str) -> datetime | None:
    """Safely parse an ISO 8601 timestamp string to datetime.

    Returns None if parsing fails — caller decides what to do.
    """
    try:
        return dateutil_parser.isoparse(ts_str)
    except (ValueError, TypeError):
        return None


def _format_entry_for_embedding(entry: dict) -> str:
    """Convert a parsed log entry to human-readable text for embedding.

    Why not just embed the JSON? Because embedding models understand
    natural language better. "Failed SSH login for root from 203.0.113.42"
    embeds much closer to security-related queries than raw JSON fields.
    """
    source_type = entry.get("source_type", "unknown")
    timestamp = entry.get("timestamp", "unknown_time")

    if source_type == "apache":
        ip = entry.get("ip", "unknown")
        method = entry.get("method", "?")
        path = entry.get("path", "/")
        status = entry.get("status", 0)
        ua = entry.get("user_agent", "")
        user = entry.get("user", "")
        user_part = f" user={user}" if user else ""
        return f"[{timestamp}] HTTP {method} {path} from {ip} -> {status}{user_part} (UA: {ua})"

    elif source_type == "auth":
        event_type = entry.get("event_type", "unknown")
        user = entry.get("user", "unknown")
        ip = entry.get("ip", "")
        command = entry.get("command", "")
        target = entry.get("target_user", "")

        if event_type == "ssh_accepted":
            auth = entry.get("auth_method", "")
            return f"[{timestamp}] SSH accepted: user={user} from {ip} via {auth}"
        elif event_type == "ssh_failed":
            auth = entry.get("auth_method", "")
            return f"[{timestamp}] SSH FAILED: user={user} from {ip} via {auth}"
        elif event_type == "sudo_command":
            return f"[{timestamp}] SUDO: {user} ran '{command}' as {target}"
        elif event_type == "su_switch":
            return f"[{timestamp}] SU: {user} switched to {target}"
        else:
            msg = entry.get("message", "")
            return f"[{timestamp}] AUTH: {msg}"

    elif source_type == "syslog":
        service = entry.get("service", "unknown")
        event_type = entry.get("event_type", "INFO")
        message = entry.get("message", "")
        ip = entry.get("ip", "")
        port = entry.get("port", "")

        if "ufw" in event_type:
            return f"[{timestamp}] FIREWALL {event_type}: {ip} -> port {port}"
        else:
            return f"[{timestamp}] {service} [{event_type}]: {message}"

    else:
        raw = entry.get("raw_line", str(entry))
        return f"[{timestamp}] {raw}"


def chunk_by_time(
    entries: list[dict],
    log_source: str,
    window_minutes: int = 15,
) -> list[LogChunk]:
    """Group parsed log entries into time-based windows.

    Args:
        entries: List of parsed log entries (must have 'timestamp' field)
        log_source: Source format identifier ("apache" | "auth" | "syslog")
        window_minutes: Size of each time window in minutes (default: 15)

    Returns:
        List of LogChunk objects, sorted by start_time.

    Algorithm:
        1. Parse all timestamps, skip entries with unparseable timestamps
        2. Sort by timestamp (logs aren't always in order)
        3. Find the earliest timestamp, create windows from there
        4. Assign each entry to its window
        5. Generate human-readable text for each non-empty chunk

    Empty windows are skipped — if nothing happened between 02:15 and 02:30,
    we don't create a chunk for it. This keeps the vector store lean.
    """
    if not entries:
        logger.info("chunk_by_time: no entries to chunk")
        return []

    # Step 1: Parse timestamps and pair with entries
    timed_entries: list[tuple[datetime, dict]] = []
    skipped_count = 0

    for entry in entries:
        ts = _parse_timestamp(entry.get("timestamp", ""))
        if ts is None:
            skipped_count += 1
            logger.warning(
                "chunk_skipped_unparseable_timestamp: %s",
                entry.get("timestamp", "missing"),
            )
            continue
        # Make offset-naive for consistent comparison
        if ts.tzinfo is not None:
            ts = ts.replace(tzinfo=None)
        timed_entries.append((ts, entry))

    if not timed_entries:
        logger.warning("chunk_by_time: all entries had unparseable timestamps")
        return []

    # Step 2: Sort by timestamp
    timed_entries.sort(key=lambda x: x[0])

    # Step 3: Determine window boundaries
    window_delta = timedelta(minutes=window_minutes)
    earliest = timed_entries[0][0]
    latest = timed_entries[-1][0]

    # Align to window boundary (floor to nearest window)
    window_start = earliest.replace(
        minute=(earliest.minute // window_minutes) * window_minutes,
        second=0,
        microsecond=0,
    )

    # Step 4: Assign entries to windows
    # Using a dict so we only create chunks for windows that have data
    windows: dict[datetime, list[dict]] = {}
    for ts, entry in timed_entries:
        # Find which window this entry belongs to
        offset = ts - window_start
        window_index = int(offset.total_seconds() // window_delta.total_seconds())
        w_start = window_start + (window_delta * window_index)

        if w_start not in windows:
            windows[w_start] = []
        windows[w_start].append(entry)

    # Step 5: Build LogChunk objects
    chunks: list[LogChunk] = []
    sorted_windows = sorted(windows.keys())

    for idx, w_start in enumerate(sorted_windows):
        w_end = w_start + window_delta
        window_entries = windows[w_start]

        # Generate human-readable text
        text_lines = [
            f"Log chunk {idx} | {log_source} | {w_start.isoformat()} to {w_end.isoformat()} | {len(window_entries)} entries",
            "---",
        ]
        for entry in window_entries:
            text_lines.append(_format_entry_for_embedding(entry))

        chunk = LogChunk(
            chunk_index=idx,
            start_time=w_start.isoformat(),
            end_time=w_end.isoformat(),
            log_source=log_source,
            entries=window_entries,
            text="\n".join(text_lines),
            entry_count=len(window_entries),
        )
        chunks.append(chunk)

    logger.info(
        "chunking_complete: source=%s entries=%d chunks=%d window=%dm skipped=%d",
        log_source,
        len(timed_entries),
        len(chunks),
        window_minutes,
        skipped_count,
    )

    return chunks
