"""
LogSentinel AI — Attack Pattern Tracer

Traces activity of an IP address or username across multiple log sources,
sorting events chronologically and categorizing them into attack progression stages:
  - RECONNAISSANCE
  - ACCESS_ATTEMPT
  - INITIAL_ACCESS
  - PRIVILEGE_ESCALATION
"""

import logging
import re
from typing import Any

from app.ingestion.embedder import LogEmbedder

logger = logging.getLogger(__name__)


class AttackTracer:
    """Correlates and traces multi-stage attack patterns from log chunks."""

    def __init__(self, embedder: LogEmbedder):
        """Initialize the tracer with the provided log embedder.

        Args:
            embedder: LogEmbedder instance.
        """
        self.embedder = embedder
        # Regex to parse timestamped lines: [2026-06-15T02:15:00] MESSAGE
        self.log_line_regex = re.compile(r"^\[([^\]]+)\]\s+(.*)$")

    def trace_entity(self, entity: str, limit: int = 20) -> dict[str, Any]:
        """Trace logs associated with an IP address or username.

        Args:
            entity: IP address (e.g. '203.0.113.42') or username (e.g. 'root')
            limit: Maximum number of events in the timeline

        Returns:
            Dict containing the entity, structured timeline, and identified stages.
        """
        logger.info("tracer_start_trace: entity=%s limit=%d", entity, limit)

        # Retrieve chunks containing the entity
        chunks = self.embedder.get_chunks_containing_text(
            search_text=entity, limit=100
        )

        events = []
        seen_lines = set()

        for chunk in chunks:
            log_source = chunk["metadata"].get("log_source", "unknown")
            content = chunk["content"]
            lines = content.split("\n")

            for line in lines:
                line = line.strip()
                if not line or line in seen_lines:
                    continue

                match = self.log_line_regex.match(line)
                if match:
                    timestamp_str = match.group(1)
                    message = match.group(2)

                    # Deduplicate exact same timestamp + message
                    line_key = f"{timestamp_str}|{message}"
                    if line_key in seen_lines:
                        continue
                    seen_lines.add(line_key)

                    # Determine attack stage
                    stage = self._categorize_event(message, log_source)

                    events.append({
                        "timestamp": timestamp_str,
                        "message": message,
                        "source": log_source,
                        "stage": stage,
                        "raw_line": line,
                    })

        # Sort all events chronologically
        events.sort(key=lambda x: x["timestamp"])

        # Deduplicate sequential identical events (e.g. duplicate UFW logs)
        deduped_events = []
        for e in events:
            if not deduped_events:
                deduped_events.append(e)
            else:
                last = deduped_events[-1]
                if (
                    last["timestamp"] == e["timestamp"]
                    and last["message"] == e["message"]
                ):
                    continue
                deduped_events.append(e)

        # Enforce limit
        deduped_events = deduped_events[:limit]

        # Extract stages present in the trace (excluding NONE)
        stages_present = sorted(
            list(set(e["stage"] for e in deduped_events if e["stage"] != "NONE"))
        )

        logger.info(
            "tracer_completed: entity=%s total_events=%d stages=%s",
            entity,
            len(deduped_events),
            stages_present,
        )

        return {
            "entity": entity,
            "events": deduped_events,
            "stages_present": stages_present,
        }

    def _categorize_event(self, message: str, source: str) -> str:
        """Categorize a log message into a security stage."""
        msg_upper = message.upper()

        # ── Stage 4: Privilege Escalation / Lateral Movement ─────────
        if (
            "SUDO:" in msg_upper
            or "SU:" in msg_upper
            or "SWITCHED TO" in msg_upper
        ):
            return "PRIVILEGE_ESCALATION"
        if "SHADOW" in msg_upper or "PASSWD" in msg_upper:
            return "PRIVILEGE_ESCALATION"

        # ── Stage 3: Initial Access ──────────────────────────────────
        if (
            "SSH ACCEPTED" in msg_upper
            or "ACCEPTED PASSWORD" in msg_upper
            or "ACCEPTED PUBLICKEY" in msg_upper
        ):
            return "INITIAL_ACCESS"
        # Successful login on web (Apache)
        if source == "apache" and (
            "POST /LOGIN" in msg_upper or "POST /SIGNIN" in msg_upper
        ):
            if "-> 200" in msg_upper or "-> 302" in msg_upper:
                return "INITIAL_ACCESS"

        # ── Stage 2: Access Attempt ──────────────────────────────────
        if (
            "SSH FAILED" in msg_upper
            or "FAILED PASSWORD" in msg_upper
            or "FAILED LOGIN" in msg_upper
        ):
            return "ACCESS_ATTEMPT"
        if "UNION" in msg_upper or "SELECT" in msg_upper or "OR 1=1" in msg_upper:
            return "ACCESS_ATTEMPT"
        if "SQLMAP" in msg_upper or "NIKTO" in msg_upper:
            return "ACCESS_ATTEMPT"
        if source == "apache" and "-> 401" in msg_upper:
            return "ACCESS_ATTEMPT"

        # ── Stage 1: Reconnaissance ──────────────────────────────────
        if (
            "FIREWALL" in msg_upper
            or "UFW BLOCK" in msg_upper
            or "UFW" in msg_upper
        ):
            return "RECONNAISSANCE"
        if "NMAP" in msg_upper or "PORT SCAN" in msg_upper:
            return "RECONNAISSANCE"
        if (
            "/ADMIN" in msg_upper
            or "/WP-ADMIN" in msg_upper
            or "/.ENV" in msg_upper
        ):
            return "RECONNAISSANCE"
        if source == "apache" and "-> 403" in msg_upper:
            return "RECONNAISSANCE"

        return "NONE"

    def format_trace(self, trace_result: dict[str, Any]) -> str:
        """Formats the trace dict into a clean human-readable text block.

        Args:
            trace_result: Result dict from trace_entity.

        Returns:
            Human-readable report of the reconstructed timeline.
        """
        entity = trace_result["entity"]
        events = trace_result["events"]
        stages = trace_result["stages_present"]

        if not events:
            return f"No trace timeline could be reconstructed for: {entity}"

        lines = [
            f"=== ATTACK CHAIN TRACE: {entity} ===",
            f"Stages Identified: {', '.join(stages) if stages else 'None'}",
            f"Timeline Events: {len(events)}",
            "---",
        ]

        for idx, e in enumerate(events):
            stage_marker = f"[{e['stage']}]" if e["stage"] != "NONE" else ""
            lines.append(
                f"{idx + 1}. {e['timestamp']} | {e['source'].upper()} | {stage_marker} {e['message']}"
            )

        # Highlight potential multi-stage progress
        if len(stages) >= 2:
            lines.append("---")
            lines.append(
                f"WARNING: Multi-stage attack progression detected across {len(stages)} stages."
            )

        return "\n".join(lines)
