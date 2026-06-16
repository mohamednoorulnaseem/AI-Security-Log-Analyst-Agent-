"""
LogSentinel AI — Log Parsers

Three parsers for three log formats, unified under a common interface.
Each parser:
  1. Takes raw text (string or list of lines)
  2. Returns a list of ParsedLogEntry dicts
  3. Logs and skips malformed lines — never crashes

Supported formats:
  - Apache/Nginx Combined Log Format
  - Linux auth logs (sshd, sudo, su)
  - Generic syslog (RFC 3164 style)

Every parsed entry contains at minimum:
  - timestamp (ISO 8601 string)
  - source_type ("apache" | "auth" | "syslog")
  - raw_line (original text for evidence)
  - Plus format-specific fields
"""

import re
import logging
from datetime import datetime
from typing import TypedDict, NotRequired

from dateutil import parser as dateutil_parser

logger = logging.getLogger(__name__)


# ── Common Output Schema ──────────────────────────────────────
# Using TypedDict so consumers get type hints without Pydantic overhead
# at the parsing stage. Pydantic is used at the API/agent layer.

class ParsedLogEntry(TypedDict):
    """Common shape for all parsed log entries."""
    timestamp: str              # ISO 8601
    source_type: str            # "apache" | "auth" | "syslog"
    raw_line: str               # Original log line for evidence
    # Format-specific fields are added as extra keys
    ip: NotRequired[str]
    user: NotRequired[str]
    method: NotRequired[str]
    path: NotRequired[str]
    status: NotRequired[int]
    size: NotRequired[int]
    user_agent: NotRequired[str]
    referer: NotRequired[str]
    hostname: NotRequired[str]
    service: NotRequired[str]
    pid: NotRequired[int]
    message: NotRequired[str]
    event_type: NotRequired[str]
    target_user: NotRequired[str]
    auth_method: NotRequired[str]
    port: NotRequired[int]
    command: NotRequired[str]


# ── Apache / Nginx Combined Log Format Parser ────────────────
# Format: IP - user [timestamp] "METHOD /path HTTP/x.x" status size "referer" "user-agent"
# This regex handles the standard Combined Log Format used by
# Apache and Nginx. The optional fields (referer, user-agent)
# gracefully handle missing values ("-").

APACHE_PATTERN = re.compile(
    r'^(?P<ip>\S+)'                           # Client IP
    r'\s+\S+'                                  # Ident (always -)
    r'\s+(?P<user>\S+)'                        # Auth user (or -)
    r'\s+\[(?P<timestamp>[^\]]+)\]'            # Timestamp in brackets
    r'\s+"(?P<method>\S+)'                     # HTTP method
    r'\s+(?P<path>\S+)'                        # Request path
    r'\s+\S+"'                                 # Protocol (HTTP/1.1)
    r'\s+(?P<status>\d{3})'                    # Status code
    r'\s+(?P<size>\d+|-)'                      # Response size (or -)
    r'(?:\s+"(?P<referer>[^"]*)")?'            # Referer (optional)
    r'(?:\s+"(?P<user_agent>[^"]*)")?'         # User-Agent (optional)
)

# Apache timestamp format: 15/Jun/2026:02:15:23 +0000
APACHE_TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


def parse_apache_line(line: str) -> ParsedLogEntry | None:
    """Parse a single Apache/Nginx Combined Log Format line.

    Returns None if the line doesn't match the expected format.
    """
    line = line.strip()
    if not line:
        return None

    match = APACHE_PATTERN.match(line)
    if not match:
        return None

    groups = match.groupdict()

    # Parse timestamp to ISO 8601
    try:
        ts = datetime.strptime(groups["timestamp"], APACHE_TIME_FORMAT)
        timestamp_iso = ts.isoformat()
    except ValueError:
        logger.warning("apache_timestamp_parse_failed: %s", line[:100])
        return None

    # Parse numeric fields safely
    status = int(groups["status"])
    size_str = groups["size"]
    size = 0 if size_str == "-" else int(size_str)
    user = groups["user"] if groups["user"] != "-" else None

    return ParsedLogEntry(
        timestamp=timestamp_iso,
        source_type="apache",
        raw_line=line,
        ip=groups["ip"],
        user=user,
        method=groups["method"],
        path=groups["path"],
        status=status,
        size=size,
        referer=groups.get("referer", "-"),
        user_agent=groups.get("user_agent", ""),
    )


def parse_apache_logs(text: str) -> tuple[list[ParsedLogEntry], list[str]]:
    """Parse multiple Apache log lines.

    Returns:
        Tuple of (parsed_entries, skipped_lines).
        Skipped lines are malformed — logged but never crash.
    """
    entries: list[ParsedLogEntry] = []
    skipped: list[str] = []

    for line_num, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        entry = parse_apache_line(line)
        if entry:
            entries.append(entry)
        else:
            skipped.append(line)
            logger.warning(
                "skipped_malformed_apache_line: line=%d preview=%s",
                line_num,
                line[:80],
            )

    logger.info(
        "apache_parse_complete: total=%d parsed=%d skipped=%d",
        len(entries) + len(skipped),
        len(entries),
        len(skipped),
    )
    return entries, skipped


# ── Linux Auth Log Parser ────────────────────────────────────
# Auth logs come from sshd, sudo, and su. Each has a different
# message format, so we use multiple patterns and classify
# the event_type based on which pattern matches.

# Base pattern: "Jun 15 02:15:01 hostname service[pid]: message"
AUTH_BASE_PATTERN = re.compile(
    r'^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'  # Syslog timestamp
    r'\s+(?P<hostname>\S+)'                                     # Hostname
    r'\s+(?P<service>\S+?)(?:\[(?P<pid>\d+)\])?'               # Service[PID]
    r':\s+(?P<message>.+)$'                                     # Message
)

# SSH-specific message patterns
SSH_ACCEPTED_PATTERN = re.compile(
    r'Accepted\s+(?P<auth_method>\S+)\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)'
)

SSH_FAILED_PATTERN = re.compile(
    r'Failed\s+(?P<auth_method>\S+)\s+for\s+(?:invalid\s+user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)'
)

# Sudo pattern: "user : TTY=... ; PWD=... ; USER=target ; COMMAND=cmd"
SUDO_PATTERN = re.compile(
    r'(?P<user>\S+)\s+:\s+TTY=\S+\s*;\s*PWD=\S+\s*;\s*USER=(?P<target_user>\S+)\s*;\s*COMMAND=(?P<command>.+)$'
)

# Su pattern: "Successful su for target by user" or "(to target) user on"
SU_PATTERN = re.compile(
    r'(?:Successful\s+su\s+for\s+(?P<target_user>\S+)\s+by\s+(?P<user>\S+))|'
    r'(?:\(to\s+(?P<target_user2>\S+)\)\s+(?P<user2>\S+)\s+on)'
)


def _infer_year_for_syslog_timestamp(ts_str: str) -> str:
    """Syslog timestamps don't include year. We assume current year.

    Why: Auth logs and syslog use "Jun 15 02:15:01" format without year.
    For a log analyst tool, we assume logs are from the current year.
    In production you'd check if the date is in the future and roll back.
    """
    current_year = datetime.now().year
    return f"{ts_str} {current_year}"


def parse_auth_line(line: str) -> ParsedLogEntry | None:
    """Parse a single auth log line (sshd, sudo, su).

    Classifies the event as one of:
      - ssh_accepted, ssh_failed
      - sudo_command
      - su_switch
      - auth_other (recognized format but unknown event type)
    """
    line = line.strip()
    if not line:
        return None

    base_match = AUTH_BASE_PATTERN.match(line)
    if not base_match:
        return None

    groups = base_match.groupdict()
    message = groups["message"]

    # Parse timestamp
    try:
        ts_with_year = _infer_year_for_syslog_timestamp(groups["timestamp"])
        ts = dateutil_parser.parse(ts_with_year)
        timestamp_iso = ts.isoformat()
    except (ValueError, TypeError):
        logger.warning("auth_timestamp_parse_failed: %s", line[:100])
        return None

    # Build base entry
    entry = ParsedLogEntry(
        timestamp=timestamp_iso,
        source_type="auth",
        raw_line=line,
        hostname=groups["hostname"],
        service=groups["service"],
        pid=int(groups["pid"]) if groups["pid"] else None,
        message=message,
    )

    # Try SSH accepted
    ssh_match = SSH_ACCEPTED_PATTERN.search(message)
    if ssh_match:
        ssh = ssh_match.groupdict()
        entry["event_type"] = "ssh_accepted"
        entry["user"] = ssh["user"]
        entry["ip"] = ssh["ip"]
        entry["port"] = int(ssh["port"])
        entry["auth_method"] = ssh["auth_method"]
        return entry

    # Try SSH failed
    ssh_match = SSH_FAILED_PATTERN.search(message)
    if ssh_match:
        ssh = ssh_match.groupdict()
        entry["event_type"] = "ssh_failed"
        entry["user"] = ssh["user"]
        entry["ip"] = ssh["ip"]
        entry["port"] = int(ssh["port"])
        entry["auth_method"] = ssh["auth_method"]
        return entry

    # Try sudo
    sudo_match = SUDO_PATTERN.search(message)
    if sudo_match:
        sudo = sudo_match.groupdict()
        entry["event_type"] = "sudo_command"
        entry["user"] = sudo["user"]
        entry["target_user"] = sudo["target_user"]
        entry["command"] = sudo["command"]
        return entry

    # Try su
    su_match = SU_PATTERN.search(message)
    if su_match:
        su = su_match.groupdict()
        entry["event_type"] = "su_switch"
        entry["target_user"] = su.get("target_user") or su.get("target_user2")
        entry["user"] = su.get("user") or su.get("user2")
        return entry

    # Recognized syslog format but unknown event type
    entry["event_type"] = "auth_other"
    return entry


def parse_auth_logs(text: str) -> tuple[list[ParsedLogEntry], list[str]]:
    """Parse multiple auth log lines.

    Returns:
        Tuple of (parsed_entries, skipped_lines).
    """
    entries: list[ParsedLogEntry] = []
    skipped: list[str] = []

    for line_num, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        entry = parse_auth_line(line)
        if entry:
            entries.append(entry)
        else:
            skipped.append(line)
            logger.warning(
                "skipped_malformed_auth_line: line=%d preview=%s",
                line_num,
                line[:80],
            )

    logger.info(
        "auth_parse_complete: total=%d parsed=%d skipped=%d",
        len(entries) + len(skipped),
        len(entries),
        len(skipped),
    )
    return entries, skipped


# ── Generic Syslog Parser ────────────────────────────────────
# Syslog (RFC 3164) format: "Jun 15 02:15:00 hostname service[pid]: message"
# Same base format as auth logs, but we extract different fields
# and don't try to classify SSH/sudo events.

# Known severity keywords found in syslog messages
SEVERITY_KEYWORDS = {
    "emerg": "EMERGENCY",
    "alert": "ALERT",
    "crit": "CRITICAL",
    "err": "ERROR",
    "error": "ERROR",
    "warn": "WARNING",
    "warning": "WARNING",
    "notice": "NOTICE",
    "info": "INFO",
    "debug": "DEBUG",
}

# UFW firewall log pattern for extracting blocked connection details
UFW_PATTERN = re.compile(
    r'\[UFW\s+(?P<action>\w+)\].*?SRC=(?P<src_ip>\S+).*?DST=(?P<dst_ip>\S+).*?PROTO=(?P<proto>\S+).*?DPT=(?P<dpt>\d+)'
)


def _detect_severity(message: str) -> str:
    """Infer severity from message content.

    Why heuristic: Generic syslog doesn't always include a structured
    severity field. We check for common keywords in the message text.
    """
    message_lower = message.lower()

    # Check for explicit severity keywords
    for keyword, severity in SEVERITY_KEYWORDS.items():
        if keyword in message_lower:
            return severity

    # Heuristic escalation patterns
    if "out of memory" in message_lower or "killed process" in message_lower:
        return "CRITICAL"
    if "syn flooding" in message_lower or "flood" in message_lower:
        return "WARNING"
    if "block" in message_lower:
        return "WARNING"
    if "started" in message_lower or "stopped" in message_lower:
        return "INFO"
    if "link up" in message_lower or "dhcp" in message_lower:
        return "INFO"

    return "INFO"


def parse_syslog_line(line: str) -> ParsedLogEntry | None:
    """Parse a single generic syslog line.

    Extracts service name, message, and infers severity.
    Also extracts UFW firewall block details when present.
    """
    line = line.strip()
    if not line:
        return None

    base_match = AUTH_BASE_PATTERN.match(line)
    if not base_match:
        return None

    groups = base_match.groupdict()
    message = groups["message"]

    # Parse timestamp
    try:
        ts_with_year = _infer_year_for_syslog_timestamp(groups["timestamp"])
        ts = dateutil_parser.parse(ts_with_year)
        timestamp_iso = ts.isoformat()
    except (ValueError, TypeError):
        logger.warning("syslog_timestamp_parse_failed: %s", line[:100])
        return None

    severity = _detect_severity(message)

    entry = ParsedLogEntry(
        timestamp=timestamp_iso,
        source_type="syslog",
        raw_line=line,
        hostname=groups["hostname"],
        service=groups["service"],
        pid=int(groups["pid"]) if groups["pid"] else None,
        message=message,
        event_type=severity,  # Reuse event_type for severity in syslog
    )

    # Extract UFW block details if present
    ufw_match = UFW_PATTERN.search(message)
    if ufw_match:
        ufw = ufw_match.groupdict()
        entry["ip"] = ufw["src_ip"]
        entry["port"] = int(ufw["dpt"])
        entry["event_type"] = f"ufw_{ufw['action'].lower()}"

    return entry


def parse_syslog_logs(text: str) -> tuple[list[ParsedLogEntry], list[str]]:
    """Parse multiple syslog lines.

    Returns:
        Tuple of (parsed_entries, skipped_lines).
    """
    entries: list[ParsedLogEntry] = []
    skipped: list[str] = []

    for line_num, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        entry = parse_syslog_line(line)
        if entry:
            entries.append(entry)
        else:
            skipped.append(line)
            logger.warning(
                "skipped_malformed_syslog_line: line=%d preview=%s",
                line_num,
                line[:80],
            )

    logger.info(
        "syslog_parse_complete: total=%d parsed=%d skipped=%d",
        len(entries) + len(skipped),
        len(entries),
        len(skipped),
    )
    return entries, skipped


# ── Auto-Detection ────────────────────────────────────────────
# When a user uploads a log file, we don't always know the format.
# This function tries all parsers and returns whichever gets the
# highest parse rate. This is a heuristic — not perfect — but
# good enough for the common case.

def detect_and_parse(text: str) -> tuple[list[ParsedLogEntry], list[str], str]:
    """Auto-detect log format and parse.

    Tries each parser on the first 20 lines. Whichever parser
    successfully parses the most lines wins. Then that parser
    processes the entire file.

    Returns:
        Tuple of (parsed_entries, skipped_lines, detected_format).
        detected_format is one of: "apache", "auth", "syslog", "unknown"
    """
    # Sample first 20 non-empty lines for detection
    sample_lines = [l for l in text.splitlines() if l.strip()][:20]
    sample_text = "\n".join(sample_lines)

    parsers = {
        "apache": parse_apache_logs,
        "auth": parse_auth_logs,
        "syslog": parse_syslog_logs,
    }

    best_format = "unknown"
    best_count = 0

    for fmt, parser_fn in parsers.items():
        entries, _ = parser_fn(sample_text)
        if len(entries) > best_count:
            best_count = len(entries)
            best_format = fmt

    if best_format == "unknown" or best_count == 0:
        logger.warning("log_format_detection_failed: sample_size=%d", len(sample_lines))
        return [], [l for l in text.splitlines() if l.strip()], "unknown"

    logger.info(
        "log_format_detected: format=%s parsed=%d total=%d",
        best_format,
        best_count,
        len(sample_lines),
    )

    # Parse entire file with the winning parser
    entries, skipped = parsers[best_format](text)
    return entries, skipped, best_format
