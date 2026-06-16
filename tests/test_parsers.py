"""
LogSentinel AI — Parser Tests

Comprehensive tests for all three log parsers:
  - Apache/Nginx access log parser (7 tests)
  - Auth log parser (7 tests)
  - Syslog parser (5 tests)
  - Auto-detection (3 tests)
  - Malformed line handling (2 tests)

Total: 24 test cases covering normal traffic, security events,
edge cases, and malformed input.
"""

import pytest
from app.ingestion.parser import (
    parse_apache_line,
    parse_apache_logs,
    parse_auth_line,
    parse_auth_logs,
    parse_syslog_line,
    parse_syslog_logs,
    detect_and_parse,
)


# ══════════════════════════════════════════════════════════════
# Apache / Nginx Parser Tests
# ══════════════════════════════════════════════════════════════

class TestApacheParser:
    """Tests for Apache/Nginx Combined Log Format parser."""

    def test_parse_normal_get_request(self):
        """Normal GET request — the most common log line."""
        line = '192.168.1.100 - - [15/Jun/2026:02:15:23 +0000] "GET /index.html HTTP/1.1" 200 3456 "https://example.com" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"'
        entry = parse_apache_line(line)

        assert entry is not None
        assert entry["ip"] == "192.168.1.100"
        assert entry["method"] == "GET"
        assert entry["path"] == "/index.html"
        assert entry["status"] == 200
        assert entry["size"] == 3456
        assert entry["source_type"] == "apache"
        assert entry["user"] is None  # "-" becomes None
        assert "2026-06-15" in entry["timestamp"]

    def test_parse_post_with_auth_user(self):
        """POST with authenticated user — admin login."""
        line = '10.0.0.55 - admin [15/Jun/2026:02:16:45 +0000] "POST /api/login HTTP/1.1" 200 128 "-" "curl/7.68.0"'
        entry = parse_apache_line(line)

        assert entry is not None
        assert entry["user"] == "admin"
        assert entry["method"] == "POST"
        assert entry["path"] == "/api/login"
        assert entry["user_agent"] == "curl/7.68.0"

    def test_parse_403_forbidden(self):
        """403 Forbidden — someone probing admin panel."""
        line = '203.0.113.42 - - [15/Jun/2026:02:18:30 +0000] "GET /admin/config HTTP/1.1" 403 1024 "-" "Python-urllib/3.9"'
        entry = parse_apache_line(line)

        assert entry is not None
        assert entry["status"] == 403
        assert entry["path"] == "/admin/config"
        assert entry["ip"] == "203.0.113.42"

    def test_parse_401_brute_force(self):
        """401 Unauthorized — brute force login attempt."""
        line = '198.51.100.17 - - [15/Jun/2026:02:19:55 +0000] "POST /login HTTP/1.1" 401 256 "-" "Mozilla/5.0"'
        entry = parse_apache_line(line)

        assert entry is not None
        assert entry["status"] == 401
        assert entry["method"] == "POST"
        assert entry["path"] == "/login"

    def test_parse_sql_injection_attempt(self):
        """GET with SQL injection in query string — via sqlmap."""
        line = '45.33.32.156 - - [15/Jun/2026:02:21:00 +0000] "GET /search?q=1%27%20OR%201%3D1%20-- HTTP/1.1" 200 4096 "-" "sqlmap/1.5"'
        entry = parse_apache_line(line)

        assert entry is not None
        assert "search?q=1" in entry["path"]
        assert entry["user_agent"] == "sqlmap/1.5"
        assert entry["status"] == 200  # Server didn't block it

    def test_parse_500_error(self):
        """500 Internal Server Error — possible SQLi success."""
        line = '45.33.32.156 - - [15/Jun/2026:02:21:03 +0000] "GET /search?q=1%27%20UNION%20SELECT%20username%2Cpassword%20FROM%20users-- HTTP/1.1" 500 0 "-" "sqlmap/1.5"'
        entry = parse_apache_line(line)

        assert entry is not None
        assert entry["status"] == 500
        assert entry["size"] == 0
        assert "UNION" in entry["path"]

    def test_parse_304_not_modified(self):
        """304 Not Modified — cached resource, completely normal."""
        line = '192.168.1.100 - - [15/Jun/2026:02:17:01 +0000] "GET /dashboard HTTP/1.1" 304 0 "https://example.com/index.html" "Mozilla/5.0"'
        entry = parse_apache_line(line)

        assert entry is not None
        assert entry["status"] == 304
        assert entry["size"] == 0


# ══════════════════════════════════════════════════════════════
# Auth Log Parser Tests
# ══════════════════════════════════════════════════════════════

class TestAuthParser:
    """Tests for Linux auth log parser (sshd, sudo, su)."""

    def test_parse_ssh_accepted_publickey(self):
        """Successful SSH via public key — normal operation."""
        line = "Jun 15 02:15:01 server1 sshd[12345]: Accepted publickey for deploy from 192.168.1.100 port 52413 ssh2"
        entry = parse_auth_line(line)

        assert entry is not None
        assert entry["event_type"] == "ssh_accepted"
        assert entry["user"] == "deploy"
        assert entry["ip"] == "192.168.1.100"
        assert entry["auth_method"] == "publickey"
        assert entry["source_type"] == "auth"

    def test_parse_ssh_failed_password(self):
        """Failed SSH password — brute force attempt."""
        line = "Jun 15 02:16:30 server1 sshd[12401]: Failed password for root from 203.0.113.42 port 48231 ssh2"
        entry = parse_auth_line(line)

        assert entry is not None
        assert entry["event_type"] == "ssh_failed"
        assert entry["user"] == "root"
        assert entry["ip"] == "203.0.113.42"
        assert entry["auth_method"] == "password"

    def test_parse_ssh_failed_invalid_user(self):
        """Failed SSH for non-existent user — scanning for valid usernames."""
        line = "Jun 15 02:18:00 server1 sshd[12500]: Failed password for invalid user admin from 198.51.100.17 port 55123 ssh2"
        entry = parse_auth_line(line)

        assert entry is not None
        assert entry["event_type"] == "ssh_failed"
        assert entry["user"] == "admin"
        assert entry["ip"] == "198.51.100.17"

    def test_parse_ssh_accepted_after_failures(self):
        """SSH accepted (password) — might be after brute force success."""
        line = "Jun 15 02:17:00 server1 sshd[12410]: Accepted password for root from 203.0.113.42 port 48240 ssh2"
        entry = parse_auth_line(line)

        assert entry is not None
        assert entry["event_type"] == "ssh_accepted"
        assert entry["user"] == "root"
        assert entry["auth_method"] == "password"

    def test_parse_sudo_command(self):
        """Sudo command execution — could be escalation."""
        line = "Jun 15 02:17:30 server1 sudo: root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/cat /etc/shadow"
        entry = parse_auth_line(line)

        assert entry is not None
        assert entry["event_type"] == "sudo_command"
        assert entry["command"] == "/bin/cat /etc/shadow"
        assert entry["target_user"] == "root"

    def test_parse_su_switch(self):
        """su user switch — lateral movement."""
        line = "Jun 15 02:19:00 server1 su[12600]: Successful su for www-data by root"
        entry = parse_auth_line(line)

        assert entry is not None
        assert entry["event_type"] == "su_switch"
        assert entry["target_user"] == "www-data"
        assert entry["user"] == "root"

    def test_parse_auth_with_pid(self):
        """Verify PID extraction from service[pid] format."""
        line = "Jun 15 02:20:00 server1 sshd[12700]: Accepted publickey for ubuntu from 10.0.0.5 port 60001 ssh2"
        entry = parse_auth_line(line)

        assert entry is not None
        assert entry["pid"] == 12700
        assert entry["hostname"] == "server1"


# ══════════════════════════════════════════════════════════════
# Syslog Parser Tests
# ══════════════════════════════════════════════════════════════

class TestSyslogParser:
    """Tests for generic syslog parser."""

    def test_parse_kernel_link_up(self):
        """Normal kernel message — network interface up."""
        line = "Jun 15 02:15:00 server1 kernel: [  123.456789] eth0: link up, 1000 Mbps"
        entry = parse_syslog_line(line)

        assert entry is not None
        assert entry["service"] == "kernel"
        assert entry["source_type"] == "syslog"
        assert "link up" in entry["message"]

    def test_parse_syn_flood_warning(self):
        """SYN flood detection — serious network threat."""
        line = "Jun 15 02:17:00 server1 kernel: [  245.789012] TCP: request_sock_TCP: Possible SYN flooding on port 80. Sending cookies."
        entry = parse_syslog_line(line)

        assert entry is not None
        assert "SYN flooding" in entry["message"]
        # Severity should be WARNING due to "flood" keyword
        assert entry["event_type"] == "WARNING"

    def test_parse_oom_kill(self):
        """Out of Memory kill — critical system event."""
        line = "Jun 15 02:18:00 server1 kernel: [  300.123456] Out of memory: Killed process 12345 (java) total-vm:4096000kB"
        entry = parse_syslog_line(line)

        assert entry is not None
        assert "Out of memory" in entry["message"]
        assert entry["event_type"] == "CRITICAL"

    def test_parse_ufw_block(self):
        """UFW firewall block — port scan indicator."""
        line = "Jun 15 02:20:00 server1 ufw[8000]: [UFW BLOCK] IN=eth0 OUT= SRC=45.33.32.156 DST=192.168.1.10 PROTO=TCP SPT=12345 DPT=22"
        entry = parse_syslog_line(line)

        assert entry is not None
        assert entry["event_type"] == "ufw_block"
        assert entry["ip"] == "45.33.32.156"
        assert entry["port"] == 22

    def test_parse_service_restart(self):
        """Service restart — normal maintenance activity."""
        line = "Jun 15 02:19:15 server1 systemd[1]: Started PostgreSQL database server."
        entry = parse_syslog_line(line)

        assert entry is not None
        assert entry["service"] == "systemd"
        assert "Started" in entry["message"]


# ══════════════════════════════════════════════════════════════
# Multi-Line Parsing and Malformed Input Tests
# ══════════════════════════════════════════════════════════════

class TestMultiLineParsing:
    """Tests for parsing entire log files and handling malformed input."""

    def test_apache_file_with_malformed_line(self):
        """Entire Apache log file — malformed line gets skipped, rest parses fine."""
        text = (
            '192.168.1.100 - - [15/Jun/2026:02:15:23 +0000] "GET /index.html HTTP/1.1" 200 3456 "https://example.com" "Mozilla/5.0"\n'
            'this is a malformed line that should be skipped gracefully\n'
            '172.16.0.5 - - [15/Jun/2026:02:22:15 +0000] "GET /static/style.css HTTP/1.1" 200 8192 "https://example.com" "Mozilla/5.0"\n'
        )
        entries, skipped = parse_apache_logs(text)

        assert len(entries) == 2
        assert len(skipped) == 1
        assert "malformed" in skipped[0]

    def test_auth_file_with_malformed_line(self):
        """Auth log file — malformed line skipped, events classified correctly."""
        text = (
            "Jun 15 02:16:30 server1 sshd[12401]: Failed password for root from 203.0.113.42 port 48231 ssh2\n"
            "this line is garbage and should be skipped\n"
            "Jun 15 02:17:00 server1 sshd[12410]: Accepted password for root from 203.0.113.42 port 48240 ssh2\n"
        )
        entries, skipped = parse_auth_logs(text)

        assert len(entries) == 2
        assert len(skipped) == 1
        assert entries[0]["event_type"] == "ssh_failed"
        assert entries[1]["event_type"] == "ssh_accepted"


# ══════════════════════════════════════════════════════════════
# Auto-Detection Tests
# ══════════════════════════════════════════════════════════════

class TestAutoDetection:
    """Tests for automatic log format detection."""

    def test_detect_apache_format(self):
        """Auto-detect Apache logs from file content."""
        text = (
            '192.168.1.100 - - [15/Jun/2026:02:15:23 +0000] "GET /index.html HTTP/1.1" 200 3456 "https://example.com" "Mozilla/5.0"\n'
            '10.0.0.55 - admin [15/Jun/2026:02:16:45 +0000] "POST /api/login HTTP/1.1" 200 128 "-" "curl/7.68.0"\n'
        )
        entries, skipped, fmt = detect_and_parse(text)

        assert fmt == "apache"
        assert len(entries) == 2
        assert len(skipped) == 0

    def test_detect_auth_format(self):
        """Auto-detect auth logs from file content."""
        text = (
            "Jun 15 02:16:30 server1 sshd[12401]: Failed password for root from 203.0.113.42 port 48231 ssh2\n"
            "Jun 15 02:17:00 server1 sshd[12410]: Accepted password for root from 203.0.113.42 port 48240 ssh2\n"
            "Jun 15 02:17:30 server1 sudo: root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/cat /etc/shadow\n"
        )
        entries, skipped, fmt = detect_and_parse(text)

        # Auth and syslog share the same base format, but auth-specific patterns
        # (ssh_accepted, ssh_failed, sudo) should give auth more parsed entries
        assert fmt in ("auth", "syslog")  # Both can parse this format
        assert len(entries) == 3

    def test_detect_unknown_format(self):
        """Completely unrecognizable format — returns unknown."""
        text = "random garbage\nnot a log format\nmore nonsense\n"
        entries, skipped, fmt = detect_and_parse(text)

        assert fmt == "unknown"
        assert len(entries) == 0
        assert len(skipped) == 3


# ══════════════════════════════════════════════════════════════
# Edge Case Tests
# ══════════════════════════════════════════════════════════════

class TestEdgeCases:
    """Edge cases that could crash a naive parser."""

    def test_empty_input(self):
        """Empty string should return empty results, not crash."""
        entries, skipped = parse_apache_logs("")
        assert entries == []
        assert skipped == []

    def test_blank_lines_only(self):
        """File with only whitespace lines."""
        entries, skipped = parse_auth_logs("\n\n   \n\n")
        assert entries == []
        assert skipped == []

    def test_none_from_empty_line(self):
        """Single-line parsers return None for empty input."""
        assert parse_apache_line("") is None
        assert parse_auth_line("") is None
        assert parse_syslog_line("") is None

    def test_apache_size_dash(self):
        """Size field as '-' (no body) should parse as 0."""
        line = '192.168.1.1 - - [15/Jun/2026:02:15:23 +0000] "HEAD / HTTP/1.1" 200 - "-" "curl"'
        entry = parse_apache_line(line)

        assert entry is not None
        assert entry["size"] == 0
