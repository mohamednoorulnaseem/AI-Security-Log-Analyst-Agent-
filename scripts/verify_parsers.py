"""Quick verification script — parses all sample log files and prints results."""
import sys
sys.path.insert(0, ".")

from app.ingestion.parser import parse_apache_logs, parse_auth_logs, parse_syslog_logs, detect_and_parse

# Test Apache logs
with open("tests/sample_logs/apache_access.log") as f:
    entries, skipped = parse_apache_logs(f.read())
print("=== Apache Logs ===")
print(f"Parsed: {len(entries)}, Skipped: {len(skipped)}")
for e in entries:
    ip = e.get("ip", "-")
    method = e.get("method", "-")
    path = e.get("path", "-")
    status = e.get("status", "-")
    ua = e.get("user_agent", "-")
    print(f"  {ip:>20s}  {method:>6s} {path:<50s}  {status}  ua={ua[:30]}")
print(f"Skipped: {skipped}")
print()

# Test Auth logs
with open("tests/sample_logs/auth.log") as f:
    entries, skipped = parse_auth_logs(f.read())
print("=== Auth Logs ===")
print(f"Parsed: {len(entries)}, Skipped: {len(skipped)}")
for e in entries:
    event = e.get("event_type", "unknown")
    user = e.get("user", "-")
    ip = e.get("ip", "-")
    cmd = e.get("command", "")
    print(f"  {event:<16s}  user={user:<10s}  ip={ip:<18s}  {cmd}")
print(f"Skipped: {skipped}")
print()

# Test Syslog
with open("tests/sample_logs/syslog.log") as f:
    entries, skipped = parse_syslog_logs(f.read())
print("=== Syslog ===")
print(f"Parsed: {len(entries)}, Skipped: {len(skipped)}")
for e in entries:
    svc = e.get("service", "-")
    evt = e.get("event_type", "-")
    msg = e.get("message", "")[:60]
    print(f"  {svc:<12s}  {evt:<12s}  {msg}")
print(f"Skipped: {skipped}")
print()

# Test auto-detection on each file
for name in ["apache_access.log", "auth.log", "syslog.log"]:
    with open(f"tests/sample_logs/{name}") as f:
        entries, skipped, fmt = detect_and_parse(f.read())
    print(f"Auto-detect {name}: format={fmt}, parsed={len(entries)}, skipped={len(skipped)}")
