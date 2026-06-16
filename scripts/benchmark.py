"""
LogSentinel AI — Benchmark Runner

Runs the full agent pipeline against generated benchmark logs
and produces a scored results table.

Steps:
  1. Generate fresh benchmark logs (if not already present)
  2. Parse, chunk, and embed all three log formats
  3. Run the SecurityAnalystAgent with targeted queries per attack
  4. Score agent output against ground truth manifest
  5. Print results table and save to JSON

Requires: OPENAI_API_KEY in .env

Usage:
    python scripts/benchmark.py
"""

import json
import os
import sys
import time

# Ensure project root is on sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.config import settings
from app.ingestion.parser import parse_apache_logs, parse_auth_logs, parse_syslog_logs
from app.ingestion.chunker import chunk_by_time
from app.ingestion.embedder import LogEmbedder
from app.agent.analyst import SecurityAnalystAgent
from app.agent.schemas import AnalysisRequest, IncidentReport


# ── Paths ─────────────────────────────────────────────────────

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
LOG_DIR = os.path.join(DATA_DIR, "logs")
MANIFEST_PATH = os.path.join(DATA_DIR, "benchmark_manifest.json")
RESULTS_PATH = os.path.join(DATA_DIR, "benchmark_results.json")


# ── Severity Scoring ──────────────────────────────────────────

SEVERITY_ORDER = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def severity_distance(expected: str, actual: str) -> int:
    """Compute absolute distance between two severity levels.

    Returns 0 for exact match, 1 for one level off, etc.
    """
    return abs(SEVERITY_ORDER.get(expected, 0) - SEVERITY_ORDER.get(actual, 0))


# ── Ingestion Pipeline ───────────────────────────────────────

def ingest_benchmark_logs(embedder: LogEmbedder) -> dict:
    """Parse, chunk, and embed all benchmark log files.

    Returns:
        Dict with ingestion statistics.
    """
    stats = {"parsed": 0, "chunks": 0, "chunk_ids": []}

    log_files = {
        "apache": (os.path.join(LOG_DIR, "benchmark_apache.log"), parse_apache_logs),
        "auth": (os.path.join(LOG_DIR, "benchmark_auth.log"), parse_auth_logs),
        "syslog": (os.path.join(LOG_DIR, "benchmark_syslog.log"), parse_syslog_logs),
    }

    for source, (filepath, parser_fn) in log_files.items():
        if not os.path.exists(filepath):
            print(f"  [WARN] Missing {filepath} — skipping")
            continue

        with open(filepath, "r", encoding="utf-8") as f:
            text = f.read()

        entries, skipped = parser_fn(text)
        print(f"  {source:>8}: {len(entries)} parsed, {len(skipped)} skipped")

        chunks = chunk_by_time(entries, source, window_minutes=15)
        print(f"           {len(chunks)} chunks created")

        if chunks:
            chunk_ids = embedder.embed_and_store(chunks)
            stats["chunk_ids"].extend(chunk_ids)
            stats["chunks"] += len(chunks)

        stats["parsed"] += len(entries)

    return stats


# ── Analysis Runner ──────────────────────────────────────────

def run_analysis(agent: SecurityAnalystAgent, query: str) -> tuple[IncidentReport, float]:
    """Run the agent on a query and measure latency.

    Returns:
        Tuple of (IncidentReport, duration_seconds).
    """
    request = AnalysisRequest(query=query)
    start = time.time()
    report = agent.analyze(request)
    duration = time.time() - start
    return report, duration


# ── Scoring Functions ─────────────────────────────────────────

def score_detection(
    report: IncidentReport,
    expected_type: str,
    expected_severity: str,
    expected_ip: str,
    indicators: list[str],
) -> dict:
    """Score how well the agent detected a specific attack.

    Returns:
        Dict with scoring metrics for this scenario.
    """
    # Threat detected?
    threat_detected = report.threat_detected

    # Type match: fuzzy — check if expected type keywords appear in the report
    type_keywords = expected_type.lower().split()
    report_type = (report.threat_type or "").lower()
    report_summary = report.summary.lower()
    type_match = any(
        kw in report_type or kw in report_summary
        for kw in type_keywords
        if kw not in {"a", "the", "of", "and", "attempt"}
    )

    # Severity match
    sev_dist = severity_distance(expected_severity, report.severity)
    severity_exact = sev_dist == 0
    severity_close = sev_dist <= 1

    # IP mentioned in report?
    ip_mentioned = expected_ip in report.summary or any(
        expected_ip in e.log_line or expected_ip in e.significance
        for e in report.timeline
    )

    # Indicator coverage: how many attack indicators appear in the report text
    full_text = report.summary + " " + (report.threat_type or "") + " " + report.recommended_action
    for event in report.timeline:
        full_text += " " + event.log_line + " " + event.significance
    full_text_lower = full_text.lower()

    indicators_found = sum(
        1 for ind in indicators
        if ind.lower() in full_text_lower
    )
    indicator_coverage = indicators_found / len(indicators) if indicators else 0.0

    return {
        "threat_detected": threat_detected,
        "type_match": type_match,
        "severity_expected": expected_severity,
        "severity_actual": report.severity,
        "severity_exact": severity_exact,
        "severity_close": severity_close,
        "ip_mentioned": ip_mentioned,
        "confidence_score": report.confidence_score,
        "indicator_coverage": indicator_coverage,
        "timeline_events": len(report.timeline),
        "summary_excerpt": report.summary[:120],
    }


# ── Results Formatting ───────────────────────────────────────

def print_results_table(results: list[dict]) -> None:
    """Print a formatted ASCII results table."""
    print("\n" + "=" * 100)
    print("BENCHMARK RESULTS")
    print("=" * 100)

    # Header
    print(f"{'Scenario':<28} {'Detected':>8} {'Type':>6} {'Severity':>12} {'IP':>4} {'Conf':>6} {'Events':>6} {'Latency':>8}")
    print("-" * 100)

    total_detected = 0
    total_type_match = 0
    total_severity_exact = 0
    total_severity_close = 0
    total_ip = 0
    total_latency = 0.0
    total_confidence = 0.0

    for r in results:
        scenario = r["scenario"][:27]
        detected = "YES" if r["threat_detected"] else "NO"
        type_m = "YES" if r["type_match"] else "NO"
        sev = f"{r['severity_actual']}/{r['severity_expected']}"
        ip = "YES" if r["ip_mentioned"] else "NO"
        conf = f"{r['confidence_score']:.2f}"
        events = str(r["timeline_events"])
        latency = f"{r['latency']:.1f}s"

        print(f"{scenario:<28} {detected:>8} {type_m:>6} {sev:>12} {ip:>4} {conf:>6} {events:>6} {latency:>8}")

        total_detected += int(r["threat_detected"])
        total_type_match += int(r["type_match"])
        total_severity_exact += int(r["severity_exact"])
        total_severity_close += int(r["severity_close"])
        total_ip += int(r["ip_mentioned"])
        total_latency += r["latency"]
        total_confidence += r["confidence_score"]

    n = len(results)
    print("-" * 100)
    print(f"{'TOTALS':<28} {total_detected}/{n:>5} {total_type_match}/{n:>3} "
          f"{'exact=' + str(total_severity_exact) + '/' + str(n):>12} "
          f"{total_ip}/{n:>2} {total_confidence/n:>5.2f} "
          f"{'':>6} {total_latency/n:>7.1f}s")

    print("\n--- Summary Metrics ---")
    print(f"  Detection Rate:     {total_detected}/{n} ({total_detected/n*100:.0f}%)")
    print(f"  Type Accuracy:      {total_type_match}/{n} ({total_type_match/n*100:.0f}%)")
    print(f"  Severity Exact:     {total_severity_exact}/{n} ({total_severity_exact/n*100:.0f}%)")
    print(f"  Severity +/-1:      {total_severity_close}/{n} ({total_severity_close/n*100:.0f}%)")
    print(f"  IP Attribution:     {total_ip}/{n} ({total_ip/n*100:.0f}%)")
    print(f"  Avg Confidence:     {total_confidence/n:.2f}")
    print(f"  Avg Latency:        {total_latency/n:.1f}s")
    print(f"  Total Latency:      {total_latency:.1f}s")
    print("=" * 100)


# ── Main ──────────────────────────────────────────────────────

def main() -> None:
    """Run the full benchmark pipeline."""
    print("=" * 60)
    print("LogSentinel AI -- Benchmark Runner")
    print("=" * 60)

    # Pre-flight checks
    if not settings.openai_api_key or settings.openai_api_key == "test-openai-key":
        print("\n[ERROR] Valid OPENAI_API_KEY required in .env for benchmarking.")
        print("        The benchmark calls the full agent pipeline (embeddings + LLM).")
        sys.exit(1)

    # Step 1: Generate logs if not present
    print("\n[1/4] Generating benchmark logs...")
    if not os.path.exists(MANIFEST_PATH):
        from scripts.generate_logs import generate_all_logs
        manifest = generate_all_logs()
        print(f"       Generated {manifest['total_lines']['total']} lines")
    else:
        with open(MANIFEST_PATH, "r") as f:
            manifest = json.load(f)
        print(f"       Using existing logs ({manifest['total_lines']['total']} lines)")

    # Step 2: Ingest logs into ephemeral ChromaDB
    print("\n[2/4] Ingesting logs (parse -> chunk -> embed)...")
    collection_name = f"benchmark_{int(time.time())}"
    embedder = LogEmbedder(
        openai_api_key=settings.openai_api_key,
        embedding_model=settings.openai_embedding_model,
        collection_name=collection_name,
    )
    ingest_stats = ingest_benchmark_logs(embedder)
    print(f"       Total: {ingest_stats['parsed']} entries -> {ingest_stats['chunks']} chunks embedded")

    # Step 3: Run agent analysis for each planted attack
    print("\n[3/4] Running agent analysis...")
    agent = SecurityAnalystAgent(
        openai_api_key=settings.openai_api_key,
        model_name=settings.openai_model,
        embedder=embedder,
    )

    # Define targeted queries for each attack scenario
    attack_queries = {
        "brute_force_ssh": (
            f"Analyse auth logs for brute force SSH login attempts. "
            f"Look for repeated failed password attempts from the same IP address."
        ),
        "privilege_escalation": (
            f"Analyse auth logs for privilege escalation activity. "
            f"Look for suspicious sudo commands, user creation, file access to /etc/shadow, "
            f"and user switching that might indicate post-compromise activity."
        ),
        "port_scanning": (
            f"Analyse syslog and firewall logs for port scanning activity. "
            f"Look for sequential blocked connections to multiple ports from the same IP."
        ),
        "sql_injection": (
            f"Analyse web server logs for SQL injection attempts. "
            f"Look for suspicious query strings containing SQL keywords like UNION, SELECT, "
            f"OR 1=1, DROP TABLE, and known scanner user agents."
        ),
    }

    results = []

    for attack in manifest["planted_attacks"]:
        attack_id = attack["id"]
        query = attack_queries.get(attack_id, "Analyse all logs for security threats")

        print(f"\n  Running: {attack['type']}...")
        report, duration = run_analysis(agent, query)

        score = score_detection(
            report=report,
            expected_type=attack["type"],
            expected_severity=attack["expected_severity"],
            expected_ip=attack["attacker_ip"],
            indicators=attack.get("indicators", []),
        )
        score["scenario"] = attack["type"]
        score["attack_id"] = attack_id
        score["latency"] = duration
        score["query"] = query
        results.append(score)

        print(f"    Detected: {score['threat_detected']} | "
              f"Severity: {score['severity_actual']}/{score['severity_expected']} | "
              f"Confidence: {score['confidence_score']:.2f} | "
              f"Latency: {duration:.1f}s")

    # Step 4: Print and save results
    print("\n[4/4] Scoring results...")
    print_results_table(results)

    # Save results to JSON
    output = {
        "benchmark_run_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "model": settings.openai_model,
        "embedding_model": settings.openai_embedding_model,
        "total_log_lines": manifest["total_lines"]["total"],
        "scenarios": len(results),
        "results": results,
        "summary": {
            "detection_rate": sum(r["threat_detected"] for r in results) / len(results),
            "type_accuracy": sum(r["type_match"] for r in results) / len(results),
            "severity_exact_match": sum(r["severity_exact"] for r in results) / len(results),
            "severity_within_1": sum(r["severity_close"] for r in results) / len(results),
            "ip_attribution_rate": sum(r["ip_mentioned"] for r in results) / len(results),
            "avg_confidence": sum(r["confidence_score"] for r in results) / len(results),
            "avg_latency_seconds": sum(r["latency"] for r in results) / len(results),
            "total_latency_seconds": sum(r["latency"] for r in results),
        },
    }

    with open(RESULTS_PATH, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

    print(f"\n[SAVED] Results written to: {RESULTS_PATH}")

    # Cleanup: delete the benchmark collection
    try:
        embedder.chroma_client.delete_collection(collection_name)
        print(f"[CLEANUP] Deleted ephemeral collection: {collection_name}")
    except Exception:
        pass

    print("\nBenchmark complete.")


if __name__ == "__main__":
    main()
