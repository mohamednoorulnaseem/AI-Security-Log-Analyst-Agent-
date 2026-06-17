"""
LogSentinel AI — Agent Tools

LangChain tools available to the agent:
  1. Semantic search over ChromaDB log chunks
  2. Time-range filter for retrieving logs by timestamp
  3. IP correlation tool for tracing attack chains

Built in Phase 4 and extended in Phase 5.
"""

from typing import Optional
from langchain_core.tools import tool
from app.ingestion.embedder import LogEmbedder


def get_agent_tools(embedder: LogEmbedder) -> list:
    """Returns the list of tools available to the agent, bound to the provided embedder instance.

    Args:
        embedder: The LogEmbedder instance to query.

    Returns:
        List of LangChain tools.
    """

    @tool
    def search_logs_semantically(
        query: str, log_source: Optional[str] = None, limit: int = 5
    ) -> str:
        """Search log chunks semantically using natural language queries (e.g. 'unauthorized root login').

        Args:
            query: The semantic search query string.
            log_source: Optional filter for log format ('apache', 'auth', 'syslog').
            limit: Maximum number of chunks to retrieve (default: 5).

        Returns:
            A formatted string containing the matching log chunks and metadata.
        """
        filter_dict = {"log_source": log_source} if log_source else None
        results = embedder.similarity_search(
            query=query, k=limit, filter_dict=filter_dict
        )

        if not results:
            return "No matching log chunks found."

        formatted_results = []
        for idx, r in enumerate(results):
            meta = r["metadata"]
            formatted_results.append(
                f"### Result {idx + 1} | Source: {meta.get('log_source', 'unknown')} | "
                f"Time: {meta.get('start_time', 'unknown')} to {meta.get('end_time', 'unknown')}\n"
                f"{r['content']}\n"
            )
        return "\n".join(formatted_results)

    @tool
    def retrieve_logs_by_time_range(
        start_time: str,
        end_time: str,
        log_source: Optional[str] = None,
        limit: int = 10,
    ) -> str:
        """Retrieve log chunks within a specific time window.

        Args:
            start_time: Start timestamp in ISO 8601 format (e.g. '2026-06-15T02:00:00').
            end_time: End timestamp in ISO 8601 format (e.g. '2026-06-15T03:00:00').
            log_source: Optional filter for log format ('apache', 'auth', 'syslog').
            limit: Maximum number of chunks to retrieve (default: 10).

        Returns:
            A formatted string containing the log chunks and metadata within the time range.
        """
        # Retrieve chunks matching metadata log_source
        filter_dict = {"log_source": log_source} if log_source else None
        # Fetch a reasonable upper bound of chunks to filter in Python
        results = embedder.get_chunks_by_metadata(
            filter_dict=filter_dict, limit=100
        )

        # Filter by start_time and end_time range overlap:
        # c_start <= end_time AND c_end >= start_time
        filtered_results = []
        for r in results:
            meta = r["metadata"]
            c_start = meta.get("start_time", "")
            c_end = meta.get("end_time", "")
            if c_start and c_end:
                if c_start <= end_time and c_end >= start_time:
                    filtered_results.append(r)

        # Sort chronologically
        filtered_results.sort(
            key=lambda x: x["metadata"].get("start_time", "")
        )

        # Apply limit
        filtered_results = filtered_results[:limit]

        if not filtered_results:
            return f"No log chunks found in time range: {start_time} to {end_time}."

        formatted_results = []
        for idx, r in enumerate(filtered_results):
            meta = r["metadata"]
            formatted_results.append(
                f"### Log Chunk {idx + 1} | Source: {meta.get('log_source', 'unknown')} | "
                f"Time: {meta.get('start_time', 'unknown')} to {meta.get('end_time', 'unknown')}\n"
                f"{r['content']}\n"
            )
        return "\n".join(formatted_results)

    @tool
    def correlate_logs_by_ip(ip_address: str, limit: int = 10) -> str:
        """Find all log chunks containing a specific IP address.

        Args:
            ip_address: The exact IP address to trace (e.g. '203.0.113.42').
            limit: Maximum number of chunks to retrieve (default: 10).

        Returns:
            A formatted string of all log chunks containing the target IP address.
        """
        results = embedder.get_chunks_containing_text(
            search_text=ip_address, limit=limit
        )

        if not results:
            return f"No log chunks found containing IP address: {ip_address}."

        formatted_results = []
        for idx, r in enumerate(results):
            meta = r["metadata"]
            formatted_results.append(
                f"### Correlated Chunk {idx + 1} | Source: {meta.get('log_source', 'unknown')} | "
                f"Time: {meta.get('start_time', 'unknown')} to {meta.get('end_time', 'unknown')}\n"
                f"{r['content']}\n"
            )
        return "\n".join(formatted_results)

    @tool
    def trace_attack_chain(entity: str, limit: int = 20) -> str:
        """Reconstruct the attack timeline (stages and progression) for a specific IP address or username.

        Args:
            entity: The IP address (e.g. '203.0.113.42') or username (e.g. 'root') to trace.
            limit: Maximum number of timeline events to return (default: 20).

        Returns:
            A chronological, categorized timeline trace of events associated with the entity.
        """
        from app.agent.tracer import AttackTracer

        tracer = AttackTracer(embedder)
        result = tracer.trace_entity(entity=entity, limit=limit)
        return tracer.format_trace(result)

    return [
        search_logs_semantically,
        retrieve_logs_by_time_range,
        correlate_logs_by_ip,
        trace_attack_chain,
    ]

