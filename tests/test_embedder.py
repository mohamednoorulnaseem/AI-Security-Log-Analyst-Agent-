"""
LogSentinel AI — Embedder Integration Tests

Tests the full ChromaDB pipeline without requiring OpenAI API key.
Uses a fake embedding function to verify:
  - Chunks are stored in ChromaDB correctly
  - Metadata is preserved and queryable
  - Similarity search returns results
  - Collection stats are accurate
  - Collection deletion works
"""

import uuid
import pytest
from unittest.mock import MagicMock, patch
from langchain_core.embeddings import Embeddings

from app.ingestion.chunker import LogChunk, chunk_by_time
from app.ingestion.parser import parse_apache_logs, parse_auth_logs, parse_syslog_logs
from app.ingestion.embedder import LogEmbedder


class FakeEmbeddings(Embeddings):
    """Deterministic fake embeddings for testing without OpenAI.

    Produces a 10-dimensional vector based on the text length.
    Not semantically meaningful, but sufficient to verify the
    ChromaDB storage and retrieval pipeline works.
    """

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        return [self._fake_vector(t) for t in texts]

    def embed_query(self, text: str) -> list[float]:
        return self._fake_vector(text)

    @staticmethod
    def _fake_vector(text: str) -> list[float]:
        """Generate a deterministic vector from text."""
        # Use character sum modulo to create variety
        char_sum = sum(ord(c) for c in text)
        return [(char_sum + i) % 100 / 100.0 for i in range(10)]


class TestEmbedderIntegration:
    """Integration tests for LogEmbedder with ChromaDB (in-memory)."""

    def _make_embedder(self) -> LogEmbedder:
        """Create an embedder with fake embeddings and ephemeral ChromaDB.
        Each call gets a unique collection name to prevent cross-test contamination."""
        collection_name = f"test_{uuid.uuid4().hex[:8]}"
        embedder = LogEmbedder(
            openai_api_key="fake-key-for-testing",
            collection_name=collection_name,
            # No chroma_host and no persist_directory = ephemeral mode
        )
        # Replace the real OpenAI embeddings with our fake
        embedder._embeddings = FakeEmbeddings()
        # Reinitialize vector store with fake embeddings
        from langchain_chroma import Chroma
        embedder._vector_store = Chroma(
            client=embedder._chroma_client,
            collection_name=collection_name,
            embedding_function=FakeEmbeddings(),
        )
        return embedder

    def _make_chunks(self) -> list[LogChunk]:
        """Create test chunks from sample log data."""
        entries = [
            {
                "timestamp": "2026-06-15T02:15:00",
                "source_type": "auth",
                "raw_line": "Jun 15 02:15:00 server sshd: Failed password for root from 203.0.113.42",
                "event_type": "ssh_failed",
                "user": "root",
                "ip": "203.0.113.42",
                "auth_method": "password",
            },
            {
                "timestamp": "2026-06-15T02:16:00",
                "source_type": "auth",
                "raw_line": "Jun 15 02:16:00 server sshd: Failed password for root from 203.0.113.42",
                "event_type": "ssh_failed",
                "user": "root",
                "ip": "203.0.113.42",
                "auth_method": "password",
            },
            {
                "timestamp": "2026-06-15T02:30:00",
                "source_type": "auth",
                "raw_line": "Jun 15 02:30:00 server sshd: Accepted password for root from 203.0.113.42",
                "event_type": "ssh_accepted",
                "user": "root",
                "ip": "203.0.113.42",
                "auth_method": "password",
            },
        ]
        return chunk_by_time(entries, log_source="auth", window_minutes=15)

    def test_embed_and_store(self):
        """Chunks are stored in ChromaDB and IDs are returned."""
        embedder = self._make_embedder()
        chunks = self._make_chunks()

        ids = embedder.embed_and_store(chunks)

        assert len(ids) == len(chunks)
        assert all(isinstance(id_, str) for id_ in ids)
        assert len(set(ids)) == len(ids)  # All IDs unique

    def test_collection_stats_after_store(self):
        """Collection stats reflect the number of stored chunks."""
        embedder = self._make_embedder()
        chunks = self._make_chunks()

        embedder.embed_and_store(chunks)
        stats = embedder.get_collection_stats()

        assert stats["collection_name"].startswith("test_")
        assert stats["document_count"] == len(chunks)

    def test_metadata_preserved(self):
        """Chunk metadata (start_time, end_time, log_source) survives storage."""
        embedder = self._make_embedder()
        chunks = self._make_chunks()

        embedder.embed_and_store(chunks)
        results = embedder.similarity_search("SSH failed login", k=5)

        assert len(results) > 0
        for r in results:
            meta = r["metadata"]
            assert "start_time" in meta
            assert "end_time" in meta
            assert "log_source" in meta
            assert meta["log_source"] == "auth"
            assert "entry_count" in meta

    def test_similarity_search_returns_results(self):
        """Similarity search returns stored chunks."""
        embedder = self._make_embedder()
        chunks = self._make_chunks()

        embedder.embed_and_store(chunks)
        results = embedder.similarity_search("brute force attack", k=2)

        assert len(results) > 0
        assert "content" in results[0]
        assert "metadata" in results[0]
        assert "score" in results[0]

    def test_empty_chunks_no_error(self):
        """Embedding an empty list of chunks should not error."""
        embedder = self._make_embedder()
        ids = embedder.embed_and_store([])

        assert ids == []

    def test_search_with_metadata_filter(self):
        """Filtered search only returns matching chunks."""
        embedder = self._make_embedder()
        chunks = self._make_chunks()
        embedder.embed_and_store(chunks)

        # Filter for auth logs only (all our test data is auth)
        results = embedder.similarity_search(
            "login attempt",
            k=5,
            filter_dict={"log_source": "auth"},
        )

        assert len(results) > 0
        for r in results:
            assert r["metadata"]["log_source"] == "auth"

    def test_delete_collection(self):
        """Collection can be deleted and recreated."""
        embedder = self._make_embedder()
        chunks = self._make_chunks()

        embedder.embed_and_store(chunks)
        assert embedder.get_collection_stats()["document_count"] > 0

        success = embedder.delete_collection()
        assert success is True
        assert embedder.get_collection_stats()["document_count"] == 0


class TestFullPipelineIntegration:
    """End-to-end: parse → chunk → embed → search (without OpenAI)."""

    def _make_embedder(self) -> LogEmbedder:
        """Create an embedder with fake embeddings and unique collection."""
        collection_name = f"pipeline_{uuid.uuid4().hex[:8]}"
        embedder = LogEmbedder(
            openai_api_key="fake-key",
            collection_name=collection_name,
        )
        embedder._embeddings = FakeEmbeddings()
        from langchain_chroma import Chroma
        embedder._vector_store = Chroma(
            client=embedder._chroma_client,
            collection_name=collection_name,
            embedding_function=FakeEmbeddings(),
        )
        return embedder

    def test_apache_logs_end_to_end(self):
        """Parse Apache logs → chunk → embed → search."""
        raw = (
            '198.51.100.17 - - [15/Jun/2026:02:19:55 +0000] "POST /login HTTP/1.1" 401 256 "-" "Mozilla/5.0"\n'
            '198.51.100.17 - - [15/Jun/2026:02:19:58 +0000] "POST /login HTTP/1.1" 401 256 "-" "Mozilla/5.0"\n'
            '198.51.100.17 - - [15/Jun/2026:02:20:01 +0000] "POST /login HTTP/1.1" 401 256 "-" "Mozilla/5.0"\n'
            '45.33.32.156 - - [15/Jun/2026:02:21:00 +0000] "GET /search?q=1%27%20OR%201%3D1 HTTP/1.1" 200 4096 "-" "sqlmap/1.5"\n'
        )
        entries, skipped = parse_apache_logs(raw)
        chunks = chunk_by_time(entries, log_source="apache", window_minutes=15)

        embedder = self._make_embedder()
        ids = embedder.embed_and_store(chunks)

        assert len(ids) > 0

        results = embedder.similarity_search("SQL injection attack", k=1)
        assert len(results) > 0
        assert "apache" in results[0]["metadata"]["log_source"]

    def test_auth_logs_end_to_end(self):
        """Parse auth logs → chunk → embed → search."""
        raw = (
            "Jun 15 02:16:30 server1 sshd[12401]: Failed password for root from 203.0.113.42 port 48231 ssh2\n"
            "Jun 15 02:16:33 server1 sshd[12402]: Failed password for root from 203.0.113.42 port 48232 ssh2\n"
            "Jun 15 02:17:00 server1 sshd[12410]: Accepted password for root from 203.0.113.42 port 48240 ssh2\n"
        )
        entries, skipped = parse_auth_logs(raw)
        chunks = chunk_by_time(entries, log_source="auth", window_minutes=15)

        embedder = self._make_embedder()
        ids = embedder.embed_and_store(chunks)

        assert len(ids) > 0

        results = embedder.similarity_search("brute force SSH", k=1)
        assert len(results) > 0

    def test_syslog_end_to_end(self):
        """Parse syslog → chunk → embed → search."""
        raw = (
            "Jun 15 02:20:00 server1 ufw[8000]: [UFW BLOCK] IN=eth0 OUT= SRC=45.33.32.156 DST=192.168.1.10 PROTO=TCP SPT=12345 DPT=22\n"
            "Jun 15 02:20:01 server1 ufw[8000]: [UFW BLOCK] IN=eth0 OUT= SRC=45.33.32.156 DST=192.168.1.10 PROTO=TCP SPT=12346 DPT=23\n"
            "Jun 15 02:20:02 server1 ufw[8000]: [UFW BLOCK] IN=eth0 OUT= SRC=45.33.32.156 DST=192.168.1.10 PROTO=TCP SPT=12347 DPT=25\n"
        )
        entries, skipped = parse_syslog_logs(raw)
        chunks = chunk_by_time(entries, log_source="syslog", window_minutes=15)

        embedder = self._make_embedder()
        ids = embedder.embed_and_store(chunks)

        assert len(ids) > 0

        results = embedder.similarity_search("port scan firewall", k=1)
        assert len(results) > 0
        assert "syslog" in results[0]["metadata"]["log_source"]
