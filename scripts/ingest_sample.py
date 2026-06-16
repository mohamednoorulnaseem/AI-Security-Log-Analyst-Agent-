"""
LogSentinel AI — End-to-End Ingestion Script

Demonstrates the complete pipeline:
  1. Read a sample log file
  2. Auto-detect format and parse
  3. Chunk into 15-minute windows
  4. Embed with OpenAI text-embedding-3-small
  5. Store in ChromaDB
  6. Verify chunks are stored with a test query

Usage:
    python scripts/ingest_sample.py

Requires:
    - OPENAI_API_KEY set in .env or environment
    - ChromaDB running (or uses local persistent mode)
"""

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv()

from app.ingestion.parser import detect_and_parse
from app.ingestion.chunker import chunk_by_time
from app.ingestion.embedder import LogEmbedder


def main():
    # ── Configuration ─────────────────────────────────────────
    openai_key = os.getenv("OPENAI_API_KEY")
    if not openai_key:
        print("ERROR: OPENAI_API_KEY not set. Copy .env.example to .env and add your key.")
        sys.exit(1)

    chroma_host = os.getenv("CHROMA_HOST")
    chroma_port = int(os.getenv("CHROMA_PORT", "8000"))
    collection_name = os.getenv("CHROMA_COLLECTION_NAME", "log_chunks")
    persist_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "chroma_data")

    # ── Step 1: Read sample log files ─────────────────────────
    sample_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "tests", "sample_logs",
    )

    log_files = ["apache_access.log", "auth.log", "syslog.log"]
    all_chunks = []

    for log_file in log_files:
        filepath = os.path.join(sample_dir, log_file)
        print(f"\n{'='*60}")
        print(f"Processing: {log_file}")
        print(f"{'='*60}")

        with open(filepath, "r") as f:
            raw_text = f.read()

        # ── Step 2: Parse ─────────────────────────────────────
        entries, skipped, detected_format = detect_and_parse(raw_text)
        print(f"  Format detected: {detected_format}")
        print(f"  Parsed entries:  {len(entries)}")
        print(f"  Skipped lines:   {len(skipped)}")

        if not entries:
            print(f"  WARNING: No entries parsed from {log_file}, skipping")
            continue

        # ── Step 3: Chunk ─────────────────────────────────────
        chunks = chunk_by_time(
            entries=entries,
            log_source=detected_format,
            window_minutes=15,
        )
        print(f"  Chunks created:  {len(chunks)}")

        for chunk in chunks:
            print(f"    Chunk {chunk.chunk_index}: "
                  f"{chunk.start_time} → {chunk.end_time} "
                  f"({chunk.entry_count} entries)")

        all_chunks.extend(chunks)

    if not all_chunks:
        print("\nNo chunks to embed. Check your log files.")
        sys.exit(1)

    # ── Step 4: Embed and Store ───────────────────────────────
    print(f"\n{'='*60}")
    print(f"Embedding {len(all_chunks)} chunks...")
    print(f"{'='*60}")

    # Use persistent local ChromaDB if no server is configured
    embedder = LogEmbedder(
        openai_api_key=openai_key,
        embedding_model=os.getenv("OPENAI_EMBEDDING_MODEL", "text-embedding-3-small"),
        chroma_host=chroma_host if chroma_host and chroma_host != "localhost" else None,
        chroma_port=chroma_port,
        collection_name=collection_name,
        persist_directory=persist_dir if not chroma_host or chroma_host == "localhost" else None,
    )

    chunk_ids = embedder.embed_and_store(all_chunks)
    print(f"  Stored {len(chunk_ids)} chunks in ChromaDB")
    print(f"  Chunk IDs: {chunk_ids[:3]}..." if len(chunk_ids) > 3 else f"  Chunk IDs: {chunk_ids}")

    # ── Step 5: Verify with Collection Stats ──────────────────
    stats = embedder.get_collection_stats()
    print(f"\n{'='*60}")
    print(f"ChromaDB Collection Stats")
    print(f"{'='*60}")
    print(f"  Collection: {stats['collection_name']}")
    print(f"  Documents:  {stats['document_count']}")
    print(f"  Model:      {stats['embedding_model']}")

    # ── Step 6: Test Semantic Search ──────────────────────────
    test_queries = [
        "failed SSH login attempts",
        "SQL injection attack",
        "port scan firewall blocked",
        "what happened between 2am and 3am",
        "sudo privilege escalation",
    ]

    print(f"\n{'='*60}")
    print(f"Testing Semantic Search")
    print(f"{'='*60}")

    for query in test_queries:
        print(f"\n  Query: '{query}'")
        results = embedder.similarity_search(query, k=2)
        for i, r in enumerate(results):
            meta = r["metadata"]
            score = r["score"]
            content_preview = r["content"][:100].replace("\n", " ")
            print(f"    Result {i+1} (score={score:.4f}): "
                  f"[{meta.get('log_source', '?')}] "
                  f"{meta.get('start_time', '?')} → {meta.get('end_time', '?')} "
                  f"({meta.get('entry_count', '?')} entries)")
            print(f"      Preview: {content_preview}...")

    print(f"\n{'='*60}")
    print(f"✅ End-to-end ingestion complete!")
    print(f"   {len(all_chunks)} chunks embedded and stored in ChromaDB")
    print(f"   Semantic search verified with {len(test_queries)} test queries")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
