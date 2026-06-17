"""
LogSentinel AI — Embedding Pipeline

Embeds log chunks using OpenAI text-embedding-3-small and stores
them in ChromaDB with metadata for filtered retrieval.

Architecture decision: We use LangChain's Chroma integration for
embedding + storage in one step. This avoids manually calling the
OpenAI API and managing vector IDs.

ChromaDB is used in two modes:
  - Client mode (HttpClient): When ChromaDB runs as a Docker service
  - Persistent mode: When running locally for dev/testing

The embedder is stateless — it creates/gets a collection and adds
documents. Re-ingesting the same logs creates new chunks (not upserts)
because the same log file might be re-analysed with different window sizes.
"""

import logging
import uuid
from typing import Optional

import chromadb
from chromadb.config import Settings as ChromaSettings
from langchain_openai import OpenAIEmbeddings
from langchain_chroma import Chroma

from app.config import settings
from app.ingestion.chunker import LogChunk

logger = logging.getLogger(__name__)


class LogEmbedder:
    """Embeds log chunks and stores them in ChromaDB.

    Usage:
        embedder = LogEmbedder(
            openai_api_key="sk-...",
            embedding_model="text-embedding-3-small",
            chroma_host="localhost",
            chroma_port=8000,
            collection_name="log_chunks",
        )
        chunk_ids = embedder.embed_and_store(chunks)
    """

    def __init__(
        self,
        openai_api_key: str,
        embedding_model: str = "text-embedding-3-small",
        chroma_host: Optional[str] = None,
        chroma_port: int = 8000,
        collection_name: str = "log_chunks",
        persist_directory: Optional[str] = None,
    ):
        """Initialize the embedder.

        Args:
            openai_api_key: OpenAI API key for embeddings
            embedding_model: Model name (default: text-embedding-3-small)
            chroma_host: ChromaDB server host (None = use persistent local)
            chroma_port: ChromaDB server port
            collection_name: Name of the ChromaDB collection
            persist_directory: Local directory for persistent ChromaDB (dev mode)
        """
        self._embedding_model = embedding_model
        self._collection_name = collection_name

        # Initialize embeddings via LangChain (support local HuggingFace for Groq)
        if (
            (openai_api_key and openai_api_key.startswith("gsk_"))
            or "groq" in settings.openai_api_base.lower()
            or "all-minilm" in embedding_model.lower()
        ):
            from langchain_community.embeddings import HuggingFaceEmbeddings
            self._embeddings = HuggingFaceEmbeddings(
                model_name=embedding_model,
            )
            logger.info("embedder_using_local_huggingface: model=%s", embedding_model)
        else:
            self._embeddings = OpenAIEmbeddings(
                model=embedding_model,
                openai_api_key=openai_api_key,
            )

        # Initialize ChromaDB client
        if chroma_host:
            # Docker/remote mode: connect to ChromaDB server
            self._chroma_client = chromadb.HttpClient(
                host=chroma_host,
                port=chroma_port,
            )
            logger.info(
                "chromadb_connected: host=%s port=%d",
                chroma_host,
                chroma_port,
            )
        elif persist_directory:
            # Local persistent mode: store on disk
            self._chroma_client = chromadb.PersistentClient(
                path=persist_directory,
            )
            logger.info(
                "chromadb_persistent: dir=%s",
                persist_directory,
            )
        else:
            # In-memory mode: for testing only
            self._chroma_client = chromadb.EphemeralClient()
            logger.info("chromadb_ephemeral: in-memory mode (testing only)")

        # Initialize LangChain Chroma vector store
        self._vector_store = Chroma(
            client=self._chroma_client,
            collection_name=collection_name,
            embedding_function=self._embeddings,
        )

        logger.info(
            "embedder_initialized: model=%s collection=%s",
            embedding_model,
            collection_name,
        )

    @property
    def vector_store(self) -> Chroma:
        """Expose the LangChain Chroma vector store for retrieval."""
        return self._vector_store

    @property
    def chroma_client(self) -> chromadb.ClientAPI:
        """Expose the raw ChromaDB client for direct queries."""
        return self._chroma_client

    def embed_and_store(self, chunks: list[LogChunk]) -> list[str]:
        """Embed log chunks and store them in ChromaDB.

        Each chunk gets:
          - A unique ID (UUID)
          - The chunk text as the document (what gets embedded)
          - Metadata: start_time, end_time, log_source, chunk_index, entry_count

        Args:
            chunks: List of LogChunk objects from the chunker

        Returns:
            List of chunk IDs that were stored

        Raises:
            No exceptions — logs errors and continues.
            Returns partial results if some chunks fail.
        """
        if not chunks:
            logger.info("embed_and_store: no chunks to embed")
            return []

        # Prepare documents, metadata, and IDs
        texts: list[str] = []
        metadatas: list[dict] = []
        ids: list[str] = []

        for chunk in chunks:
            chunk_id = str(uuid.uuid4())
            texts.append(chunk.text)
            metadatas.append(chunk.to_metadata())
            ids.append(chunk_id)

        # Embed and store via LangChain Chroma
        try:
            self._vector_store.add_texts(
                texts=texts,
                metadatas=metadatas,
                ids=ids,
            )
            logger.info(
                "embed_and_store_complete: chunks=%d collection=%s",
                len(chunks),
                self._collection_name,
            )
        except Exception as e:
            logger.error(
                "embed_and_store_failed: error=%s",
                str(e),
            )
            raise

        return ids

    def similarity_search(
        self,
        query: str,
        k: int = 5,
        filter_dict: Optional[dict] = None,
    ) -> list[dict]:
        """Search for similar log chunks.

        Args:
            query: Natural language query (e.g., "failed SSH login attempts")
            k: Number of results to return
            filter_dict: ChromaDB metadata filter (e.g., {"log_source": "auth"})

        Returns:
            List of dicts with 'content', 'metadata', and 'score' keys
        """
        try:
            if filter_dict:
                results = self._vector_store.similarity_search_with_score(
                    query=query,
                    k=k,
                    filter=filter_dict,
                )
            else:
                results = self._vector_store.similarity_search_with_score(
                    query=query,
                    k=k,
                )

            formatted = []
            for doc, score in results:
                formatted.append({
                    "content": doc.page_content,
                    "metadata": doc.metadata,
                    "score": score,
                })

            logger.info(
                "similarity_search: query='%s' results=%d",
                query[:50],
                len(formatted),
            )
            return formatted

        except Exception as e:
            logger.error("similarity_search_failed: %s", str(e))
            return []

    def get_collection_stats(self) -> dict:
        """Get statistics about the current collection.

        Returns:
            Dict with collection name, document count, and metadata.
        """
        try:
            collection = self._chroma_client.get_collection(
                name=self._collection_name,
            )
            count = collection.count()
            return {
                "collection_name": self._collection_name,
                "document_count": count,
                "embedding_model": self._embedding_model,
            }
        except Exception as e:
            logger.error("get_collection_stats_failed: %s", str(e))
            return {
                "collection_name": self._collection_name,
                "document_count": -1,
                "error": str(e),
            }

    def delete_collection(self) -> bool:
        """Delete the entire collection. Use with caution.

        Returns:
            True if successful, False if failed.
        """
        try:
            self._chroma_client.delete_collection(name=self._collection_name)
            logger.info(
                "collection_deleted: %s", self._collection_name
            )
            # Reinitialize the vector store with a fresh collection
            self._vector_store = Chroma(
                client=self._chroma_client,
                collection_name=self._collection_name,
                embedding_function=self._embeddings,
            )
            return True
        except Exception as e:
            logger.error("delete_collection_failed: %s", str(e))
            return False

    def get_chunks_by_metadata(
        self,
        filter_dict: Optional[dict] = None,
        limit: int = 10,
    ) -> list[dict]:
        """Retrieve log chunks matching a specific metadata filter without similarity search.

        Args:
            filter_dict: ChromaDB metadata filter (e.g. {"log_source": "auth"}).
                         Pass None to retrieve chunks without filtering.
            limit: Maximum number of results to return

        Returns:
            List of dicts with 'content', 'metadata', and 'id' keys.
        """
        try:
            collection = self._chroma_client.get_collection(
                name=self._collection_name,
            )
            get_kwargs = {"limit": limit}
            if filter_dict:
                get_kwargs["where"] = filter_dict
            results = collection.get(**get_kwargs)
            formatted = []
            if results and "documents" in results and results["documents"]:
                for i in range(len(results["documents"])):
                    formatted.append({
                        "content": results["documents"][i],
                        "metadata": results["metadatas"][i] if results["metadatas"] else {},
                        "id": results["ids"][i],
                    })
            return formatted
        except Exception as e:
            logger.error("get_chunks_by_metadata_failed: %s", str(e))
            return []

    def get_chunks_containing_text(
        self,
        search_text: str,
        limit: int = 10,
    ) -> list[dict]:
        """Retrieve log chunks whose text contains the specified substring.

        This is extremely useful for IP or user address correlation where
        exact matches are required rather than semantic similarity.

        Args:
            search_text: Substring to search for inside chunk documents
            limit: Maximum number of results to return

        Returns:
            List of dicts with 'content', 'metadata', and 'id' keys.
        """
        try:
            collection = self._chroma_client.get_collection(
                name=self._collection_name,
            )
            results = collection.get(
                where_document={"$contains": search_text},
                limit=limit,
            )
            formatted = []
            if results and "documents" in results and results["documents"]:
                for i in range(len(results["documents"])):
                    formatted.append({
                        "content": results["documents"][i],
                        "metadata": results["metadatas"][i] if results["metadatas"] else {},
                        "id": results["ids"][i],
                    })
            return formatted
        except Exception as e:
            logger.error("get_chunks_containing_text_failed: %s", str(e))
            return []

