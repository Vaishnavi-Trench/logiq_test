"""Elasticsearch Manager for handling vector search and document operations.

This module provides a singleton class for managing Elasticsearch operations,
including vector similarity search, document storage, and document management.
"""

from typing import List, Dict, Any, Optional
from elasticsearch import Elasticsearch
from ..propx import PropX
from ..logger2 import Logger2 as Logger


class ElasticsearchManager:
    """Singleton class for managing Elasticsearch operations.

    This class provides methods for:
    - Vector similarity search (kNN)
    - Document storage and retrieval
    - Document updates and deletions
    """

    __instance: Optional["ElasticsearchManager"] = None

    def __init__(self) -> None:
        """Initialize the ElasticsearchManager singleton.

        Raises:
            RuntimeError: If an instance already exists.
        """
        if ElasticsearchManager.__instance is not None:
            raise RuntimeError("This class is a singleton!")
        self.es_client: Optional[Elasticsearch] = None

    @staticmethod
    def get_instance() -> "ElasticsearchManager":
        """Get the singleton instance of ElasticsearchManager.

        Returns:
            ElasticsearchManager: The singleton instance.
        """
        if ElasticsearchManager.__instance is None:
            ElasticsearchManager.__instance = ElasticsearchManager()
        return ElasticsearchManager.__instance

    def set_es_client(self, es_client: Elasticsearch) -> None:
        """Set the Elasticsearch client.

        Args:
            es_client: The Elasticsearch client instance.
        """
        self.es_client = es_client

    def get_es_client(self) -> Optional[Elasticsearch]:
        """Get the Elasticsearch client.

        Returns:
            Optional[Elasticsearch]: The Elasticsearch client instance.
        """
        return self.es_client

    @staticmethod
    def initialize() -> None:
        """Initialize the Elasticsearch client with configuration from properties.

        Reads configuration from PropX and initializes the Elasticsearch client
        with basic authentication.
        """
        host = PropX.get_property("elastic.host")
        username = PropX.get_property("elastic.username")
        password = PropX.get_property("elastic.password")

        if not all([host, username, password]):
            Logger.error("Missing required Elasticsearch configuration properties.")
            return

        Logger.info("Initializing Elasticsearch client")
        es_client = Elasticsearch(host, basic_auth=(username, password))
        ElasticsearchManager.get_instance().set_es_client(es_client)
        Logger.info("Elasticsearch client initialized")

    @staticmethod
    def get_single_best_match(
        index_name: str, intcid: str, embedding: List[float]
    ) -> Optional[List[Dict[str, Any]]]:
        """Retrieve the best matching document using kNN search.

        Args:
            index_name: Name of the Elasticsearch index.
            embedding: Vector embedding to search for.
            intcid: Customer ID to filter results.

        Returns:
            Optional[List[Dict[str, Any]]]: List of matching documents or None if error occurs.
        """
        es = ElasticsearchManager.get_instance().get_es_client()
        if not es:
            Logger.error("Elasticsearch client not initialized")
            return None

        knn_query = {
            "size": 1,
            "knn": {
                "field": "embedding",
                "query_vector": embedding,
                "k": 1,
                "num_candidates": 100,
            },
            "query": {"term": {"intcid": intcid}},
        }

        try:
            response = es.search(index=index_name, body=knn_query)
            hits = response.get("hits", {}).get("hits", [])
            best_match = hits[0]["_source"]
            return best_match
        except Exception as e:
            Logger.error(f"Error in kNN search for {intcid}: {e}")
            return None

    @staticmethod
    def get_multiple_best_match(
        index_name: str,
        intcid: str,
        embedding: List[float],
        threshold: float = 0.8,
        max_results: int = 10,
    ) -> List[Dict[str, Any]]:
        """Retrieve multiple relevant documents using kNN search.

        Args:
            index_name: Name of the Elasticsearch index.
            intcid: Customer ID to filter results.
            embedding: Vector embedding to search for.
            threshold: Minimum similarity score threshold.
            max_results: Maximum number of results to return.

        Returns:
            List[Dict[str, Any]]: List of relevant documents.
        """
        es = ElasticsearchManager.get_instance().get_es_client()
        if not es:
            Logger.error("Elasticsearch client not initialized")
            return []

        knn_query = {
            "size": max_results,
            "knn": {
                "field": "embedding",
                "query_vector": embedding,
                "k": max_results,
                "num_candidates": 100,
            },
            "query": {"term": {"intcid": intcid}},
        }

        try:
            response = es.search(index=index_name, body=knn_query)
            hits = response.get("hits", {}).get("hits", [])

            if not hits:
                Logger.info(f"No relevant documents found for {intcid}.")
                return []

            relevant_results = [
                hit["_source"] for hit in hits if hit["_score"] >= threshold
            ]

            Logger.info(
                f"Found {len(relevant_results)} relevant documents for {intcid}."
            )
            return relevant_results

        except Exception as e:
            Logger.error(f"Error in kNN search for {intcid}: {e}")
            return []

    @staticmethod
    def store_document(
        index_name: str, intcid: str, doc: Dict[str, Any]
    ) -> Optional[str]:

        es = ElasticsearchManager.get_instance().get_es_client()
        if not es:
            Logger.error("Elasticsearch client not initialized")
            return None

        try:
            es.index(index=index_name, body=doc)
            Logger.info(f"Stored document {doc} for customer {intcid}")
            return True

        except Exception as e:
            Logger.error(f"Error storing document {doc} for {intcid}: {e}")
            return None

    @staticmethod
    def delete_document(
        index_name: str,
        intcid: str,
        filters: List[Dict[str, Any]],
        dp_id: Optional[str] = None,
        note_id: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Delete knowledge base documents based on query criteria.

        Args:
            index_name: Name of the Elasticsearch index.
            intcid: Customer ID.
            must_list: List of must conditions for the query.
            dp_id: Optional document ID to filter by.
            note_id: Optional note ID to filter by.

        Returns:
            Optional[Dict[str, Any]]: Response from Elasticsearch if successful, None otherwise.
        """
        es = ElasticsearchManager.get_instance().get_es_client()
        if not es:
            Logger.error("Elasticsearch client not initialized")
            return None

        try:
            query = {
                "query": {
                    "bool": {
                        "must": [
                            {"term": {key: value}} for key, value in filters.items()
                        ]
                    }
                }
            }

            response = es.delete_by_query(index=index_name, body=query)
            Logger.info(
                f"Deleted {response.get('deleted', 0)} document(s) for intcid: {intcid}"
            )
            return response

        except Exception as e:
            Logger.error(f"Error deleting document for intcid {intcid}, {e}")
            return None

    @staticmethod
    def update_document(
        index_name: str, filters: List[Dict[str, Any]], doc: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Update a knowledge base document by deleting and reinserting.

        Args:
            index_name: Name of the Elasticsearch index.
            must_list: List of must conditions for the query.
            doc: New document to insert.

        Returns:
            Optional[Dict[str, Any]]: Response containing delete and insert results if successful.
        """
        es = ElasticsearchManager.get_instance().get_es_client()
        if not es:
            Logger.error("Elasticsearch client not initialized")
            return None

        try:
            query = {
                "query": {
                    "bool": {
                        "must": [
                            {"term": {key: value}} for key, value in filters.items()
                        ]
                    }
                }
            }

            delete_response = es.delete_by_query(index=index_name, body=query)
            Logger.info(
                f"Deleted {delete_response.get('deleted', 0)} document(s) with dp_id: {doc['dp_id']}"
            )

            es.index(index=index_name, body=doc)
            Logger.info(f"Inserted Document: {doc}")

            return True

        except Exception as e:
            Logger.error(f"Error updating Document{doc}: {e}")
            return None

    @staticmethod
    def get_multiple_best_match(
        index_name: str,
        query_terms: List[Dict[str, Any]],
        embedding: List[float],
        threshold: float = 0.8,
        max_results: int = 10,
    ) -> List[Dict[str, Any]]:
        """Retrieve multiple relevant documents using kNN search.

        Args:
            index_name: Name of the Elasticsearch index.
            intcid: Customer ID to filter results.
            embedding: Vector embedding to search for.
            threshold: Minimum similarity score threshold.
            max_results: Maximum number of results to return.

        Returns:
            List[Dict[str, Any]]: List of relevant documents.
        """
        es = ElasticsearchManager.get_instance().get_es_client()
        if not es:
            Logger.error("Elasticsearch client not initialized")
            return []

        final_query_terms = [{"term": query_term} for query_term in query_terms]

        knn_query = {
            "size": max_results,
            "knn": {
                "field": "embeddings",
                "query_vector": embedding,
                "k": max_results,
                "num_candidates": 100,
                "filter": final_query_terms,
            },
        }

        try:
            response = es.search(index=index_name, body=knn_query)
            hits = response.get("hits", {}).get("hits", [])

            if not hits:
                Logger.info(f"No relevant documents found for {query_terms}.")
                return []

            for hit in hits:
                score = hit.get("_score", 0)
                if score < threshold:
                    Logger.debug(
                        f"Document {hit['_id']} below threshold ({score} < {threshold})"
                    )

            relevant_results = [
                hit["_source"] for hit in hits if hit["_score"] >= threshold
            ]

            Logger.info(
                f"Found {len(relevant_results)} relevant documents for {query_terms}."
            )
            return relevant_results

        except Exception as e:
            Logger.error(f"Error in kNN search for {query_terms}: {e}")
            return []