"""
LogSentinel AI — Dashboard API Client Utilities

Provides API connection logic, requests wrapping with headers, error handling,
and time utility helpers. Built in Phase 8.
"""

from typing import Any, Dict, Optional, List
import requests
import streamlit as st


class APIClient:
    """Client for connecting and sending authenticated requests to the FastAPI backend."""

    def __init__(self, base_url: str, api_key: Optional[str] = None):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key

    def _get_headers(self) -> Dict[str, str]:
        """Generate authentication headers using the API Key."""
        headers = {}
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        return headers

    def check_health(self) -> Dict[str, Any]:
        """Check the health status of backend subsystems (Postgres, ChromaDB, OpenAI)."""
        url = f"{self.base_url}/health"
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                return response.json()
            return {"status": "unhealthy", "error": f"HTTP {response.status_code}"}
        except requests.exceptions.RequestException as e:
            return {"status": "unhealthy", "error": str(e)}

    def upload_log(self, file_name: str, file_bytes: bytes, log_source: str) -> Dict[str, Any]:
        """Upload a log file for ingestion and parsing.

        Args:
            file_name: Name of the uploaded file.
            file_bytes: Binary contents of the log file.
            log_source: Format identifier ('apache', 'auth', 'syslog', or 'auto').
        """
        url = f"{self.base_url}/logs/upload"
        headers = self._get_headers()
        files = {"file": (file_name, file_bytes, "text/plain")}
        data = {"log_source": log_source}

        try:
            response = requests.post(url, headers=headers, files=files, data=data, timeout=120)
            if response.status_code == 200:
                return response.json()
            else:
                try:
                    detail = response.json().get("detail", "Unknown error")
                except Exception:
                    detail = response.text
                return {"status": "error", "error": f"HTTP {response.status_code}: {detail}"}
        except requests.exceptions.RequestException as e:
            return {"status": "error", "error": str(e)}

    def trigger_analysis(
        self,
        query: str,
        log_source: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        max_chunks: int = 5,
    ) -> Dict[str, Any]:
        """Trigger AI Agent analysis on a query and time range.

        Returns:
            JSON response representing the IncidentReport.
        """
        url = f"{self.base_url}/analyse"
        headers = self._get_headers()
        payload = {
            "query": query,
            "log_source": log_source if log_source != "auto" else None,
            "start_time": start_time or None,
            "end_time": end_time or None,
            "max_chunks": max_chunks,
        }

        try:
            response = requests.post(url, headers=headers, json=payload, timeout=180)
            if response.status_code == 200:
                return response.json()
            else:
                try:
                    detail = response.json().get("detail", "Unknown error")
                except Exception:
                    detail = response.text
                return {"status": "error", "error": f"HTTP {response.status_code}: {detail}"}
        except requests.exceptions.RequestException as e:
            return {"status": "error", "error": str(e)}

    def list_reports(self, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        """Retrieve a list of security incident reports."""
        url = f"{self.base_url}/reports"
        headers = self._get_headers()
        params = {"limit": limit, "offset": offset}

        try:
            response = requests.get(url, headers=headers, params=params, timeout=10)
            if response.status_code == 200:
                return response.json()
            return []
        except requests.exceptions.RequestException:
            return []

    def get_report(self, report_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a single incident report by UUID."""
        url = f"{self.base_url}/reports/{report_id}"
        headers = self._get_headers()

        try:
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                return response.json()
            return None
        except requests.exceptions.RequestException:
            return None

    def get_analyses(self, report_id: str) -> List[Dict[str, Any]]:
        """Retrieve the agent execution history linked to a report ID."""
        url = f"{self.base_url}/reports/{report_id}/analyses"
        headers = self._get_headers()

        try:
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                return response.json()
            return []
        except requests.exceptions.RequestException:
            return []
