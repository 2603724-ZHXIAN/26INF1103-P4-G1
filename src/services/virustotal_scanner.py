"""VirusTotalScanner service implementation.

Concrete class implementing the IThreatScanner interface.
Provides local file hashing (privacy-first), URL analysis polling,
and multi-engine telemetry parsing via the VirusTotal v3 REST API.
"""

import base64
import hashlib
import logging
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests

from ..interfaces.threat_scanner import IThreatScanner

LOGGER = logging.getLogger(__name__)


class VirusTotalScanner(IThreatScanner):
    """VirusTotal v3 threat intelligence scanner implementing IThreatScanner."""

    VT_BASE_URL = "https://www.virustotal.com/api/v3"
    SUPPORTED_HASH_LENGTHS = {32, 40, 64}
    HASH_PATTERN = re.compile(r"^[a-fA-F0-9]+$")

    def __init__(
        self,
        api_key: str,
        base_url: str = VT_BASE_URL,
        timeout: int = 30,
        poll_interval: int = 5,
        max_poll_attempts: int = 12,
    ) -> None:
        self._api_key: str = str(api_key or "").strip()
        self._base_url: str = base_url.rstrip("/")
        self._timeout: int = max(5, int(timeout))
        self._poll_interval: int = max(1, int(poll_interval))
        self._max_poll_attempts: int = max(1, int(max_poll_attempts))

    # -------------------------------------------------------------------------
    # IThreatScanner Interface Implementation
    # -------------------------------------------------------------------------

    def is_available(self) -> bool:
        """Return True if an API key is configured."""
        return bool(self._api_key)

    def get_report_url(
        self, resource_type: str, resource_id: str
    ) -> Optional[str]:
        """Construct the web report URL on VirusTotal GUI."""
        if not resource_id:
            return None
        clean_type = resource_type.lower()
        if clean_type == "file":
            return f"https://www.virustotal.com/gui/file/{resource_id}"
        if clean_type == "url":
            return f"https://www.virustotal.com/gui/url/{resource_id}"
        return None

    def scan_resource(
        self, resource_type: str, resource_identifier: str
    ) -> Dict[str, Any]:
        """Scan or lookup file or URL reputation on VirusTotal."""
        if not self.is_available():
            return {
                "error": "VirusTotal API key is not configured.",
                "error_type": "configuration_error",
            }

        clean_type = str(resource_type).strip().lower()
        if clean_type == "file":
            return self._scan_file(resource_identifier)
        if clean_type == "url":
            return self._scan_url(resource_identifier)

        return {
            "error": f"Unsupported resource_type '{resource_type}'. Allowed: 'file', 'url'.",
            "error_type": "validation_error",
        }

    # -------------------------------------------------------------------------
    # File Hashing & Privacy Helpers
    # -------------------------------------------------------------------------

    @classmethod
    def is_supported_hash(cls, value: str) -> bool:
        """Return True if string looks like an MD5, SHA-1 or SHA-256 hash."""
        if not isinstance(value, str):
            return False
        candidate = value.strip()
        return (
            len(candidate) in cls.SUPPORTED_HASH_LENGTHS
            and cls.HASH_PATTERN.fullmatch(candidate) is not None
        )

    @classmethod
    def calculate_sha256(cls, file_path: str) -> str:
        """Calculate the SHA-256 digest of a local file (Privacy-First)."""
        path = Path(file_path).expanduser()
        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")
        if not path.is_file():
            raise ValueError(f"Path is not a regular file: {path}")

        hasher = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                hasher.update(chunk)
        return hasher.hexdigest()

    # -------------------------------------------------------------------------
    # Internal Scan Operations
    # -------------------------------------------------------------------------

    def _build_headers(self) -> Dict[str, str]:
        return {
            "accept": "application/json",
            "x-apikey": self._api_key,
        }

    def _request_endpoint(self, endpoint: str) -> Dict[str, Any]:
        """Make an authenticated GET request with comprehensive error mapping."""
        try:
            res = requests.get(
                endpoint,
                headers=self._build_headers(),
                timeout=self._timeout,
            )
        except requests.exceptions.Timeout:
            return {"error": "VirusTotal request timed out.", "error_type": "timeout"}
        except requests.exceptions.RequestException as exc:
            return {"error": f"VirusTotal connection failed: {exc}", "error_type": "connection_error"}

        try:
            data = res.json()
        except requests.exceptions.JSONDecodeError:
            data = None

        if res.status_code == 200:
            if isinstance(data, dict):
                return {"response_data": data}
            return {"error": "Invalid JSON response from VirusTotal.", "error_type": "invalid_response"}

        return {
            "error": f"VirusTotal returned HTTP {res.status_code}.",
            "error_type": "http_error",
            "status_code": res.status_code,
            "details": data or res.text[:1000],
        }

    def _scan_file(self, file_input: str) -> Dict[str, Any]:
        """Perform privacy-preserving file hash lookup."""
        cleaned = file_input.strip().strip('"').strip("'")
        path = Path(cleaned).expanduser()

        if path.is_file():
            try:
                file_hash = self.calculate_sha256(str(path))
            except Exception as err:
                return {"error": f"Failed to hash local file: {err}", "error_type": "file_error"}
        elif self.is_supported_hash(cleaned):
            file_hash = cleaned.lower()
        else:
            return {
                "error": "Provide an existing file path or valid MD5/SHA-1/SHA-256 hash.",
                "error_type": "validation_error",
            }

        endpoint = f"{self._base_url}/files/{file_hash}"
        res = self._request_endpoint(endpoint)

        if "error" in res:
            return res

        raw = res["response_data"]
        parsed = self._parse_vt_response(raw, "file")
        report_url = self.get_report_url("file", file_hash)

        return {
            "resource_type": "file",
            "resource_identifier": file_input,
            "report_url": report_url,
            "parsed_result": parsed,
            "raw_response": raw,
        }

    def _scan_url(self, url_input: str) -> Dict[str, Any]:
        """Query existing URL report or submit for fresh analysis."""
        clean_url = url_input.strip()
        url_id = base64.urlsafe_b64encode(clean_url.encode()).decode().strip("=")
        endpoint = f"{self._base_url}/urls/{url_id}"

        res = self._request_endpoint(endpoint)
        if "error" not in res:
            raw = res["response_data"]
            parsed = self._parse_vt_response(raw, "url")
            report_url = self.get_report_url("url", url_id)
            return {
                "resource_type": "url",
                "resource_identifier": clean_url,
                "report_url": report_url,
                "parsed_result": parsed,
                "raw_response": raw,
            }

        # Submit URL if not previously observed
        submit_endpoint = f"{self._base_url}/urls"
        try:
            submit_res = requests.post(
                submit_endpoint,
                headers=self._build_headers(),
                data={"url": clean_url},
                timeout=self._timeout,
            )
            submit_data = submit_res.json()
            analysis_id = submit_data.get("data", {}).get("id")
            if not analysis_id:
                return {"error": "Failed to receive URL analysis ID from VirusTotal."}
        except Exception as exc:
            return {"error": f"Failed to submit URL to VirusTotal: {exc}"}

        # Poll analysis
        poll_endpoint = f"{self._base_url}/analyses/{analysis_id}"
        for _ in range(self._max_poll_attempts):
            time.sleep(self._poll_interval)
            p_res = self._request_endpoint(poll_endpoint)
            if "response_data" in p_res:
                status = p_res["response_data"].get("data", {}).get("attributes", {}).get("status")
                if status == "completed":
                    final_res = self._request_endpoint(endpoint)
                    if "response_data" in final_res:
                        raw = final_res["response_data"]
                        parsed = self._parse_vt_response(raw, "url")
                        return {
                            "resource_type": "url",
                            "resource_identifier": clean_url,
                            "report_url": self.get_report_url("url", url_id),
                            "parsed_result": parsed,
                            "raw_response": raw,
                        }

        return {"error": "VirusTotal URL analysis did not complete in time."}

    # -------------------------------------------------------------------------
    # Response Parsing
    # -------------------------------------------------------------------------

    def _parse_vt_response(self, raw_json: Dict[str, Any], resource_type: str) -> Dict[str, Any]:
        """Normalize raw VirusTotal v3 JSON into clean metrics."""
        data = raw_json.get("data", {})
        attributes = data.get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        malicious = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)
        harmless = int(stats.get("harmless", 0) or 0)
        undetected = int(stats.get("undetected", 0) or 0)
        total = malicious + suspicious + harmless + undetected

        ratio = round(((malicious + suspicious) / total * 100), 2) if total > 0 else 0.0

        malicious_engines, suspicious_engines = self._extract_engines(attributes)

        return {
            "resource_type": resource_type,
            "resource_id": data.get("id", ""),
            "title": attributes.get("meaningful_name") or attributes.get("title") or "Unknown",
            "url": attributes.get("url", ""),
            "sha256": attributes.get("sha256", ""),
            "reputation": int(attributes.get("reputation", 0) or 0),
            "threat_names": attributes.get("threat_names", []),
            "categories": [c for c in (attributes.get("categories") or {}).values() if c],
            "detection_stats": {
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "undetected": undetected,
                "total": total,
                "detection_ratio": ratio,
            },
            "malicious_engines": malicious_engines,
            "suspicious_engines": suspicious_engines,
        }

    def _extract_engines(
        self, attributes: Dict[str, Any]
    ) -> Tuple[List[Dict[str, str]], List[Dict[str, str]]]:
        malicious = []
        suspicious = []
        results = attributes.get("last_analysis_results", {})
        for engine, res in results.items():
            category = res.get("category")
            entry = {
                "engine": res.get("engine_name", engine),
                "category": category,
                "result": res.get("result", ""),
            }
            if category == "malicious":
                malicious.append(entry)
            elif category == "suspicious":
                suspicious.append(entry)
        return malicious, suspicious
