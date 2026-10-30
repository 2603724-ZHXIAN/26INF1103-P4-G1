"""IThreatScanner Interface (Abstract Base Class).

Defines the contract for external technical threat intelligence scanners
(e.g., VirusTotal, HybridAnalysis, etc.).
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional


class IThreatScanner(ABC):
    """Interface defining operations for technical file/URL reputation scanners."""

    @abstractmethod
    def scan_resource(
        self,
        resource_type: str,
        resource_identifier: str,
    ) -> Dict[str, Any]:
        """Scan or query reputation for a file or URL.

        Args:
            resource_type: Either 'file' or 'url'.
            resource_identifier: File path/hash or URL string.

        Returns:
            A dictionary containing parsed scan metrics, engine consensus,
            and report URLs, or an error dictionary.
        """
        raise NotImplementedError

    @abstractmethod
    def get_report_url(
        self,
        resource_type: str,
        resource_id: str,
    ) -> Optional[str]:
        """Return the public web URL for a completed scan report."""
        raise NotImplementedError

    @abstractmethod
    def is_available(self) -> bool:
        """Check if scanner configuration (e.g. API keys) is available."""
        raise NotImplementedError
