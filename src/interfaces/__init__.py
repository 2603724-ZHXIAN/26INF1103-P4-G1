"""Abstract interfaces for external service adapters and AI clients."""

from .llm_client import BaseLLMClient
from .threat_scanner import IThreatScanner

__all__ = ["BaseLLMClient", "IThreatScanner"]
