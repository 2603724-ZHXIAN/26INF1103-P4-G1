"""Managers package providing UI presentation, business logic, AI orchestration, and data storage."""

from .ai_manager import AIManager
from .io_manager import IOManager

__all__ = ["AIManager", "IOManager"]
