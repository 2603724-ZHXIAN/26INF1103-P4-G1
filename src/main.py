"""Application entry point for the Cyber Threat & Scam Detection Engine.

Bootstraps all OOP components and hands control to EngineCoordinator.
Demonstrates:
- Dependency Injection: all concrete classes are wired here and injected
  into the coordinator, keeping every manager decoupled from each other.
- SRP: this module only constructs the object graph and starts the engine.
"""

import logging
import os
from pathlib import Path

from dotenv import load_dotenv

from src.coordinator import EngineCoordinator
from src.managers.ai_manager import AIManager
from src.managers.data_manager import DataManager
from src.managers.io_manager import IOManager
from src.managers.logic_manager import LogicManager
from src.services.gemini_client import GeminiClient
from src.services.groq_client import GroqClient
from src.services.virustotal_scanner import VirusTotalScanner

# ---------------------------------------------------------------------------
# Logging configuration
# ---------------------------------------------------------------------------
logging.basicConfig(
    filename="cyber_threat_engine.log",
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)


def main() -> None:
    """Construct the full object graph and launch the engine."""
    # Load credentials from root or local .env
    root_dir = Path(__file__).resolve().parent.parent
    env_file = root_dir / ".env"
    if env_file.exists():
        load_dotenv(env_file)
    else:
        load_dotenv(Path(__file__).resolve().parent / ".env")

    # --- Service layer (concrete LLM clients & scanner) ---------------------
    gemini_key = os.getenv("GEMINI_API_KEY", "").strip()
    groq_key = os.getenv("GROQ_API_KEY", "").strip()
    vt_key = os.getenv("VT_API_KEY", "").strip()

    gemini_client = (
        GeminiClient(
            api_key=gemini_key,
            model_name=os.getenv("GEMINI_MODEL", "gemini-2.5-flash"),
        )
        if gemini_key
        else None
    )

    groq_client = (
        GroqClient(
            api_key=groq_key,
            model_name=os.getenv("GROQ_MODEL", "openai/gpt-oss-120b"),
        )
        if groq_key
        else None
    )

    scanner = VirusTotalScanner(api_key=vt_key) if vt_key else None

    # --- Manager layer -------------------------------------------------------
    data_manager = DataManager(db_path="data/database.db")
    data_manager.initialize_database()

    ai_manager = AIManager(llm_client=gemini_client, fallback_client=groq_client)
    logic_manager = LogicManager()
    io_manager = IOManager(data_manager=data_manager)

    # --- Coordinator (Composition + Aggregation) ----------------------------
    coordinator = EngineCoordinator(
        io_manager=io_manager,
        ai_manager=ai_manager,
        logic_manager=logic_manager,
        data_manager=data_manager,
        scanner=scanner,          # Aggregation: scanner lifetime owned by main()
    )

    coordinator.run()


if __name__ == "__main__":
    main()
