"""Offline tests for EngineCoordinator.

All tests run without live APIs.  Concrete managers are replaced by lightweight
doubles so the tests validate routing and state-machine logic only.
"""

import unittest
from unittest.mock import MagicMock, patch

from src.coordinator import EngineCoordinator
from src.interfaces.llm_client import BaseLLMClient
from src.managers.ai_manager import AIManager
from src.managers.data_manager import DataManager
from src.managers.io_manager import IOManager
from src.managers.logic_manager import LogicManager
from src.models.assessment import AssessmentResult
from src.models.submission import Submission
from src.services.virustotal_scanner import VirusTotalScanner


# ---------------------------------------------------------------------------
# Minimal fakes
# ---------------------------------------------------------------------------

class _MockLLMClient(BaseLLMClient):
    """Stub LLM client that returns a valid structured response."""

    def __init__(self):
        self._model_name = "mock-llm"
        self._provider_name = "mock"

    @property
    def model_name(self) -> str:
        return self._model_name

    @property
    def provider_name(self) -> str:
        return self._provider_name

    def generate_structured_analysis(self, prompt: str, schema: dict) -> dict:
        return _VALID_AI_RESPONSE


class _MockScanner(VirusTotalScanner):
    """Stub scanner that returns a benign VirusTotal-style result."""

    def __init__(self):
        super().__init__(api_key="mock_vt_key")

    def scan_resource(self, resource_type: str, resource_value: str) -> dict:
        return {
            "parsed_result": {
                "resource_type": resource_type,
                "detection_stats": {
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 70,
                    "undetected": 2,
                    "timeout": 0,
                    "total": 72,
                },
                "threat_names": [],
                "categories": [],
                "reputation": 0,
            }
        }

    def get_report_url(self, resource_value: str) -> str:
        return f"https://virustotal.com/gui/url/{resource_value}"

    def is_available(self) -> bool:
        return True


_VALID_AI_RESPONSE = {
    "message_classification": "legitimate",
    "primary_threat_type": "none",
    "analysis_confidence": "high",
    "language": "English",
    "message_type": "sms",
    "claimed_entity": "",
    "requested_actions": [],
    "possible_intents": [],
    "extracted_urls": [],
    "extracted_contacts": [],
    "suspected_threat_types": [],
    "indicators": {
        "urgency_pressure": {"present": False, "evidence": ""},
        "authority_impersonation": {"present": False, "evidence": ""},
        "credential_request": {"present": False, "evidence": ""},
        "personal_information_request": {"present": False, "evidence": ""},
        "payment_request": {"present": False, "evidence": ""},
        "otp_request": {"present": False, "evidence": ""},
        "suspicious_link": {"present": False, "evidence": ""},
        "download_request": {"present": False, "evidence": ""},
        "threatening_language": {"present": False, "evidence": ""},
        "reward_or_prize": {"present": False, "evidence": ""},
    },
    "other_warning_signs": [],
    "user_exposure": {
        "clicked_or_opened_link": False,
        "entered_credentials": False,
        "shared_personal_information": False,
        "downloaded_or_opened_file": False,
        "shared_otp": False,
        "made_payment": False,
        "shared_banking_details": False,
        "installed_software": False,
        "granted_remote_access": False,
        "description_summary": "",
    },
    "education": {
        "threat_explanations": [],
        "threat_summary": "No threat detected.",
        "what_it_is": "This appears to be a safe message.",
        "why_dangerous": [],
        "preventive_steps": [],
        "recovery_steps": ["No action needed."],
        "limitations": [],
    },
}


# ---------------------------------------------------------------------------
# Helper: build a coordinator with in-memory DB and mock services
# ---------------------------------------------------------------------------

def _make_coordinator() -> EngineCoordinator:
    """Return a fully wired coordinator backed by in-memory SQLite and mocks."""
    llm = _MockLLMClient()
    ai_manager = AIManager(llm_client=llm, fallback_client=None)
    data_manager = DataManager(db_path=":memory:")
    data_manager.initialize_database()
    logic_manager = LogicManager()

    # IOManager needs a data_manager; suppress terminal output in tests
    io_manager = IOManager(use_color=False, data_manager=data_manager)

    scanner = _MockScanner()

    return EngineCoordinator(
        io_manager=io_manager,
        ai_manager=ai_manager,
        logic_manager=logic_manager,
        data_manager=data_manager,
        scanner=scanner,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestEngineCoordinatorConstruction(unittest.TestCase):
    """Verify the coordinator is wired correctly at construction time."""

    def test_coordinator_stores_all_managers(self):
        coord = _make_coordinator()
        self.assertIsInstance(coord._io, IOManager)
        self.assertIsInstance(coord._ai, AIManager)
        self.assertIsInstance(coord._logic, LogicManager)
        self.assertIsInstance(coord._data, DataManager)
        self.assertIsInstance(coord._scanner, VirusTotalScanner)

    def test_coordinator_accepts_none_scanner(self):
        """Aggregation: scanner is optional at construction."""
        llm = _MockLLMClient()
        data_manager = DataManager(db_path=":memory:")
        data_manager.initialize_database()
        io_manager = IOManager(use_color=False, data_manager=data_manager)
        coord = EngineCoordinator(
            io_manager=io_manager,
            ai_manager=AIManager(llm_client=llm),
            logic_manager=LogicManager(),
            data_manager=data_manager,
            scanner=None,
        )
        self.assertIsNone(coord._scanner)


class TestTextPipeline(unittest.TestCase):
    """Verify that _handle_text_pipeline produces a completed Submission."""

    def setUp(self):
        self.coord = _make_coordinator()
        # Silence IOManager output
        self.coord._io._print = lambda *a, **kw: None
        self.coord._io.display_assessment = lambda *a, **kw: None

    def test_text_pipeline_creates_completed_submission(self):
        request = {
            "action": "analyze_submission",
            "input_type": "text",
            "input_value": "Hello, please verify your account.",
            "input_hash": "abc123",
            "interaction_type": "viewed_only",
            "interaction_description": None,
        }
        self.coord._handle_text_pipeline(request)

        # A submission must exist in the DB
        sub = self.coord._data.get_submission_by_id(1)
        self.assertIsNotNone(sub)
        self.assertEqual(sub.processing_status, "completed")

    def test_text_pipeline_persists_assessment(self):
        request = {
            "action": "analyze_submission",
            "input_type": "text",
            "input_value": "Win a free iPhone now! Click here.",
            "input_hash": "def456",
            "interaction_type": "clicked_link",
            "interaction_description": None,
        }
        self.coord._handle_text_pipeline(request)
        sub = self.coord._data.get_submission_by_id(1)
        self.assertIsNotNone(sub)
        self.assertIsNotNone(sub.assessment)

    def test_text_pipeline_marks_failed_on_ai_error(self):
        """If AI returns an error dict, submission must be marked failed."""
        self.coord._ai.analyze_message = MagicMock(
            return_value={"error": "API quota exceeded."}
        )
        request = {
            "action": "analyze_submission",
            "input_type": "text",
            "input_value": "Test message",
            "input_hash": "ghi789",
            "interaction_type": "viewed_only",
            "interaction_description": None,
        }
        self.coord._handle_text_pipeline(request)
        sub = self.coord._data.get_submission_by_id(1)
        self.assertIsNotNone(sub)
        self.assertEqual(sub.processing_status, "failed")

    def test_text_pipeline_extracts_evidence_for_active_indicators(self):
        """Active indicators in AI result → ThreatEvidence objects on submission."""
        ai_with_indicator = dict(_VALID_AI_RESPONSE)
        ai_with_indicator["indicators"] = dict(_VALID_AI_RESPONSE["indicators"])
        ai_with_indicator["indicators"]["payment_request"] = {
            "present": True,
            "evidence": "Transfer $500 immediately.",
        }
        self.coord._ai.analyze_message = MagicMock(return_value=ai_with_indicator)

        request = {
            "action": "analyze_submission",
            "input_type": "text",
            "input_value": "Please transfer $500 immediately.",
            "input_hash": "jkl000",
            "interaction_type": "viewed_only",
            "interaction_description": None,
        }
        self.coord._handle_text_pipeline(request)
        sub = self.coord._data.get_submission_by_id(1)
        self.assertIsNotNone(sub)
        self.assertGreater(len(sub.evidences), 0)
        names = [e.evidence_name for e in sub.evidences]
        self.assertIn("payment_request", names)


class TestResourcePipeline(unittest.TestCase):
    """Verify that _handle_resource_pipeline produces a completed Submission."""

    def setUp(self):
        self.coord = _make_coordinator()
        self.coord._io._print = lambda *a, **kw: None
        self.coord._io.display_assessment = lambda *a, **kw: None

    def test_url_pipeline_creates_completed_submission(self):
        request = {
            "action": "analyze_submission",
            "input_type": "url",
            "input_value": "http://example.com",
            "input_hash": "url001",
            "interaction_type": "viewed_only",
            "interaction_description": None,
            "file_path": None,
        }
        self.coord._handle_resource_pipeline(request)
        sub = self.coord._data.get_submission_by_id(1)
        self.assertIsNotNone(sub)
        self.assertEqual(sub.processing_status, "completed")

    def test_file_pipeline_creates_completed_submission(self):
        request = {
            "action": "analyze_submission",
            "input_type": "file",
            "input_value": "malware.exe",
            "input_hash": "file001",
            "interaction_type": "opened_or_downloaded_file",
            "interaction_description": None,
            "file_path": "/tmp/malware.exe",
        }
        self.coord._handle_resource_pipeline(request)
        sub = self.coord._data.get_submission_by_id(1)
        self.assertIsNotNone(sub)
        self.assertEqual(sub.processing_status, "completed")

    def test_resource_pipeline_marks_failed_on_scanner_error(self):
        self.coord._scanner.scan_resource = MagicMock(
            return_value={"error": "VirusTotal quota exceeded."}
        )
        request = {
            "action": "analyze_submission",
            "input_type": "url",
            "input_value": "http://evil.com",
            "input_hash": "url002",
            "interaction_type": "clicked_link",
            "interaction_description": None,
            "file_path": None,
        }
        self.coord._handle_resource_pipeline(request)
        sub = self.coord._data.get_submission_by_id(1)
        self.assertEqual(sub.processing_status, "failed")

    def test_resource_pipeline_marks_failed_when_no_scanner(self):
        """No scanner configured → submission marked failed, not crashed."""
        self.coord._scanner = None
        request = {
            "action": "analyze_submission",
            "input_type": "url",
            "input_value": "http://test.com",
            "input_hash": "url003",
            "interaction_type": "viewed_only",
            "interaction_description": None,
            "file_path": None,
        }
        self.coord._handle_resource_pipeline(request)
        sub = self.coord._data.get_submission_by_id(1)
        self.assertEqual(sub.processing_status, "failed")


class TestThreatRadarPipeline(unittest.TestCase):
    """Verify _handle_threat_radar delegates to AI and IO correctly."""

    def setUp(self):
        self.coord = _make_coordinator()
        self.coord._io._print = lambda *a, **kw: None
        self.coord._io.display_threat_radar = MagicMock()

    def test_threat_radar_calls_ai_manager(self):
        self.coord._ai.fetch_emerging_radar = MagicMock(
            return_value={
                "content": "Emerging phishing campaigns targeting Singapore banks.",
                "sources": [{"title": "CISA", "url": "https://cisa.gov"}],
                "search_queries": ["phishing 2025"],
                "model_name": "mock-llm",
            }
        )
        with patch.object(self.coord._io, "display_threat_radar", MagicMock()) as mock_display:
            self.coord._handle_threat_radar({"action": "emerging_threat_radar", "topic": "phishing"})
            self.coord._ai.fetch_emerging_radar.assert_called_once_with(topic="phishing")

    def test_threat_radar_with_none_topic(self):
        self.coord._ai.fetch_emerging_radar = MagicMock(
            return_value={
                "content": "Top threats: ransomware, phishing.",
                "sources": [],
                "search_queries": [],
                "model_name": "mock-llm",
            }
        )
        # Should not raise even with topic=None
        self.coord._handle_threat_radar({"action": "emerging_threat_radar", "topic": None})
        self.coord._ai.fetch_emerging_radar.assert_called_once_with(topic=None)

    def test_threat_radar_handles_ai_error_gracefully(self):
        self.coord._ai.fetch_emerging_radar = MagicMock(
            return_value={"error": "Grounding API limit reached."}
        )
        # Must not raise; coordinator should print an error message
        printed = []
        self.coord._io._print = lambda msg="": printed.append(msg)
        self.coord._handle_threat_radar({"action": "emerging_threat_radar", "topic": None})
        self.assertTrue(any("Could not fetch" in str(m) for m in printed))


class TestRunLoopDispatch(unittest.TestCase):
    """Verify run() dispatches actions correctly and exits cleanly."""

    def setUp(self):
        self.coord = _make_coordinator()
        self.coord._io._print = lambda *a, **kw: None

    def test_run_exits_on_exit_action(self):
        """Single 'exit' request → run() returns normally."""
        self.coord._io.collect_user_request = MagicMock(
            return_value={"action": "exit"}
        )
        self.coord.run()  # Must return without exception

    def test_run_calls_text_pipeline_for_text_submission(self):
        requests = [
            {
                "action": "analyze_submission",
                "input_type": "text",
                "input_value": "Hello world",
                "input_hash": "h1",
                "interaction_type": "viewed_only",
                "interaction_description": None,
            },
            {"action": "exit"},
        ]
        self.coord._io.collect_user_request = MagicMock(side_effect=requests)
        self.coord._io.display_assessment = MagicMock()
        self.coord.run()
        self.coord._io.display_assessment.assert_called_once()

    def test_run_calls_resource_pipeline_for_url_submission(self):
        requests = [
            {
                "action": "analyze_submission",
                "input_type": "url",
                "input_value": "http://example.com",
                "input_hash": "h2",
                "interaction_type": "viewed_only",
                "interaction_description": None,
                "file_path": None,
            },
            {"action": "exit"},
        ]
        self.coord._io.collect_user_request = MagicMock(side_effect=requests)
        self.coord._io.display_assessment = MagicMock()
        self.coord.run()
        self.coord._io.display_assessment.assert_called_once()

    def test_run_handles_keyboard_interrupt_gracefully(self):
        """KeyboardInterrupt mid-menu → run() exits without re-raising."""
        self.coord._io.collect_user_request = MagicMock(side_effect=KeyboardInterrupt)
        self.coord.run()  # Must not propagate KeyboardInterrupt

    def test_run_ignores_view_trending_action(self):
        """view_trending_threats is handled by IOManager itself; coordinator just loops."""
        requests = [
            {"action": "view_trending_threats"},
            {"action": "exit"},
        ]
        self.coord._io.collect_user_request = MagicMock(side_effect=requests)
        self.coord.run()  # Must not raise

    def test_run_ignores_history_query_action(self):
        """history_query is handled by IOManager itself; coordinator just loops."""
        requests = [
            {"action": "history_query", "status": "completed", "records_found": 0},
            {"action": "exit"},
        ]
        self.coord._io.collect_user_request = MagicMock(side_effect=requests)
        self.coord.run()  # Must not raise


class TestHelperMethods(unittest.TestCase):
    """Unit-test private helper methods in isolation."""

    def setUp(self):
        self.coord = _make_coordinator()
        self.coord._io._print = lambda *a, **kw: None

    def test_get_model_name_returns_string(self):
        name = self.coord._get_model_name()
        self.assertIsInstance(name, str)
        self.assertEqual(name, "mock-llm")

    def test_get_model_name_falls_back_to_unknown(self):
        self.coord._ai._llm_client = None  # Break the client reference
        name = self.coord._get_model_name()
        self.assertEqual(name, "unknown")

    def test_safe_update_submission_does_not_raise_on_bad_id(self):
        sub = Submission(
            input_type="text",
            input_value="test",
            interaction_type="viewed_only",
        )
        sub._submission_id = 99999  # Non-existent ID
        # Must not raise; should log warning silently
        self.coord._safe_update_submission(sub)


if __name__ == "__main__":
    unittest.main()
