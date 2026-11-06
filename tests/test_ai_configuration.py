"""Behaviour when no AI provider key is configured (no live APIs, no network)."""

import io
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import MagicMock, patch

from src import main as app_main
from src.managers.ai_manager import AIManager
from src.managers.io_manager import IOManager
from src.services.groq_client import GroqClient

NO_KEYS = (None, "gemini-2.5-flash", None, "openai/gpt-oss-120b")
GROQ_ONLY = (None, "gemini-2.5-flash", "test-groq-key", "openai/gpt-oss-120b")


def _no_network(*args, **kwargs):
    raise AssertionError("A network request was made although no AI key is configured.")


@patch.object(AIManager, "_load_env_credentials", return_value=NO_KEYS)
class TestAIManagerWithoutProvider(unittest.TestCase):
    """AIManager must fail fast with a clear message and never call a provider."""

    def test_reports_not_configured(self, _env):
        manager = AIManager()
        self.assertFalse(manager.is_configured)
        self.assertIsNone(manager.llm_client)
        self.assertIsNone(manager.fallback_client)

    @patch("requests.post", side_effect=_no_network)
    def test_message_analysis_returns_clear_error_without_network(self, _post, _env):
        result = AIManager().analyze_message("Your account is locked, verify now.")
        self.assertEqual(result["error"], AIManager.NO_PROVIDER_MESSAGE)
        self.assertIn("GEMINI_API_KEY", result["error"])

    @patch("requests.post", side_effect=_no_network)
    def test_technical_analysis_returns_clear_error_without_network(self, _post, _env):
        vt_data = {"resource_type": "url", "detection_stats": {"malicious": 1}}
        result = AIManager().analyze_technical_threat(vt_data)
        self.assertEqual(result["error"], AIManager.NO_PROVIDER_MESSAGE)

    @patch("requests.post", side_effect=_no_network)
    def test_threat_radar_returns_clear_error_without_network(self, _post, _env):
        result = AIManager().fetch_emerging_radar("parcel scams")
        self.assertEqual(result["error"], AIManager.NO_PROVIDER_MESSAGE)


class TestAIManagerProviderSelection(unittest.TestCase):
    """Existing behaviour with keys is unchanged."""

    @patch.object(AIManager, "_load_env_credentials", return_value=GROQ_ONLY)
    def test_groq_key_only_becomes_primary(self, _env):
        manager = AIManager()
        self.assertTrue(manager.is_configured)
        self.assertIsInstance(manager.llm_client, GroqClient)

    @patch.object(AIManager, "_load_env_credentials", return_value=NO_KEYS)
    def test_injected_client_counts_as_configured(self, _env):
        manager = AIManager(llm_client=GroqClient(api_key="injected-key", model_name="m"))
        self.assertTrue(manager.is_configured)


class TestStartupWithoutAIKeys(unittest.TestCase):
    """main() warns about missing keys but still starts the menu."""

    def setUp(self):
        self._original_cwd = os.getcwd()
        self._temp = tempfile.TemporaryDirectory()
        self.addCleanup(self._temp.cleanup)
        os.chdir(self._temp.name)
        self.addCleanup(os.chdir, self._original_cwd)
        Path("data").mkdir()

    def test_warning_shown_and_app_still_starts(self):
        output = io.StringIO()
        keys_removed = {k: "" for k in ("GEMINI_API_KEY", "GROQ_API_KEY", "VT_API_KEY")}
        with patch.object(app_main, "load_dotenv"), \
                patch.dict(os.environ, keys_removed), \
                patch.object(AIManager, "_load_env_credentials", return_value=NO_KEYS), \
                patch.object(app_main, "EngineCoordinator") as coordinator_cls, \
                redirect_stdout(output):
            app_main.main()

        coordinator_cls.return_value.run.assert_called_once()
        self.assertIn("No AI provider is configured", output.getvalue())


class TestAIConfigurationMessage(unittest.TestCase):
    """IOManager owns the wording shown to the user."""

    def test_message_explains_the_fix_and_what_still_works(self):
        output = io.StringIO()
        with redirect_stdout(output):
            IOManager(use_color=False).display_ai_configuration_warning()
        text = output.getvalue()
        self.assertIn("No AI provider is configured", text)
        self.assertIn("GEMINI_API_KEY", text)
        self.assertIn("History, trending and previous batch records still work", text)


if __name__ == "__main__":
    unittest.main()
