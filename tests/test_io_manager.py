"""Unit tests for IOManager presentation layer.

Verifies:
- Purposeful class instantiation with encapsulation
- Protected styling attributes (_use_color, _banner_width, _theme_colors)
- Strict Separation of Concerns (no direct SQL, no threat score calculation)
- Menu formatting, URL syntax validation, and interaction collection
- Assessment and Radar formatting
- Table browsing and fallback navigation
"""

import hashlib
import io
import unittest
from unittest.mock import MagicMock, patch

from src.managers import IOManager
from src.models import AssessmentResult, Submission, ThreatEvidence


class TestIOManagerEncapsulation(unittest.TestCase):
    """Test encapsulation, properties, and validation in IOManager."""

    def setUp(self):
        self.io = IOManager(use_color=False, banner_width=80)

    def test_default_instantiation(self):
        io_default = IOManager()
        self.assertIsInstance(io_default.use_color, bool)
        self.assertEqual(io_default.banner_width, 72)
        self.assertIsInstance(io_default.theme_colors, dict)
        self.assertIsNotNone(io_default.data_manager)

    def test_custom_instantiation(self):
        self.assertFalse(self.io.use_color)
        self.assertEqual(self.io.banner_width, 80)

    def test_use_color_encapsulation_validation(self):
        self.io.use_color = True
        self.assertTrue(self.io.use_color)

        with self.assertRaises(TypeError):
            self.io.use_color = "yes"

        with self.assertRaises(TypeError):
            self.io.use_color = 1

    def test_banner_width_encapsulation_validation(self):
        self.io.banner_width = 90
        self.assertEqual(self.io.banner_width, 90)

        with self.assertRaises(ValueError):
            self.io.banner_width = 30

        with self.assertRaises(ValueError):
            self.io.banner_width = 250

        with self.assertRaises(TypeError):
            self.io.banner_width = "80"

        with self.assertRaises(TypeError):
            self.io.banner_width = True

    def test_theme_colors_encapsulation_validation(self):
        custom_theme = {"reset": "", "cyan": "", "red": ""}
        self.io.theme_colors = custom_theme
        self.assertEqual(self.io.theme_colors, custom_theme)

        with self.assertRaises(TypeError):
            self.io.theme_colors = ["not", "a", "dict"]

    def test_data_manager_encapsulation_validation(self):
        mock_dm = MagicMock()
        self.io.data_manager = mock_dm
        self.assertIs(self.io.data_manager, mock_dm)

        with self.assertRaises(ValueError):
            self.io.data_manager = None


class TestIOManagerValidationAndHelpers(unittest.TestCase):
    """Test URL validation, cryptographic hashing, and label formatting."""

    def setUp(self):
        self.io = IOManager(use_color=False)

    def test_validate_url_syntax(self):
        self.assertTrue(self.io.validate_url_syntax("https://secure-login.bank.com/auth"))
        self.assertTrue(self.io.validate_url_syntax("http://phishing-site.xyz"))
        self.assertTrue(self.io.validate_url_syntax("suspicious-domain.com"))
        self.assertFalse(self.io.validate_url_syntax("not a url at all"))
        self.assertFalse(self.io.validate_url_syntax(""))
        self.assertFalse(self.io.validate_url_syntax("   "))
        self.assertFalse(self.io.validate_url_syntax("https:// bad url with spaces.com"))

    def test_generate_hash(self):
        text = "suspicious SMS text message"
        expected = hashlib.sha256(text.encode("utf-8")).hexdigest()
        self.assertEqual(self.io.generate_hash(text), expected)

    def test_format_label(self):
        self.assertEqual(self.io.format_label("urgency_pressure"), "Urgency Pressure")
        self.assertEqual(self.io.format_label("spear_phishing"), "Spear Phishing")
        self.assertEqual(self.io.format_label(None, default="N/A"), "N/A")

    def test_render_menu(self):
        menu = self.io.render_menu()
        self.assertIn("1", menu)
        self.assertIn("2", menu)
        self.assertIn("3", menu)
        self.assertIn("4", menu)
        self.assertIn("5", menu)
        self.assertIn("6", menu)
        self.assertIn("7", menu)
        self.assertIn("CYBER THREAT & SCAM DETECTION ENGINE", menu)
        self.assertIn("Analyze Suspicious Text", menu)
        self.assertIn("Analyze Suspicious URL", menu)
        self.assertIn("Analyze File", menu)
        self.assertIn("Exit", menu)


class TestIOManagerPromptsAndRequests(unittest.TestCase):
    """Test prompt flows for input collection and interaction details."""

    def setUp(self):
        self.io = IOManager(use_color=False)

    @patch("builtins.input", side_effect=["1"])
    def test_collect_interaction_details_viewed_only(self, mock_input):
        itype, idesc = self.io.collect_interaction_details()
        self.assertEqual(itype, "viewed_only")
        self.assertIsNone(idesc)

    @patch("builtins.input", side_effect=["2"])
    def test_collect_interaction_details_clicked_link(self, mock_input):
        itype, idesc = self.io.collect_interaction_details()
        self.assertEqual(itype, "clicked_link")
        self.assertIsNone(idesc)

    @patch(
        "builtins.input",
        side_effect=["6", "Entered my credit card credentials and OTP"],
    )
    def test_collect_interaction_details_other_with_description(self, mock_input):
        itype, idesc = self.io.collect_interaction_details()
        self.assertEqual(itype, "other")
        self.assertEqual(idesc, "Entered my credit card credentials and OTP")

    @patch("builtins.input", side_effect=["8", "1"])
    def test_collect_interaction_details_invalid_choice_reprompt(self, mock_input):
        itype, idesc = self.io.collect_interaction_details()
        self.assertEqual(itype, "viewed_only")
        self.assertIsNone(idesc)

    @patch(
        "builtins.input",
        side_effect=["1", "Suspicious scam text message", "END", "1"],
    )
    def test_collect_user_request_text_option(self, mock_input):
        request = self.io.collect_user_request()
        self.assertEqual(request["action"], "analyze_submission")
        self.assertEqual(request["input_type"], "text")
        self.assertEqual(request["input_value"], "Suspicious scam text message")
        self.assertEqual(request["interaction_type"], "viewed_only")
        self.assertIsNotNone(request["input_hash"])

    @patch(
        "builtins.input",
        side_effect=["2", "https://paypal-verify-fake.com/login", "2"],
    )
    def test_collect_user_request_url_option(self, mock_input):
        request = self.io.collect_user_request()
        self.assertEqual(request["action"], "analyze_submission")
        self.assertEqual(request["input_type"], "url")
        self.assertEqual(request["input_value"], "https://paypal-verify-fake.com/login")
        self.assertEqual(request["interaction_type"], "clicked_link")

    @patch(
        "builtins.input",
        side_effect=["3", "C:/suspicious/invoice.pdf", "4"],
    )
    @patch("os.path.isfile", return_value=True)
    def test_collect_user_request_file_option(self, mock_isfile, mock_input):
        request = self.io.collect_user_request()
        self.assertEqual(request["action"], "analyze_submission")
        self.assertEqual(request["input_type"], "file")
        self.assertEqual(request["input_value"], "invoice.pdf")
        self.assertEqual(request["interaction_type"], "opened_or_downloaded_file")

    @patch("builtins.input", side_effect=["6", "Telegram Investment Scam"])
    def test_collect_user_request_radar_option(self, mock_input):
        request = self.io.collect_user_request()
        self.assertEqual(request["action"], "emerging_threat_radar")
        self.assertEqual(request["topic"], "Telegram Investment Scam")

    @patch("builtins.input", side_effect=["7", "y"])
    def test_collect_user_request_exit_option(self, mock_input):
        request = self.io.collect_user_request()
        self.assertEqual(request["action"], "exit")


class TestIOManagerSeparationOfConcerns(unittest.TestCase):
    """Test strict separation of concerns:
    - ❌ No direct SQL execution (delegates historical queries to DataManager)
    - ❌ No threat score calculation in IOManager
    """

    def setUp(self):
        self.mock_dm = MagicMock()
        self.io = IOManager(use_color=False, data_manager=self.mock_dm)

    @patch("builtins.input", side_effect=["4", "1", "invoice", "0"])
    def test_history_query_delegates_to_data_manager_search(self, mock_input):
        self.mock_dm.search_records.return_value = [
            {
                "submission_id": 1,
                "input_type": "text",
                "input_value": "fake invoice",
                "risk_category": "high",
            }
        ]
        request = self.io.collect_user_request()
        self.assertEqual(request["action"], "history_query")
        self.mock_dm.search_records.assert_called_once()

    @patch("builtins.input", side_effect=["4", "2", "3", "0"])
    def test_history_query_delegates_to_data_manager_risk_level(self, mock_input):
        self.mock_dm.get_records_by_risk_level.return_value = [
            {
                "submission_id": 2,
                "input_type": "url",
                "input_value": "phish.com",
                "risk_category": "high",
            }
        ]
        request = self.io.collect_user_request()
        self.assertEqual(request["action"], "history_query")
        self.mock_dm.get_records_by_risk_level.assert_called_once()

    @patch("builtins.input", side_effect=["5", "0"])
    def test_trending_threats_delegates_to_data_manager(self, mock_input):
        self.mock_dm.get_top_threat_types.return_value = [
            {"primary_threat_type": "Phishing", "total": 12}
        ]
        self.mock_dm.get_risk_category_counts.return_value = [
            {"risk_category": "high", "total": 12}
        ]
        request = self.io.collect_user_request()
        self.assertEqual(request["action"], "view_trending_threats")
        self.mock_dm.get_top_threat_types.assert_called_once()
        self.mock_dm.get_risk_category_counts.assert_called_once()


class TestIOManagerReporting(unittest.TestCase):
    """Test display_assessment and display_threat_radar formatting."""

    def setUp(self):
        self.io = IOManager(use_color=False)

    def test_display_assessment_with_submission(self):
        assessment = AssessmentResult(
            is_scam=True,
            overall_risk="high",
            decision="malicious",
            recommended_action="Disconnect device and change passwords.",
            risk_score=95,
            priority="urgent",
            risk_reasons=[
                "Requests immediate payment",
                "Uses spoofed authority header",
            ],
            recovery_steps=[
                "1. Disconnect network",
                "2. Notify security team",
            ],
            threat_summary="Spear phishing attempt targeting banking details.",
        )
        submission = Submission(
            input_type="text",
            input_value="Immediate payment required for invoice #1234",
            assessment=assessment,
        )

        with patch("sys.stdout", new=io.StringIO()) as fake_out:
            self.io.display_assessment(submission)
            output = fake_out.getvalue()

        self.assertIn("SECURITY ASSESSMENT REPORT: TEXT", output)
        self.assertIn("Threat Status   : MALICIOUS", output)
        self.assertIn("Risk Level      : HIGH", output)
        self.assertIn("Requests immediate payment", output)
        self.assertIn("1. Disconnect network", output)
        self.assertIn("2. Notify security team", output)

    def test_display_assessment_with_assessment_result_directly(self):
        assessment = AssessmentResult(
            is_scam=False,
            overall_risk="low",
            decision="safe",
            recommended_action="Verify standard senders.",
            risk_score=5,
            recovery_steps=["No recovery steps required."],
            threat_summary="Legitimate internal notification.",
        )

        with patch("sys.stdout", new=io.StringIO()) as fake_out:
            self.io.display_assessment(assessment)
            output = fake_out.getvalue()

        self.assertIn("NOT A SCAM", output)
        self.assertIn("LOW", output)
        self.assertIn("Legitimate internal notification.", output)

    def test_display_threat_radar(self):
        radar_data = {
            "model_name": "gemini-2.5-pro",
            "content": "Active smishing attacks masquerading as CPF refunds are surging in Southeast Asia.",
            "sources": [
                {
                    "title": "CSA Advisory on SMS Scams",
                    "url": "https://csa.gov.sg/advisories/sms",
                }
            ],
            "search_queries": ["CPF SMS scam 2026", "urgent smishing trends"],
        }

        with patch("sys.stdout", new=io.StringIO()) as fake_out:
            with patch("builtins.input", return_value=""):
                self.io.display_threat_radar(radar_data, topic="CPF Scams")
                output = fake_out.getvalue()

        self.assertIn("EMERGING THREAT & SCAM RADAR", output)
        self.assertIn("CPF Scams", output)
        self.assertIn("gemini-2.5-pro + Google Search Grounding", output)
        self.assertIn("Active smishing attacks masquerading as CPF refunds", output)
        self.assertIn("CSA Advisory on SMS Scams", output)
        self.assertIn("https://csa.gov.sg/advisories/sms", output)
        self.assertIn("CPF SMS scam 2026", output)

    def test_browse_historical_records_fallback(self):
        records = [
            {
                "submission_id": 1,
                "input_type": "text",
                "risk_category": "high",
                "input_value": "scam text",
            },
            {
                "submission_id": 2,
                "input_type": "url",
                "risk_category": "low",
                "input_value": "https://google.com",
            },
        ]

        with patch("builtins.input", return_value="1"):
            idx = self.io.browse_historical_records(records)
            self.assertEqual(idx, 0)

        with patch("builtins.input", return_value="0"):
            idx = self.io.browse_historical_records(records)
            self.assertIsNone(idx)

        self.assertIsNone(self.io.browse_historical_records([]))

    def test_browse_historical_table_aliases_records(self):
        records = [
            {
                "submission_id": 1,
                "input_type": "text",
                "risk_category": "high",
                "input_value": "scam text",
            }
        ]

        with patch.object(self.io, "browse_historical_records", return_value=0) as mock_browse:
            idx = self.io.browse_historical_table(records)
            self.assertEqual(idx, 0)
            mock_browse.assert_called_once_with(records)


if __name__ == "__main__":
    unittest.main()
