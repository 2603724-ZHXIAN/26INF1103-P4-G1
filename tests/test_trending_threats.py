"""Trending threats must count text, URL and file analyses (bug B6).

Text verdicts are stored in text_analysis and URL/file verdicts in
technical_ai_analysis. Trending used to read only text_analysis, so scanned
URLs and files never appeared in "Top Trending Attacks / Scams".
"""

import tempfile
import unittest
from pathlib import Path

from src.managers.data_manager import DataManager
from src.models import Submission


class TrendingAcrossAllInputTypesTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.manager = DataManager(str(Path(self.temp.name) / "trend.db"))
        self.manager.initialize_database()

        self.text_ids = [self._text("Verify your bank login", "phishing") for _ in range(2)]
        self.url_malware = self._technical("url", "http://bad.example/payload", "malware")
        self.file_malware = self._technical("file", "invoice.exe", "malware")
        self.url_phishing = self._technical("url", "http://fake-bank.example", "phishing")

    def tearDown(self):
        self.manager.close()
        self.temp.cleanup()

    def _text(self, message, threat_type):
        submission_id = self.manager.save_submission(Submission("text", message))
        self.manager.save_text_analysis(
            submission_id,
            {"message_classification": "scam", "primary_threat_type": threat_type},
            "test-model",
        )
        return submission_id

    def _technical(self, input_type, value, threat_type):
        submission_id = self.manager.save_submission(Submission(input_type, value))
        self.manager.save_technical_analysis(
            submission_id,
            {"is_malicious": True, "scam_confidence": 90,
             "threat_type": threat_type, "reasoning": "test"},
            "test-model",
        )
        return submission_id

    def test_top_threats_count_text_url_and_file(self):
        top = self.manager.get_top_threat_types(limit=10)

        self.assertEqual(
            top,
            [
                {"primary_threat_type": "phishing", "total": 3},
                {"primary_threat_type": "malware", "total": 2},
            ],
        )

    def test_limit_still_applies(self):
        top = self.manager.get_top_threat_types(limit=1)

        self.assertEqual(top, [{"primary_threat_type": "phishing", "total": 3}])

    def test_incidents_include_url_and_file_submissions(self):
        incidents = self.manager.get_incidents_by_threat_type("malware")

        self.assertEqual(
            {row["submission_id"] for row in incidents},
            {self.url_malware, self.file_malware},
        )
        self.assertEqual({row["input_type"] for row in incidents}, {"url", "file"})

    def test_incidents_mix_text_and_url_for_shared_threat_type(self):
        incidents = self.manager.get_incidents_by_threat_type("phishing")

        self.assertEqual(
            {row["submission_id"] for row in incidents},
            set(self.text_ids) | {self.url_phishing},
        )

    def test_url_incident_opens_as_a_full_report(self):
        # Selecting a URL incident from the trending list opens its report.
        report = self.manager.get_submission_report(self.url_malware)

        self.assertIsNotNone(report)
        self.assertEqual(report["submission_id"], self.url_malware)


if __name__ == "__main__":
    unittest.main()
