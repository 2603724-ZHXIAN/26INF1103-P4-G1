
import tempfile
import unittest
from pathlib import Path

from docx import Document

from src.batch.batch_report import BatchReport
from src.batch.word_report_writer import WordReportWriter


class TestWordReportWriter(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.output_path = str(
            Path(self.temp_dir.name) / "batch_report.docx"
        )

        self.batch_info = {
            "batch_reference": "BATCH-TEST-001",
            "saved_email_count": 3,
            "completed_count": 2,
            "analysis_failed_count": 1,
            "high_risk_count": 1,
            "medium_risk_count": 1,
            "low_risk_count": 0,
        }

        self.email_records = [
            {
                "submission_id": 101,
                "processing_status": "completed",
                "input_value": "Your bank account is suspended.",
                "primary_threat_type": "phishing",
                "overall_risk": "high",
                "risk_score": 95,
                "threat_summary": "Bank impersonation attempt.",
                "preventive_steps": ["Do not click suspicious links."],
                "recovery_steps": ["Change your password."],
            },
            {
                "submission_id": 102,
                "processing_status": "completed",
                "input_value": "Your bank account is suspended.",
                "primary_threat_type": "phishing",
                "overall_risk": "medium",
                "risk_score": 55,
            },
            {
                "submission_id": 103,
                "processing_status": "failed",
                "input_value": "Email analysis failed.",
                "error_message": "AI provider timeout",
            },
        ]

        self.report = BatchReport(
            self.batch_info,
            self.email_records
        )
        self.writer = WordReportWriter()

    def tearDown(self):
        self.temp_dir.cleanup()

    def _generate_document(self):
        self.writer.export(self.report, self.output_path)
        return Document(self.output_path)

    def _document_text(self, document):
        paragraphs = [p.text for p in document.paragraphs]

        for table in document.tables:
            for row in table.rows:
                paragraphs.extend(cell.text for cell in row.cells)

        return "\n".join(paragraphs)

    def test_creates_word_document(self):
        result = self.writer.export(
            self.report, self.output_path
        )

        self.assertTrue(Path(self.output_path).exists())
        self.assertEqual(result, self.output_path)

    def test_batch_summary(self):
        document = self._generate_document()
        text = self._document_text(document)

        self.assertIn("BATCH-TEST-001", text)
        self.assertIn("Total Emails: 3", text)
        self.assertIn("Completed: 2", text)
        self.assertIn("Failed: 1", text)

    def test_risk_distribution(self):
        document = self._generate_document()
        text = self._document_text(document)

        self.assertIn("Risk Distribution", text)
        self.assertIn("50.00%", text)
        self.assertIn("High", text)
        self.assertIn("Medium", text)

    def test_common_threats(self):
        document = self._generate_document()
        text = self._document_text(document)

        self.assertIn("Top Threat Types", text)
        self.assertIn("Phishing", text)

    def test_ranked_results(self):
        document = self._generate_document()
        text = self._document_text(document)

        self.assertIn("Prioritised High-Risk Emails", text)
        self.assertIn("95", text)
        self.assertNotIn("55", text)

        ranked_table = document.tables[2]

        self.assertEqual(len(ranked_table.rows), 2)
        self.assertEqual(ranked_table.rows[1].cells[0].text, "101")
        self.assertEqual(ranked_table.rows[1].cells[1].text, "High")
        self.assertEqual(ranked_table.rows[1].cells[2].text, "95")

    def test_campaign_grouping(self):
        document = self._generate_document()
        text = self._document_text(document)

        self.assertIn("Potential Scam Campaigns", text)
        self.assertIn("Number of Emails: 2", text)
        self.assertIn("Submission IDs: 101, 102", text)

    def test_failed_email_details(self):
        document = self._generate_document()
        text = self._document_text(document)

        self.assertIn("Failed Email Analyses", text)
        self.assertIn("AI provider timeout", text)
        self.assertIn("103", text)

    def test_educational_guidance(self):
        document = self._generate_document()
        text = self._document_text(document)

        self.assertIn("AI Educational Guidance", text)
        self.assertIn("Bank impersonation attempt.", text)
        self.assertIn("Do not click suspicious links.", text)
        self.assertIn("Change your password.", text)

    def test_empty_batch(self):
        empty_report = BatchReport({}, [])
        self.writer.export(empty_report, self.output_path)

        document = Document(self.output_path)
        text = self._document_text(document)

        self.assertIn("No classified threats available.", text)
        self.assertIn("No high-risk emails identified.", text)
        self.assertIn("No campaign groups available.", text)
        self.assertIn("No failed email analyses.", text)
        self.assertIn("No educational guidance available.", text)


if __name__ == "__main__":
    unittest.main()
