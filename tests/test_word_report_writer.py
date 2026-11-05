
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

        # Verify the high-risk submission is displayed.
        self.assertIn("Submission #101", text)
        self.assertIn("Risk Level: High", text)
        self.assertIn("Risk Score: 95/100", text)

        # Verify additional information is displayed.
        self.assertIn("Threat Type: Phishing", text)
        self.assertIn("Bank impersonation attempt.", text)

        # Medium-risk submissions should not appear in
        # the detailed high-risk section.
        self.assertNotIn("Risk Score: 55/100", text)

    def test_campaign_grouping(self):
        document = self._generate_document()
        text = self._document_text(document)

        self.assertIn("Potential Scam Campaigns", text)
        self.assertIn("Number of Emails: 2", text)
        self.assertIn("Submission IDs: 101, 102", text)

    def test_campaign_section_excludes_single_emails(self):
        records = [
            {
                "submission_id": 201,
                "processing_status": "completed",
                "input_value": "Your bank account is suspended.",
                "primary_threat_type": "phishing",
            },
            {
                "submission_id": 202,
                "processing_status": "completed",
                "input_value": "Congratulations! You won a free holiday.",
                "primary_threat_type": "prize scam",
            },
        ]

        report = BatchReport({}, records)
        self.writer.export(report, self.output_path)

        document = Document(self.output_path)
        text = self._document_text(document)

        self.assertIn("Potential Scam Campaigns", text)
        self.assertIn("No campaign groups available.", text)
        self.assertNotIn("Campaign Group 1", text)

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

    def test_methodology_and_limitations(self):
        document = self._generate_document()
        text = self._document_text(document)

        self.assertIn("Methodology and Limitations", text)
        self.assertIn("Emails are analysed using AI", text)
        self.assertIn("Similar emails are grouped", text)
        self.assertIn("AI-generated classifications may be inaccurate.", text)
        self.assertIn(
            "Similar emails do not necessarily originate from the same attacker.",
            text
        )

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

    def test_large_batch_100_emails(self):
        """Verify that 100 emails are represented without excessive detail."""

        records = []

        # Create 25 high-risk emails.
        for i in range(25):
            records.append({
                "submission_id": 1001 + i,
                "processing_status": "completed",
                "input_value": f"Urgent bank verification request {i}",
                "overall_risk": "high",
                "risk_score": 100 - i,
                "primary_threat_type": "phishing",
            })

        # Create 69 medium/low-risk emails.
        for i in range(69):
            records.append({
                "submission_id": 1026 + i,
                "processing_status": "completed",
                "input_value": f"Email content {i}",
                "overall_risk": "medium" if i < 30 else "low",
                "risk_score": 60 - (i % 30),
                "primary_threat_type": "spam",
            })

        # Create 6 failed emails.
        for i in range(6):
            records.append({
                "submission_id": 1095 + i,
                "processing_status": "failed",
                "input_value": f"Failed email {i}",
                "error_message": "AI provider timeout",
            })

        batch_info = {
            "batch_reference": "BATCH-LARGE-001",
            "saved_email_count": 100,
            "completed_count": 94,
            "analysis_failed_count": 6,
            "high_risk_count": 25,
            "medium_risk_count": 30,
            "low_risk_count": 39,
        }

        report = BatchReport(batch_info, records)
        self.writer.export(report, self.output_path)

        self.writer.export(
            report,
            "reports/batch_100_email_preview.docx"
        )

        document = Document(self.output_path)
        text = self._document_text(document)

        # Check executive summary.
        self.assertIn("100 emails submitted", text)
        self.assertIn("94 successfully analysed", text)

        # Check top-10 limit.
        self.assertEqual(
            sum(
                1 for paragraph in document.paragraphs
                if paragraph.text.startswith("Submission #")
            ),
            10,
        )

        self.assertIn("Plus 15 more high-risk emails", text)

        # Find the all-email table by its header.
        matching_tables = [
            table for table in document.tables
            if table.rows
            and table.rows[0].cells[0].text == "Email ID"
            and table.rows[0].cells[1].text == "Risk Level"
        ]

        self.assertEqual(len(matching_tables), 1)

        all_email_table = matching_tables[0]

        # 100 emails + 1 header row.
        self.assertEqual(len(all_email_table.rows), 101)

        ids = [
            row.cells[0].text
            for row in all_email_table.rows[1:]
        ]

        self.assertEqual(len(set(ids)), 100)

        # Highest-risk email comes first.
        self.assertEqual(ids[0], "1001")

        # Failed emails are still included.
        failed_rows = [
            row for row in all_email_table.rows[1:]
            if row.cells[1].text == "Failed"
        ]

        self.assertEqual(len(failed_rows), 6)


if __name__ == "__main__":
    unittest.main()
