
"""Real SQLite -> BatchReportService -> Word export integration test (offline)."""

import tempfile
import unittest
from pathlib import Path

from docx import Document

from src.batch.batch_report_service import BatchReportService
from src.batch.word_report_writer import WordReportWriter
from src.managers.data_manager import DataManager
from src.models.assessment import AssessmentResult
from src.models.submission import Submission


class TestBatchDatabaseIntegration(unittest.TestCase):

    def setUp(self):
        # Create a temporary folder and database.
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)

        self.db_path = Path(self.temp_dir.name) / "batch_test.db"

        self.data_manager = DataManager(str(self.db_path))
        self.data_manager.initialize_database()

        # Create a batch containing five accepted emails.
        self.batch_reference = self.data_manager.create_email_batch(
            total_files=5,
            accepted_count=5,
            duplicate_count=0,
            import_failed_count=0,
        )

        # Four emails with simulated AI assessment results.
        examples = [
            ("Urgent bank password verification", "high", "phishing", 95),
            ("Pay now to release your parcel", "high", "payment scam", 90),
            ("Unusual account login notification", "medium", "impersonation", 55),
            ("Your monthly newsletter is here", "low", "legitimate", 10),
        ]

        for message, risk, threat_type, score in examples:

            submission = Submission(
                input_type="text",
                input_value=message,
                data_origin="batch_email",
                dataset_batch=self.batch_reference,
            )

            assessment = AssessmentResult(
                is_scam=(risk == "high"),
                overall_risk=risk,
                decision="Review this message",
                recommended_action="Verify independently",
                risk_score=score,
                threat_summary=f"Detected {threat_type}",
            )

            submission.mark_completed(assessment)

            submission_id = self.data_manager.save_submission(submission)

            # Save simulated AI analysis into SQLite.
            self.data_manager.save_text_analysis(
                submission_id,
                {
                    "message_classification": (
                        "scam" if risk == "high"
                        else "suspicious" if risk == "medium"
                        else "legitimate"
                    ),
                    "primary_threat_type": threat_type,
                    "analysis_confidence": "high",
                    "education": {
                        "what_it_is": "An example for offline integration testing."
                    },
                },
                model_name="offline-test-fixture",
            )

        # Fifth email: simulated AI processing failure.
        failed = Submission(
            input_type="text",
            input_value="Email whose AI analysis timed out",
            data_origin="batch_email",
            dataset_batch=self.batch_reference,
        )

        failed.mark_failed("Simulated AI timeout")
        self.data_manager.save_submission(failed)

        self.data_manager.update_email_batch_status(
            self.batch_reference,
            "partially_failed",
        )

    def test_saved_batch_counts_and_risks(self):
        # Retrieve the batch from the real SQLite database.
        report = BatchReportService(
            self.data_manager
        ).build_report(self.batch_reference)

        self.assertEqual(
            report.generate_summary(),
            {
                "batch_reference": self.batch_reference,
                "uploaded_files": 5,
                "accepted_emails": 5,
                "duplicate_files": 0,
                "failed_imports": 0,
                "total_emails": 5,
                "completed": 4,
                "failed": 1,
                "high_risk": 2,
                "medium_risk": 1,
                "low_risk": 1,
            },
        )

        self.assertEqual(len(report.email_records), 5)
        self.assertEqual(len(report.get_high_risk_results()), 2)

        self.assertEqual(
            report.get_risk_distribution(),
            {
                "high": 50.0,
                "medium": 25.0,
                "low": 25.0,
            },
        )

        # Check that the failed email was retained.
        self.assertTrue(
            any(
                row.get("error_message") == "Simulated AI timeout"
                for row in report.email_records
            )
        )

    def test_reopen_database_and_export_word_report(self):
        # Simulate restarting the application.
        reopened = DataManager(str(self.db_path))

        report = BatchReportService(
            reopened
        ).build_report(self.batch_reference)

        self.assertEqual(
            report.generate_summary()["total_emails"], 5
        )

        self.assertEqual(
            report.generate_summary()["failed"], 1
        )

        # Generate an actual Word document.
        output_path = Path("reports") / "batch_test_report.docx"
        output_path.parent.mkdir(parents=True, exist_ok=True)

        result = WordReportWriter().export(
            report,
            str(output_path),
        )

        # Verify that the document was generated.
        self.assertEqual(Path(result), output_path)
        self.assertTrue(output_path.is_file())

        # Open the generated Word document.
        document = Document(str(output_path))

        all_text = "\n".join(
            paragraph.text
            for paragraph in document.paragraphs
        )

        self.assertIn(self.batch_reference, all_text)
        self.assertIn("Batch", all_text)


if __name__ == "__main__":
    unittest.main()
