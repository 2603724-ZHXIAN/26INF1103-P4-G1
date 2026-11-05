
import unittest
from unittest.mock import Mock

from src.batch.batch_report_service import BatchReportService
from src.batch.batch_report import BatchReport


class TestBatchReportService(unittest.TestCase):

    def setUp(self):
        self.data_manager = Mock()
        self.service = BatchReportService(self.data_manager)

    def test_build_report_from_saved_records(self):
        self.data_manager.list_email_batches.return_value = [
            {
                "batch_reference": "BATCH-001",
                "saved_email_count": 1,
                "completed_count": 1,
                "analysis_failed_count": 0,
                "high_risk_count": 1,
                "medium_risk_count": 0,
                "low_risk_count": 0,
            }
        ]

        self.data_manager.get_batch_submissions.return_value = [
            {
                "submission_id": 10,
                "input_value": "Urgent bank verification",
                "processing_status": "completed",
            }
        ]

        self.data_manager.get_submission_report.return_value = {
            "submission_id": 10,
            "input_value": "Urgent bank verification",
            "processing_status": "completed",
            "overall_risk": "high",
            "risk_score": 90,
            "primary_threat_type": "phishing",
        }

        report = self.service.build_report("BATCH-001")

        self.assertIsInstance(report, BatchReport)
        self.assertEqual(report.generate_summary()["completed"], 1)
        self.assertEqual(len(report.get_high_risk_results()), 1)

    def test_nonexistent_batch_raises_error(self):
        self.data_manager.list_email_batches.return_value = []

        with self.assertRaises(ValueError):
            self.service.build_report("UNKNOWN-BATCH")


    def test_build_report_includes_failed_email(self):
        self.data_manager.list_email_batches.return_value = [
            {
                "batch_reference": "BATCH-002",
                "saved_email_count": 1,
                "completed_count": 0,
                "analysis_failed_count": 1,
                "high_risk_count": 0,
                "medium_risk_count": 0,
                "low_risk_count": 0,
            }
        ]

        self.data_manager.get_batch_submissions.return_value = [
            {
                "submission_id": 20,
                "input_value": "Suspicious email",
                "processing_status": "failed",
                "error_message": "AI request timed out",
            }
        ]

        self.data_manager.get_submission_report.return_value = None

        report = self.service.build_report("BATCH-002")

        self.assertEqual(report.generate_summary()["failed"], 1)
        self.assertEqual(
            len(report.get_high_risk_results()), 0
        )

        self.data_manager.get_submission_report.assert_called_once_with(20)


    def test_build_report_with_empty_batch(self):
        self.data_manager.list_email_batches.return_value = [
            {
                "batch_reference": "BATCH-003",
                "saved_email_count": 0,
                "completed_count": 0,
                "analysis_failed_count": 0,
                "high_risk_count": 0,
                "medium_risk_count": 0,
                "low_risk_count": 0,
            }
        ]

        self.data_manager.get_batch_submissions.return_value = []

        report = self.service.build_report("BATCH-003")

        self.assertIsInstance(report, BatchReport)
        self.assertEqual(report.generate_summary()["total_emails"], 0)
        self.assertEqual(report.generate_summary()["completed"], 0)
        self.assertEqual(report.get_ranked_results(), [])

        self.data_manager.get_submission_report.assert_not_called()


if __name__ == "__main__":
    unittest.main()
