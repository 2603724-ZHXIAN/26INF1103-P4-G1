import unittest

from src.batch.batch_report import BatchReport


class TestBatchReport(unittest.TestCase):

    def test_constructor_stores_batch_data(self):
        batch_info = {
            "batch_reference": "BATCH-001",
            "completed_count": 2,
        }

        email_records = [
            {"submission_id": 1, "overall_risk": "high"},
            {"submission_id": 2, "overall_risk": "low"},
        ]

        report = BatchReport(batch_info, email_records)

        self.assertEqual(
            report.batch_info["batch_reference"],
            "BATCH-001",
        )

        self.assertEqual(len(report.email_records), 2)

    def test_generate_summary(self):
        batch_info = {
            "batch_reference": "BATCH-001",
            "saved_email_count": 20,
            "completed_count": 17,
            "analysis_failed_count": 3,
            "high_risk_count": 8,
            "medium_risk_count": 6,
            "low_risk_count": 3,
        }

        report = BatchReport(batch_info, [])

        summary = report.generate_summary()

        self.assertEqual(summary["batch_reference"], "BATCH-001")
        self.assertEqual(summary["total_emails"], 20)
        self.assertEqual(summary["completed"], 17)
        self.assertEqual(summary["failed"], 3)
        self.assertEqual(summary["high_risk"], 8)
        self.assertEqual(summary["medium_risk"], 6)
        self.assertEqual(summary["low_risk"], 3)


    def test_generate_summary_empty_batch(self):
        batch_info = {
            "batch_reference": "BATCH-EMPTY",
            "saved_email_count": 0,
            "completed_count": None,
            "analysis_failed_count": None,
            "high_risk_count": None,
            "medium_risk_count": None,
            "low_risk_count": None,
        }

        report = BatchReport(batch_info, [])

        summary = report.generate_summary()

        self.assertEqual(summary["total_emails"], 0)
        self.assertEqual(summary["completed"], 0)
        self.assertEqual(summary["failed"], 0)
        self.assertEqual(summary["high_risk"], 0)
        self.assertEqual(summary["medium_risk"], 0)
        self.assertEqual(summary["low_risk"], 0)

    def test_get_risk_distribution(self):
        batch_info = {
            "high_risk_count": 8,
            "medium_risk_count": 6,
            "low_risk_count": 3,
            "analysis_failed_count": 3,
        }

        report = BatchReport(batch_info, [])

        distribution = report.get_risk_distribution()

        self.assertEqual(distribution["high"], 47.06)
        self.assertEqual(distribution["medium"], 35.29)
        self.assertEqual(distribution["low"], 17.65)

    def test_get_risk_distribution_empty_batch(self):
        report = BatchReport({}, [])

        distribution = report.get_risk_distribution()

        self.assertEqual(distribution["high"], 0.0)
        self.assertEqual(distribution["medium"], 0.0)
        self.assertEqual(distribution["low"], 0.0)

if __name__ == "__main__":
    unittest.main()