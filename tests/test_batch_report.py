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


if __name__ == "__main__":
    unittest.main()