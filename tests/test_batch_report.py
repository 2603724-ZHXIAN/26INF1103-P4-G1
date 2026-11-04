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

    def test_get_common_threats(self):
        email_records = [
            {
                "processing_status": "completed",
                "primary_threat_type": "Phishing"
            },
            {
                "processing_status": "completed",
                "primary_threat_type": "Phishing"
            },
            {
                "processing_status": "completed",
                "primary_threat_type": "Malware"
            }
        ]

        report = BatchReport({}, email_records)

        expected = [
            {"threat_type": "phishing", "count": 2},
            {"threat_type": "malware", "count": 1}
        ]

        self.assertEqual(report.get_common_threats(), expected)

    def test_get_common_threats_ignores_failed(self):
        email_records = [
            {
                "processing_status": "completed",
                "primary_threat_type": "Phishing"
            },
            {
                "processing_status": "failed",
                "primary_threat_type": "Malware"
            }
        ]

        report = BatchReport({}, email_records)

        self.assertEqual(
            report.get_common_threats(),
            [{"threat_type": "phishing", "count": 1}]
        )


    def test_get_common_threats_ignores_missing_types(self):
        email_records = [
            {
                "processing_status": "completed",
                "primary_threat_type": None
            },
            {
                "processing_status": "completed",
                "primary_threat_type": "   "
            },
            {
                "processing_status": "completed",
                "primary_threat_type": "Phishing"
            }
        ]

        report = BatchReport({}, email_records)

        self.assertEqual(
            report.get_common_threats(),
            [{"threat_type": "phishing", "count": 1}]
        )


    def test_get_common_threats_empty_batch(self):
        report = BatchReport({}, [])

        self.assertEqual(report.get_common_threats(), [])

    def test_get_common_threats_case_insensitive(self):
        email_records = [
            {
                "processing_status": "completed",
                "primary_threat_type": "Phishing"
            },
            {
                "processing_status": "completed",
                "primary_threat_type": "phishing"
            },
            {
                "processing_status": "completed",
                "primary_threat_type": "PHISHING"
            }
        ]

        report = BatchReport({}, email_records)

        self.assertEqual(
            report.get_common_threats(),
            [{"threat_type": "phishing", "count": 3}]
        )

    def test_get_ranked_results(self):
        email_records = [
            {
                "submission_id": 101,
                "processing_status": "completed",
                "overall_risk": "low",
                "risk_score": 15
            },
            {
                "submission_id": 102,
                "processing_status": "completed",
                "overall_risk": "high",
                "risk_score": 90
            },
            {
                "submission_id": 103,
                "processing_status": "completed",
                "overall_risk": "medium",
                "risk_score": 55
            }
        ]

        report = BatchReport({}, email_records)

        ranked = report.get_ranked_results()

        self.assertEqual(
            [record["submission_id"] for record in ranked],
            [102, 103, 101]
        )

    def test_get_ranked_results_ignores_failed(self):
        email_records = [
            {
                "submission_id": 101,
                "processing_status": "completed",
                "overall_risk": "medium",
                "risk_score": 55
            },
            {
                "submission_id": 102,
                "processing_status": "failed",
                "overall_risk": "high",
                "risk_score": 95
            }
        ]

        report = BatchReport({}, email_records)

        ranked = report.get_ranked_results()

        self.assertEqual(len(ranked), 1)
        self.assertEqual(ranked[0]["submission_id"], 101)

    def test_get_ranked_results_ignores_invalid_scores(self):
        email_records = [
            {"submission_id": 1, "processing_status": "completed", "risk_score": None},
            {"submission_id": 2, "processing_status": "completed", "risk_score": "90"},
            {"submission_id": 3, "processing_status": "completed", "risk_score": True},
            {"submission_id": 4, "processing_status": "completed", "risk_score": -5},
            {"submission_id": 5, "processing_status": "completed", "risk_score": 120},
            {"submission_id": 6, "processing_status": "completed", "risk_score": float("nan")},
            {"submission_id": 7, "processing_status": "completed", "risk_score": 80},
        ]

        report = BatchReport({}, email_records)

        ranked = report.get_ranked_results()

        self.assertEqual(len(ranked), 1)
        self.assertEqual(ranked[0]["submission_id"], 7)
        self.assertEqual(ranked[0]["risk_score"], 80)

    def test_get_ranked_results_empty_batch(self):
        report = BatchReport({}, [])

        self.assertEqual(report.get_ranked_results(), [])


    def test_get_ranked_results_does_not_modify_original(self):
        email_records = [
            {
                "submission_id": 1,
                "processing_status": "completed",
                "overall_risk": "low",
                "risk_score": 10
            },
            {
                "submission_id": 2,
                "processing_status": "completed",
                "overall_risk": "high",
                "risk_score": 90
            }
        ]

        report = BatchReport({}, email_records)

        report.get_ranked_results()

        self.assertEqual(
            [record["submission_id"] for record in report.email_records],
            [1, 2]
        )

    def test_campaign_groups(self):
        records = [
            {
                "submission_id": 1,
                "input_value": "Your bank account is suspended",
                "processing_status": "completed"
            },
            {
                "submission_id": 2,
                "input_value": "Your bank account is suspended!",
                "processing_status": "completed"
            }
        ]

        report = BatchReport({}, records)
        groups = report.get_campaign_groups()

        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["submission_ids"], [1, 2])


    def test_campaign_groups_empty(self):
        report = BatchReport({}, [])

        self.assertEqual(report.get_campaign_groups(), [])

    def test_get_high_risk_results(self):
        """Only high-risk emails should be returned, highest score first."""

        batch_info = {
            "batch_reference": "TEST-001"
        }

        email_records = [
            {
                "submission_id": 1,
                "processing_status": "completed",
                "overall_risk": "medium",
                "risk_score": 60
            },
            {
                "submission_id": 2,
                "processing_status": "completed",
                "overall_risk": "high",
                "risk_score": 85
            },
            {
                "submission_id": 3,
                "processing_status": "completed",
                "overall_risk": "high",
                "risk_score": 95
            },
            {
                "submission_id": 4,
                "processing_status": "completed",
                "overall_risk": "low",
                "risk_score": 20
            }
        ]

        report = BatchReport(batch_info, email_records)

        results = report.get_high_risk_results()

        self.assertEqual(len(results), 2)
        self.assertEqual(
            [result["submission_id"] for result in results],
            [3, 2]
        )
        
if __name__ == "__main__":
    unittest.main()