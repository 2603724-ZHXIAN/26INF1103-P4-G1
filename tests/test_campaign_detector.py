import unittest

from src.batch.campaign_detector import CampaignDetector


class TestCampaignDetector(unittest.TestCase):

    def setUp(self):
        self.detector = CampaignDetector()

    def test_identical_messages(self):
        score = self.detector.calculate_similarity(
            "Your account is suspended",
            "Your account is suspended"
        )
        self.assertEqual(score, 1.0)

    def test_case_insensitive(self):
        score = self.detector.calculate_similarity(
            "YOUR ACCOUNT IS SUSPENDED",
            "your account is suspended"
        )
        self.assertEqual(score, 1.0)

    def test_ignores_extra_whitespace(self):
        score = self.detector.calculate_similarity(
            "Your   account is suspended",
            "Your account is suspended"
        )
        self.assertEqual(score, 1.0)

    def test_different_messages(self):
        score = self.detector.calculate_similarity(
            "Your account is suspended",
            "Congratulations you won a holiday"
        )
        self.assertLess(score, 0.75)

    def test_empty_message(self):
        score = self.detector.calculate_similarity(
            "",
            "Your account is suspended"
        )
        self.assertEqual(score, 0.0)

    def test_invalid_message_type(self):
        with self.assertRaises(TypeError):
            self.detector.calculate_similarity(
                None,
                "Your account is suspended"
            )

    def test_invalid_threshold(self):
        with self.assertRaises(ValueError):
            CampaignDetector(1.5)

    def test_default_threshold(self):
        self.assertEqual(
            self.detector.similarity_threshold,
            0.75
        )

    def test_groups_similar_emails(self):
        emails = [
            {"submission_id": 1, "input_value": "Your bank account is suspended", "processing_status": "completed"},
            {"submission_id": 2, "input_value": "Your bank account is suspended!", "processing_status": "completed"},
            {"submission_id": 3, "input_value": "Congratulations you won a holiday", "processing_status": "completed"}
        ]

        groups = self.detector.group_similar_emails(emails)

        self.assertEqual(len(groups), 2)
        self.assertEqual(groups[0]["submission_ids"], [1, 2])
        self.assertEqual(groups[0]["count"], 2)


    def test_empty_batch(self):
        groups = self.detector.group_similar_emails([])
        self.assertEqual(groups, [])


    def test_skips_failed_emails(self):
        emails = [
            {"submission_id": 1, "input_value": "Bank alert", "processing_status": "failed"},
            {"submission_id": 2, "input_value": "Bank alert", "processing_status": "completed"}
        ]

        groups = self.detector.group_similar_emails(emails)

        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["submission_ids"], [2])


    def test_skips_missing_email_text(self):
        emails = [
            {"submission_id": 1, "processing_status": "completed"},
            {"submission_id": 2, "input_value": "", "processing_status": "completed"}
        ]

        groups = self.detector.group_similar_emails(emails)

        self.assertEqual(groups, [])


    def test_does_not_modify_original_records(self):
        emails = [
            {"submission_id": 1, "input_value": "Bank alert", "processing_status": "completed"}
        ]

        original = [record.copy() for record in emails]

        self.detector.group_similar_emails(emails)

        self.assertEqual(emails, original)