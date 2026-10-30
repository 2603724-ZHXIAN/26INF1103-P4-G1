"""Offline tests for the OOP LogicManager, expanded with each stage."""

import unittest

from src.managers.logic_manager import LogicManager
from src.models import Submission


INDICATOR_NAMES = (
    "urgency_pressure", "authority_impersonation", "credential_request",
    "personal_information_request", "payment_request", "otp_request",
    "suspicious_link", "download_request", "threatening_language", "reward_or_prize",
)


def make_indicators(*active):
    return {
        name: {"present": name in active, "evidence": f"Evidence for {name}" if name in active else ""}
        for name in INDICATOR_NAMES
    }


class LogicManagerValidationTests(unittest.TestCase):
    def setUp(self):
        self.manager = LogicManager()

    def test_accepts_text_submission_for_text_pipeline(self):
        self.manager._validate_submission(Submission("text", "hello"), {"text"})

    def test_rejects_dictionary_instead_of_domain_object(self):
        with self.assertRaises(TypeError):
            self.manager._validate_submission({"input_type": "text"}, {"text"})

    def test_rejects_wrong_pipeline(self):
        with self.assertRaises(ValueError):
            self.manager._validate_submission(Submission("url", "https://example.test"), {"text"})

    def test_complete_inactive_evidence_has_no_active_signs(self):
        self.assertEqual(self.manager._get_active_indicators(make_indicators()), set())

    def test_extracts_only_active_validated_indicators(self):
        self.assertEqual(
            self.manager._get_active_indicators(make_indicators("credential_request", "suspicious_link")),
            {"credential_request", "suspicious_link"},
        )

    def test_missing_indicator_is_rejected(self):
        data = make_indicators()
        del data["otp_request"]
        with self.assertRaisesRegex(ValueError, "otp_request"):
            self.manager._get_active_indicators(data)

    def test_active_indicator_requires_nonblank_evidence(self):
        data = make_indicators("payment_request")
        data["payment_request"]["evidence"] = "  "
        with self.assertRaises(ValueError):
            self.manager._get_active_indicators(data)

    def test_presence_must_be_boolean(self):
        data = make_indicators()
        data["urgency_pressure"]["present"] = "false"
        with self.assertRaises(ValueError):
            self.manager._get_active_indicators(data)

    def test_non_dictionary_evidence_is_rejected(self):
        with self.assertRaises(ValueError):
            self.manager._get_active_indicators(None)

    def test_rule_configuration_is_independent_per_instance(self):
        other = LogicManager()
        self.manager._risk_matrix[("high", "low")] = "low"
        self.assertEqual(other._risk_matrix[("high", "low")], "high")
        self.manager._known_indicators.clear()
        self.assertIn("otp_request", other._known_indicators)


if __name__ == "__main__":
    unittest.main(verbosity=2)
