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


class LogicManagerTextRuleTests(unittest.TestCase):
    def setUp(self):
        self.manager = LogicManager()

    def test_each_high_risk_combination(self):
        cases = [
            ({"credential_request", "suspicious_link"}, "credential_phishing_rule"),
            ({"otp_request", "authority_impersonation"}, "account_takeover_rule"),
            ({"payment_request", "authority_impersonation"}, "financial_fraud_rule"),
            ({"download_request", "suspicious_link"}, "malware_delivery_rule"),
            ({"reward_or_prize", "payment_request"}, "prize_scam_rule"),
            ({"personal_information_request", "suspicious_link"}, "personal_data_phishing_rule"),
        ]
        for active, rule_id in cases:
            with self.subTest(rule=rule_id):
                result = self.manager._determine_message_risk({}, active)
                self.assertEqual(result["level"], "high")
                self.assertIn(rule_id, [r["rule_id"] for r in result["matched_rules"]])

    def test_each_medium_risk_combination(self):
        cases = [
            ({"authority_impersonation", "urgency_pressure"}, "pressure_impersonation_rule"),
            ({"threatening_language", "urgency_pressure"}, "coercion_rule"),
        ]
        for active, rule_id in cases:
            with self.subTest(rule=rule_id):
                result = self.manager._determine_message_risk({}, active)
                self.assertEqual(result["level"], "medium")
                self.assertIn(rule_id, [r["rule_id"] for r in result["matched_rules"]])

    def test_strongest_combination_wins_and_all_matches_are_retained(self):
        result = self.manager._determine_message_risk(
            {}, {"credential_request", "suspicious_link", "authority_impersonation", "urgency_pressure"}
        )
        self.assertEqual(result["level"], "high")
        self.assertEqual(
            {r["rule_id"] for r in result["matched_rules"]},
            {"credential_phishing_rule", "pressure_impersonation_rule"},
        )
        self.assertEqual(len(result["reasons"]), 2)

    def test_each_direct_harm_indicator_has_high_fallback_risk(self):
        for name in ("credential_request", "payment_request", "otp_request", "download_request"):
            with self.subTest(indicator=name):
                result = self.manager._determine_message_risk({}, {name})
                self.assertEqual(result["level"], "high")
                self.assertEqual(result["flags"], ["direct_harm_request"])
                self.assertEqual(result["matched_rules"], [])

    def test_each_moderate_indicator_has_medium_fallback_risk(self):
        for name in ("personal_information_request", "suspicious_link"):
            with self.subTest(indicator=name):
                result = self.manager._determine_message_risk({}, {name})
                self.assertEqual(result["level"], "medium")

    def test_single_persuasion_indicator_is_low(self):
        for name in ("urgency_pressure", "authority_impersonation", "threatening_language", "reward_or_prize"):
            with self.subTest(indicator=name):
                result = self.manager._determine_message_risk({}, {name})
                self.assertEqual(result["level"], "low")
                self.assertEqual(result["flags"], ["warning_sign_detected"])

    def test_multiple_persuasion_indicators_have_medium_fallback_risk(self):
        result = self.manager._determine_message_risk({}, {"reward_or_prize", "urgency_pressure"})
        self.assertEqual(result["level"], "medium")
        self.assertEqual(result["flags"], ["multiple_persuasion_tactics"])

    def test_no_indicators_is_low_without_guaranteeing_safety(self):
        result = self.manager._determine_message_risk({}, set())
        self.assertEqual(result["level"], "low")
        self.assertEqual(result["flags"], [])
        self.assertIn("does not guarantee", result["reasons"][0])

    def test_valid_unfamiliar_warning_triggers_review_flag(self):
        warning = {"name": "Unfamiliar pattern", "evidence": "Quoted message", "explanation": "Needs review"}
        result = self.manager._determine_message_risk({"other_warning_signs": [warning]}, set())
        self.assertEqual(result["level"], "medium")
        self.assertEqual(result["flags"], ["unrecognised_warning_pattern"])
        self.assertEqual(result["unknown_warning_signs"], [warning])

    def test_invalid_unfamiliar_warnings_are_ignored(self):
        invalid = [None, "bad", {}, {"name": "pattern", "evidence": " "}]
        result = self.manager._determine_message_risk({"other_warning_signs": invalid}, set())
        self.assertEqual(result["unknown_warning_signs"], [])
        self.assertEqual(result["level"], "low")

    def test_unfamiliar_warning_does_not_lower_high_combination(self):
        result = self.manager._determine_message_risk(
            {"other_warning_signs": [{"name": "extra", "evidence": "quote"}]},
            {"credential_request", "suspicious_link"},
        )
        self.assertEqual(result["level"], "high")
        self.assertIn("unrecognised_warning_pattern", result["flags"])


class LogicManagerExposureRoutingTests(unittest.TestCase):
    def setUp(self):
        self.manager = LogicManager()

    def route(self, action, source="medium", overall="high", exposure=None, warnings=None):
        return self.manager._determine_route(overall, action, exposure or {}, warnings or [], source)

    def test_all_fixed_user_actions_have_expected_exposure(self):
        expected = {
            "viewed_only": "low", "clicked_link": "medium",
            "entered_information": "high", "opened_or_downloaded_file": "high",
            "made_payment_or_shared_banking_details": "high",
        }
        for action, level in expected.items():
            with self.subTest(action=action):
                result = self.manager._determine_user_exposure(action, {})
                self.assertEqual(result["level"], level)
                self.assertEqual(result["matched_exposures"], [action])
                self.assertTrue(result["reason"])

    def test_other_action_uses_interpreted_sensitive_exposure(self):
        result = self.manager._determine_user_exposure("other", {"entered_credentials": True})
        self.assertEqual(result["level"], "high")
        self.assertEqual(result["matched_exposures"], ["entered_credentials"])

    def test_other_action_distinguishes_click_and_no_known_action(self):
        clicked = self.manager._determine_user_exposure("other", {"clicked_or_opened_link": True})
        self.assertEqual(clicked["level"], "medium")
        self.assertEqual(self.manager._determine_user_exposure("other", {})["level"], "low")

    def test_other_action_without_interpretation_is_unknown(self):
        self.assertEqual(self.manager._determine_user_exposure("other", None)["level"], "unknown")

    def test_exposure_flags_require_actual_true_boolean(self):
        result = self.manager._determine_user_exposure("other", {"shared_otp": "false", "made_payment": 1})
        self.assertEqual(result["level"], "low")
        self.assertEqual(result["matched_exposures"], [])

    def test_all_nine_risk_matrix_combinations(self):
        expected = {
            ("low", "low"): "low", ("low", "medium"): "low", ("low", "high"): "low",
            ("medium", "low"): "medium", ("medium", "medium"): "medium", ("medium", "high"): "high",
            ("high", "low"): "high", ("high", "medium"): "high", ("high", "high"): "high",
        }
        for (source, exposure), overall in expected.items():
            with self.subTest(source=source, exposure=exposure):
                self.assertEqual(self.manager._determine_overall_risk(source, exposure), overall)

    def test_unknown_exposure_preserves_known_source_risk(self):
        for level in ("low", "medium", "high"):
            with self.subTest(level=level):
                self.assertEqual(self.manager._determine_overall_risk(level, "unknown"), level)

    def test_payment_after_suspicious_input_routes_to_urgent_financial_response(self):
        result = self.route("made_payment_or_shared_banking_details")
        self.assertEqual(result["route"], "urgent_financial_response")
        self.assertEqual(result["priority"], "urgent")
        self.assertEqual(result["decision"], "flag")

    def test_information_entry_and_download_have_distinct_routes(self):
        self.assertEqual(self.route("entered_information")["route"], "account_security_response")
        self.assertEqual(self.route("opened_or_downloaded_file")["route"], "device_security_response")

    def test_low_source_risk_does_not_trigger_recovery_solely_from_user_action(self):
        for action in ("entered_information", "opened_or_downloaded_file", "made_payment_or_shared_banking_details"):
            with self.subTest(action=action):
                result = self.route(action, source="low", overall="low")
                self.assertEqual(result["route"], "general_safety_education")
                self.assertEqual(result["priority"], "low")

    def test_custom_otp_and_remote_access_have_distinct_routes(self):
        financial = self.route("other", exposure={"shared_otp": True})
        device = self.route("other", exposure={"granted_remote_access": True})
        self.assertEqual(financial["route"], "urgent_financial_response")
        self.assertEqual(device["route"], "device_security_response")

    def test_generic_high_and_medium_risks_produce_guidance(self):
        self.assertEqual(self.route("viewed_only", source="high")["route"], "high_risk_guidance")
        medium = self.route("clicked_link", overall="medium")
        self.assertEqual(medium["route"], "verification_guidance")
        self.assertEqual(medium["decision"], "review")

    def test_unfamiliar_warning_requires_review_below_high_risk(self):
        result = self.route("viewed_only", overall="medium", warnings=[{"name": "unknown"}])
        self.assertEqual(result["route"], "unrecognised_pattern_review")
        self.assertEqual(result["decision"], "review")

    def test_critical_exposure_recognizes_sensitive_actions(self):
        self.assertTrue(self.manager._has_critical_exposure("made_payment_or_shared_banking_details", {}))
        self.assertTrue(self.manager._has_critical_exposure("other", {"installed_software": True}))
        self.assertFalse(self.manager._has_critical_exposure("clicked_link", {}))

    def test_critical_exposure_supports_high_priority_route_for_low_source(self):
        result = self.route("other", source="low", overall="high", exposure={"shared_otp": True})
        self.assertEqual(result["route"], "urgent_financial_response")


if __name__ == "__main__":
    unittest.main(verbosity=2)
