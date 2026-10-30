"""Offline tests for the OOP LogicManager, expanded with each stage."""

import copy
import unittest

from src.managers.logic_manager import LogicManager
from src.models import AssessmentResult, Submission


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


class LogicManagerTextAssessmentTests(unittest.TestCase):
    def setUp(self):
        self.manager = LogicManager()

    def ai(self, *active):
        return {"indicators": make_indicators(*active), "message_classification": "uncertain"}

    def test_returns_and_attaches_same_domain_result(self):
        sub = Submission("text", "Sign in", submission_id=17)
        result = self.manager.evaluate_text_threat(sub, self.ai("credential_request", "suspicious_link"))
        self.assertIsInstance(result, AssessmentResult)
        self.assertIs(sub.assessment, result)
        self.assertEqual(result.submission_id, 17)
        self.assertEqual(result.message_risk, "high")
        self.assertEqual(result.overall_risk, "high")
        self.assertTrue(result.is_scam)
        self.assertEqual(result.matched_rules[0]["rule_id"], "credential_phishing_rule")
        self.assertTrue(result.risk_reasons)
        self.assertEqual(result.recovery_steps, [result.recommended_action])
        self.assertEqual(sub.processing_status, "pending")

    def test_no_warning_indicators_return_low_unconfirmed_result(self):
        result = self.manager.evaluate_text_threat(Submission("text", "See you tomorrow"), self.ai())
        self.assertEqual(result.overall_risk, "low")
        self.assertFalse(result.is_scam)
        self.assertIsNone(result.risk_score)
        self.assertEqual(result.route, "general_safety_education")

    def test_all_six_actions_apply_to_suspicious_text(self):
        cases = [
            ("viewed_only", None, "low", "medium", "verification_guidance"),
            ("clicked_link", None, "medium", "medium", "verification_guidance"),
            ("entered_information", None, "high", "high", "account_security_response"),
            ("opened_or_downloaded_file", None, "high", "high", "device_security_response"),
            ("made_payment_or_shared_banking_details", None, "high", "high", "urgent_financial_response"),
            ("other", {"shared_otp": True}, "high", "high", "urgent_financial_response"),
        ]
        for action, exposure, level, risk, route in cases:
            with self.subTest(action=action):
                data = self.ai("authority_impersonation", "urgency_pressure")
                data["user_exposure"] = exposure
                result = self.manager.evaluate_text_threat(Submission("text", "Act now", action), data)
                self.assertEqual(result.exposure_level, level)
                self.assertEqual(result.overall_risk, risk)
                self.assertEqual(result.route, route)

    def test_payment_with_even_one_warning_escalates_and_routes_urgently(self):
        result = self.manager.evaluate_text_threat(
            Submission("text", "Urgent", "made_payment_or_shared_banking_details"),
            self.ai("urgency_pressure"),
        )
        self.assertEqual(result.message_risk, "low")
        self.assertEqual(result.overall_risk, "high")
        self.assertEqual(result.priority, "urgent")
        self.assertEqual(result.route, "urgent_financial_response")

    def test_other_without_interpretation_is_explicitly_unconfirmed(self):
        result = self.manager.evaluate_text_threat(
            Submission("text", "Act now", "other"),
            self.ai("authority_impersonation", "urgency_pressure"),
        )
        self.assertEqual(result.exposure_level, "medium")
        self.assertEqual(result.overall_risk, "medium")
        self.assertIn("unconfirmed", result.exposure_reason)

    def test_invalid_ai_does_not_replace_existing_assessment(self):
        sub = Submission("text", "A message")
        previous = self.manager.evaluate_text_threat(sub, self.ai())
        broken = self.ai()
        del broken["indicators"]["otp_request"]
        for data in (None, {"error": "API unavailable"}, broken):
            with self.subTest(data=data):
                with self.assertRaises(ValueError):
                    self.manager.evaluate_text_threat(sub, data)
                self.assertIs(sub.assessment, previous)

    def test_wrong_submission_type_is_rejected_without_attachment(self):
        sub = Submission("file", "sample.pdf")
        with self.assertRaises(ValueError):
            self.manager.evaluate_text_threat(sub, self.ai())
        self.assertIsNone(sub.assessment)

    def test_invalid_custom_exposure_is_rejected(self):
        for exposure in ("unknown", {"shared_otp": "true"}):
            with self.subTest(exposure=exposure):
                sub = Submission("text", "A message", "other")
                data = self.ai()
                data["user_exposure"] = exposure
                with self.assertRaises(ValueError):
                    self.manager.evaluate_text_threat(sub, data)
                self.assertIsNone(sub.assessment)

    def test_supplied_ai_data_is_not_modified(self):
        data = self.ai("credential_request", "suspicious_link")
        before = copy.deepcopy(data)
        self.manager.evaluate_text_threat(Submission("text", "Sign in"), data)
        self.assertEqual(data, before)

    def test_scam_classification_needs_supporting_warning_evidence(self):
        for active, expected in [((), False), (("urgency_pressure",), False), (("suspicious_link",), True)]:
            with self.subTest(active=active):
                data = self.ai(*active)
                data["message_classification"] = "scam"
                result = self.manager.evaluate_text_threat(Submission("text", "A message"), data)
                self.assertEqual(result.is_scam, expected)


def make_vt(malicious=0, suspicious=0, harmless=0, undetected=100, timeout=0, reputation=0):
    return {
        "detection_stats": {"malicious": malicious, "suspicious": suspicious,
                            "harmless": harmless, "undetected": undetected, "timeout": timeout},
        "reputation": reputation, "threat_names": [], "categories": [],
    }


class LogicManagerTechnicalEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.manager = LogicManager()

    def test_malicious_count_boundaries(self):
        for count, expected in [(0, "low"), (1, "medium"), (4, "medium"), (5, "high")]:
            with self.subTest(count=count):
                result = self.manager._evaluate_technical_evidence(make_vt(malicious=count))
                self.assertEqual(result["technical_risk"], expected)

    def test_ratio_threshold_boundaries(self):
        # One suspicious engine avoids the separate >=2 suspicious-count rule.
        for completed, expected in [(34, "low"), (33, "medium"), (11, "medium"), (10, "high")]:
            with self.subTest(completed=completed):
                result = self.manager._evaluate_technical_evidence(make_vt(suspicious=1, undetected=completed-1))
                self.assertEqual(result["technical_risk"], expected)

    def test_suspicious_count_boundary(self):
        for count, expected in [(1, "low"), (2, "medium")]:
            with self.subTest(count=count):
                self.assertEqual(self.manager._evaluate_technical_evidence(make_vt(suspicious=count))["technical_risk"], expected)

    def test_reputation_boundaries(self):
        for reputation, expected in [(0, "low"), (-1, "medium"), (-19, "medium"), (-20, "high")]:
            with self.subTest(reputation=reputation):
                self.assertEqual(self.manager._evaluate_technical_evidence(make_vt(reputation=reputation))["technical_risk"], expected)

    def test_timeouts_and_reported_total_do_not_dilute_ratio(self):
        data = make_vt(malicious=1, undetected=9, timeout=90)
        data["detection_stats"]["total"] = 100
        result = self.manager._evaluate_technical_evidence(data)
        self.assertEqual(result["detection_ratio"], 10.0)
        self.assertEqual(result["technical_risk"], "high")

    def test_zero_or_timeout_only_statistics_are_rejected(self):
        for timeout in (0, 10):
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                self.manager._evaluate_technical_evidence(make_vt(undetected=0, timeout=timeout))

    def test_missing_and_error_responses_are_rejected(self):
        for data in (None, {}, {"error": "Unavailable"}, {"detection_stats": []}):
            with self.subTest(data=data), self.assertRaises(ValueError):
                self.manager._evaluate_technical_evidence(data)

    def test_missing_required_count_is_not_treated_as_zero(self):
        data = make_vt()
        del data["detection_stats"]["malicious"]
        with self.assertRaises(ValueError):
            self.manager._evaluate_technical_evidence(data)

    def test_invalid_counts_are_rejected_without_truncation(self):
        for value in (-1, True, 1.5, "1.5", None, "bad"):
            with self.subTest(value=value):
                data = make_vt()
                data["detection_stats"]["malicious"] = value
                with self.assertRaises(ValueError):
                    self.manager._evaluate_technical_evidence(data)

    def test_integer_strings_from_parsed_evidence_are_supported(self):
        result = self.manager._evaluate_technical_evidence(make_vt(malicious="5", reputation="-20"))
        self.assertEqual(result["technical_risk"], "high")

    def test_invalid_reputation_is_rejected(self):
        with self.assertRaises(ValueError):
            self.manager._evaluate_technical_evidence(make_vt(reputation="unknown"))

    def test_flags_are_unique_sorted_and_input_is_unchanged(self):
        data = make_vt()
        data.update(threat_names=["trojan", "phishing"], categories=["phishing", " "])
        before = copy.deepcopy(data)
        result = self.manager._evaluate_technical_evidence(data)
        self.assertEqual(result["flags"], ["phishing", "trojan"])
        self.assertEqual(data, before)

    def test_malformed_labels_are_rejected(self):
        for labels in ("trojan", None, [1]):
            with self.subTest(labels=labels):
                data = make_vt()
                data["threat_names"] = labels
                with self.assertRaises(ValueError):
                    self.manager._evaluate_technical_evidence(data)


class LogicManagerTechnicalAssessmentTests(unittest.TestCase):
    def setUp(self):
        self.manager = LogicManager()

    def test_both_resource_types_and_all_six_user_actions(self):
        actions = [
            ("viewed_only", None, "low", "medium", "verification_guidance"),
            ("clicked_link", None, "medium", "medium", "verification_guidance"),
            ("entered_information", None, "high", "high", "account_security_response"),
            ("opened_or_downloaded_file", None, "high", "high", "device_security_response"),
            ("made_payment_or_shared_banking_details", None, "high", "high", "urgent_financial_response"),
            ("other", {"shared_otp": True}, "high", "high", "urgent_financial_response"),
        ]
        for kind in ("url", "file"):
            for action, exposure, level, overall, route in actions:
                with self.subTest(kind=kind, action=action):
                    sub = Submission(kind, "example.test" if kind == "url" else "sample.pdf", action)
                    result = self.manager.evaluate_technical_threat(sub, make_vt(suspicious=2), exposure)
                    self.assertIsInstance(result, AssessmentResult)
                    self.assertIs(sub.assessment, result)
                    self.assertEqual(result.message_risk, "medium")
                    self.assertEqual(result.exposure_level, level)
                    self.assertEqual(result.overall_risk, overall)
                    self.assertEqual(result.route, route)
                    self.assertEqual(result.recovery_steps, [result.recommended_action])

    def test_high_technical_risk_is_not_lowered_by_viewing_only(self):
        sub = Submission("file", "suspicious.exe", submission_id=21)
        data = make_vt(malicious=5)
        data["threat_names"] = ["trojan"]
        result = self.manager.evaluate_technical_threat(sub, data)
        self.assertEqual(result.overall_risk, "high")
        self.assertTrue(result.is_scam)
        self.assertEqual(result.flags, ["trojan"])
        self.assertEqual(result.submission_id, 21)
        self.assertIsNone(result.risk_score)
        self.assertIn("5 engine(s)", result.risk_reasons[0])
        self.assertEqual(sub.processing_status, "pending")

    def test_low_technical_risk_with_payment_preserves_existing_rule(self):
        result = self.manager.evaluate_technical_threat(
            Submission("url", "example.test", "made_payment_or_shared_banking_details"), make_vt()
        )
        self.assertEqual(result.overall_risk, "low")
        self.assertEqual(result.exposure_level, "high")
        self.assertEqual(result.route, "general_safety_education")

    def test_other_without_interpretation_has_explicit_unknown_explanation(self):
        result = self.manager.evaluate_technical_threat(Submission("url", "example.test", "other"), make_vt(suspicious=2))
        self.assertEqual(result.exposure_level, "medium")
        self.assertIn("unconfirmed", result.exposure_reason)

    def test_invalid_evidence_preserves_prior_assessment(self):
        sub = Submission("url", "example.test")
        prior = self.manager.evaluate_technical_threat(sub, make_vt())
        for data in ({"error": "Unavailable"}, make_vt(undetected=0, timeout=10), make_vt(malicious=-1)):
            with self.subTest(data=data), self.assertRaises(ValueError):
                try:
                    self.manager.evaluate_technical_threat(sub, data)
                finally:
                    self.assertIs(sub.assessment, prior)

    def test_text_submission_is_rejected_by_technical_pipeline(self):
        sub = Submission("text", "Hello")
        with self.assertRaises(ValueError):
            self.manager.evaluate_technical_threat(sub, make_vt())
        self.assertIsNone(sub.assessment)

    def test_custom_exposure_requires_valid_boolean_flags(self):
        for exposure in ("clicked", {"shared_otp": "false"}):
            with self.subTest(exposure=exposure), self.assertRaises(ValueError):
                self.manager.evaluate_technical_threat(Submission("url", "example.test", "other"), make_vt(), exposure)

    def test_input_findings_and_exposure_are_not_modified(self):
        data = make_vt(malicious=5)
        exposure = {"granted_remote_access": True}
        before = copy.deepcopy((data, exposure))
        self.manager.evaluate_technical_threat(Submission("file", "sample.exe", "other"), data, exposure)
        self.assertEqual((data, exposure), before)

    def test_domain_result_serialization_preserves_reasons_and_routes(self):
        sub = Submission("url", "example.test", "entered_information")
        result = self.manager.evaluate_technical_threat(sub, make_vt(malicious=5))
        restored = Submission.from_dict(sub.to_dict())
        self.assertEqual(restored.assessment.to_dict(), result.to_dict())


if __name__ == "__main__":
    unittest.main(verbosity=2)
