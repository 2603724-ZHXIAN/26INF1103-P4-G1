"""Contract tests: the AI Manager's answer format must match what the Logic Manager reads.

Each manager has its own unit tests, but those use each side's own sample data.
These tests pass data shaped by the AI Manager's JSON schema into the Logic
Manager, so a format mismatch between the two classes is caught (bug B5:
other_warning_signs was requested as plain strings, but LogicManager only
accepts objects, so every extra warning sign was silently ignored).
"""

import unittest

from src.managers.ai_manager import AIManager
from src.managers.logic_manager import LogicManager
from src.models import Submission

INDICATOR_NAMES = (
    "urgency_pressure", "authority_impersonation", "credential_request",
    "personal_information_request", "payment_request", "otp_request",
    "suspicious_link", "download_request", "threatening_language", "reward_or_prize",
)


def ai_result_with(other_warning_signs):
    """A text-analysis AI answer with no checklist indicators switched on."""
    return {
        "message_classification": "suspicious",
        "indicators": {name: {"present": False, "evidence": ""} for name in INDICATOR_NAMES},
        "other_warning_signs": other_warning_signs,
        "user_exposure": None,
    }


class OtherWarningSignsContractTests(unittest.TestCase):
    def setUp(self):
        schema = AIManager._build_message_analysis_schema()
        self.item_schema = schema["properties"]["other_warning_signs"]["items"]
        self.logic = LogicManager()

    def test_schema_asks_for_the_fields_logic_manager_reads(self):
        self.assertEqual(self.item_schema["type"], "object")
        self.assertEqual(
            set(self.item_schema["required"]),
            {"name", "evidence", "explanation"},
        )

    def test_schema_shaped_warning_raises_text_risk_to_medium(self):
        warning = {
            "name": "Unregistered sender number",
            "evidence": "Sent from +65 8123 4567",
            "explanation": "Banks send SMS from registered sender IDs.",
        }
        self.assertEqual(set(warning), set(self.item_schema["properties"]))

        result = self.logic.evaluate_text_threat(
            Submission("text", "Your parcel is held"), ai_result_with([warning])
        )

        self.assertEqual(result.message_risk, "medium")
        self.assertIn("unrecognised_warning_pattern", result.flags)

    def test_plain_string_warning_is_ignored_safely(self):
        # The old format must not crash the app; it just carries no evidence.
        result = self.logic.evaluate_text_threat(
            Submission("text", "Your parcel is held"),
            ai_result_with(["Unregistered sender number"]),
        )

        self.assertEqual(result.message_risk, "low")


if __name__ == "__main__":
    unittest.main()
