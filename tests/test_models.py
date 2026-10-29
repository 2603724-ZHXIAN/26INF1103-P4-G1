"""Unit tests for Domain Models (Submission, AssessmentResult, ThreatEvidence).

Verifies:
- Purposeful class instantiation
- Encapsulation and @property accessors with input validation
- Whole-part Composition semantics between Submission and its children
- Serialization / Deserialization (to_dict / from_dict)
"""

import unittest

from src.models import AssessmentResult, Submission, ThreatEvidence


class TestThreatEvidence(unittest.TestCase):
    """Test suite for ThreatEvidence domain entity."""

    def test_valid_instantiation(self):
        evidence = ThreatEvidence(
            evidence_name="urgency_pressure",
            source="gemini",
            evidence_type="indicator",
            evidence_value="present",
            evidence_excerpt="Act now or your account will be suspended!",
            severity="high",
        )
        self.assertEqual(evidence.evidence_name, "urgency_pressure")
        self.assertEqual(evidence.source, "gemini")
        self.assertEqual(evidence.severity, "high")
        self.assertTrue(evidence.is_concerning())

    def test_encapsulation_validation_rejects_invalid_source(self):
        with self.assertRaises(ValueError):
            ThreatEvidence(evidence_name="test", source="invalid_source")

    def test_encapsulation_validation_rejects_invalid_severity(self):
        with self.assertRaises(ValueError):
            ThreatEvidence(evidence_name="test", severity="ultra_danger")

    def test_serialization_roundtrip(self):
        original = ThreatEvidence(
            evidence_name="credential_request",
            source="gemini",
            evidence_excerpt="Enter your login credentials",
            severity="critical",
            submission_id=10,
            evidence_id=1,
        )
        data = original.to_dict()
        reconstituted = ThreatEvidence.from_dict(data)

        self.assertEqual(reconstituted.evidence_id, 1)
        self.assertEqual(reconstituted.submission_id, 10)
        self.assertEqual(reconstituted.evidence_name, "credential_request")
        self.assertEqual(reconstituted.severity, "critical")


class TestAssessmentResult(unittest.TestCase):
    """Test suite for AssessmentResult domain entity."""

    def test_valid_instantiation(self):
        assessment = AssessmentResult(
            is_scam=True,
            overall_risk="high",
            decision="malicious",
            recommended_action="Disconnect device immediately.",
            risk_score=95,
            priority="urgent",
            route="immediate_containment",
            recovery_steps=["1. Disconnect WiFi", "2. Run Antivirus"],
        )
        self.assertTrue(assessment.is_scam)
        self.assertEqual(assessment.overall_risk, "high")
        self.assertEqual(assessment.priority, "urgent")
        self.assertTrue(assessment.is_high_risk())
        self.assertTrue(assessment.requires_urgent_action())
        self.assertEqual(len(assessment.recovery_steps), 2)

    def test_encapsulation_rejects_invalid_risk_category(self):
        with self.assertRaises(ValueError):
            AssessmentResult(
                is_scam=False,
                overall_risk="extreme",  # Invalid
                decision="unknown",
                recommended_action="none",
            )

    def test_encapsulation_rejects_out_of_range_score(self):
        with self.assertRaises(ValueError):
            AssessmentResult(
                is_scam=True,
                overall_risk="high",
                decision="malicious",
                recommended_action="none",
                risk_score=150,  # Invalid: > 100
            )

    def test_serialization_roundtrip(self):
        original = AssessmentResult(
            is_scam=True,
            overall_risk="high",
            decision="malicious",
            recommended_action="Isolate",
            risk_score=85,
            recovery_steps=["Step 1"],
            assessment_id=42,
            submission_id=7,
        )
        data = original.to_dict()
        rebuilt = AssessmentResult.from_dict(data)

        self.assertEqual(rebuilt.assessment_id, 42)
        self.assertEqual(rebuilt.submission_id, 7)
        self.assertEqual(rebuilt.risk_score, 85)
        self.assertEqual(rebuilt.recovery_steps, ["Step 1"])


class TestSubmission(unittest.TestCase):
    """Test suite for Submission Aggregate Root and Composition."""

    def test_valid_instantiation_generates_hash(self):
        sub = Submission(
            input_type="text",
            input_value="Dear customer, your bank account is locked.",
            interaction_type="clicked_link",
        )
        self.assertEqual(sub.input_type, "text")
        self.assertEqual(sub.interaction_type, "clicked_link")
        self.assertEqual(sub.processing_status, "pending")
        self.assertTrue(len(sub.input_hash) > 0)

    def test_encapsulation_rejects_invalid_type(self):
        with self.assertRaises(ValueError):
            Submission(input_type="sms", input_value="hello")

    def test_composition_manages_assessment_lifecycle(self):
        sub = Submission(input_type="url", input_value="http://evil.com")
        sub.submission_id = 99

        assessment = AssessmentResult(
            is_scam=True,
            overall_risk="high",
            decision="malicious",
            recommended_action="Block domain",
        )
        sub.set_assessment(assessment)

        self.assertIsNotNone(sub.assessment)
        self.assertEqual(sub.assessment.submission_id, 99)
        self.assertEqual(sub.assessment.overall_risk, "high")

    def test_composition_manages_evidence_collection(self):
        sub = Submission(input_type="text", input_value="Urgent notice!")
        sub.submission_id = 50

        # Method 1: Add existing evidence object
        ev1 = ThreatEvidence(
            evidence_name="urgency_pressure",
            source="gemini",
            severity="high",
        )
        sub.add_evidence(ev1)

        # Method 2: Factory creation on aggregate root
        ev2 = sub.create_evidence(
            name="suspicious_link",
            source="business_rule",
            severity="medium",
            excerpt="http://bit.ly/scam",
        )

        self.assertEqual(len(sub.evidences), 2)
        self.assertEqual(sub.evidences[0].submission_id, 50)
        self.assertEqual(sub.evidences[1].submission_id, 50)
        self.assertEqual(ev2.evidence_name, "suspicious_link")

    def test_state_transitions(self):
        sub = Submission(input_type="file", input_value="malware.exe")
        self.assertEqual(sub.processing_status, "pending")

        sub.mark_processing()
        self.assertEqual(sub.processing_status, "processing")

        sub.mark_completed()
        self.assertEqual(sub.processing_status, "completed")
        self.assertIsNotNone(sub.completed_at)

        sub2 = Submission(input_type="text", input_value="test")
        sub2.mark_failed("API timeout")
        self.assertEqual(sub2.processing_status, "failed")
        self.assertEqual(sub2.error_message, "API timeout")

    def test_full_composite_serialization(self):
        sub = Submission(
            input_type="text",
            input_value="Test message",
            submission_id=123,
        )
        sub.create_evidence(name="flag1", source="gemini", severity="high")
        assessment = AssessmentResult(
            is_scam=True,
            overall_risk="high",
            decision="malicious",
            recommended_action="Delete",
        )
        sub.set_assessment(assessment)

        data = sub.to_dict()
        reconstituted = Submission.from_dict(data)

        self.assertEqual(reconstituted.submission_id, 123)
        self.assertEqual(len(reconstituted.evidences), 1)
        self.assertEqual(reconstituted.evidences[0].evidence_name, "flag1")
        self.assertIsNotNone(reconstituted.assessment)
        self.assertEqual(reconstituted.assessment.overall_risk, "high")


if __name__ == "__main__":
    unittest.main()
