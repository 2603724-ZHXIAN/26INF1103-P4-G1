"""Offline repository tests. Only temporary databases are modified."""

import logging
import sqlite3
import tempfile
import unittest
from pathlib import Path

from src.managers.data_manager import DataManager, DataManagerError
from src.models import AssessmentResult, Submission, ThreatEvidence


class DataManagerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "nested" / "test.db"
        self.manager = DataManager(str(self.path))
        self.manager.initialize_database()

    def tearDown(self):
        self.manager.close()
        self.temp.cleanup()

    def assessment(self, risk="high"):
        return AssessmentResult(
            is_scam=True, overall_risk=risk, decision="flag",
            recommended_action="Verify independently.", message_risk=risk,
            exposure_level="high", priority="urgent", route="account_security_response",
            risk_reasons=["Credentials requested"], flags=["phishing"],
            active_indicators=["credential_request"],
            matched_rules=[{"rule_id": "credential_phishing"}],
            matched_exposures=["entered_information"], exposure_reason="Credentials entered",
            recovery_steps=["Change password"], threat_summary="Possible phishing",
            what_it_is="A deceptive request", risk_score=85,
        )

    def complete_submission(self):
        submission = Submission("text", "Account warning: enter password", "entered_information")
        submission.create_evidence("credential_request", source="gemini", excerpt="enter password", severity="high")
        submission.mark_completed(self.assessment())
        return submission

    def test_initialize_is_repeatable_and_preserves_tables(self):
        self.manager.initialize_database()
        with self.manager._get_connection() as conn:
            names = {r["name"] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertTrue({"submission", "text_analysis", "vt_scan_result", "detection_evidence", "educational_guidance", "final_assessment"} <= names)

    def test_missing_parent_folder_is_created(self):
        self.assertTrue(self.path.is_file())

    def test_submission_round_trip(self):
        original = self.complete_submission()
        sub_id = self.manager.save_submission(original)
        restored = self.manager.get_submission_by_id(sub_id)
        self.assertIsInstance(restored, Submission)
        self.assertIsInstance(restored.assessment, AssessmentResult)
        self.assertIsInstance(restored.evidences[0], ThreatEvidence)
        self.assertEqual(original.to_dict(), restored.to_dict())

    def test_update_same_submission_does_not_duplicate(self):
        sub = self.complete_submission()
        first = self.manager.save_submission(sub)
        sub.mark_failed("Analysis unavailable")
        self.assertEqual(first, self.manager.save_submission(sub))
        self.assertEqual(len(self.manager.search_by_keyword("")), 1)
        loaded = self.manager.get_submission_by_id(first)
        self.assertEqual(loaded.processing_status, "failed")
        self.assertEqual(loaded.error_message, "Analysis unavailable")
        self.assertEqual(len(loaded.evidences), 1)

    def test_assessment_upsert_and_education(self):
        sub_id = self.manager.save_submission(Submission("url", "https://example.test"))
        first = self.assessment()
        self.manager.save_assessment(sub_id, first, "test-model")
        replacement = self.assessment("medium")
        self.manager.save_assessment(sub_id, replacement, "test-model-2")
        self.assertEqual(first.assessment_id, replacement.assessment_id)
        loaded = self.manager.get_submission_by_id(sub_id)
        self.assertEqual(loaded.assessment.overall_risk, "medium")
        self.assertEqual(loaded.assessment.recovery_steps, ["Change password"])
        with self.manager._get_connection() as conn:
            row = conn.execute("SELECT model_name FROM educational_guidance WHERE submission_id=?", (sub_id,)).fetchone()
        self.assertEqual(row["model_name"], "test-model-2")

    def test_evidence_snapshot_replaces_and_clears(self):
        sub_id = self.manager.save_submission(Submission("text", "hello"))
        evidence = ThreatEvidence("urgency", severity="medium")
        self.manager.save_evidences(sub_id, [evidence])
        self.manager.save_evidences(sub_id, [evidence])
        self.assertEqual(len(self.manager.get_submission_by_id(sub_id).evidences), 1)
        self.manager.save_evidences(sub_id, [])
        self.assertEqual(self.manager.get_submission_by_id(sub_id).evidences, [])

    def test_query_risk_only_returns_matching_assessments(self):
        sub_id = self.manager.save_submission(self.complete_submission())
        self.manager.save_submission(Submission("text", "unassessed"))
        self.assertEqual([r["submission_id"] for r in self.manager.query_by_risk("HIGH")], [sub_id])
        self.assertEqual(self.manager.query_by_risk("low"), [])

    def test_keyword_search_is_parameterized_and_literal(self):
        self.manager.save_submission(Submission("text", "100% account_notice"))
        self.manager.save_submission(Submission("text", "ordinary message"))
        self.assertEqual(len(self.manager.search_by_keyword("ACCOUNT")), 1)
        self.assertEqual(len(self.manager.search_by_keyword("%")), 1)
        self.assertEqual(self.manager.search_by_keyword("' OR 1=1 --"), [])

    def test_not_found_is_none(self):
        self.assertIsNone(self.manager.get_submission_by_id(999))

    def test_validation_and_missing_parent(self):
        with self.assertRaises(TypeError):
            self.manager.save_submission({})
        with self.assertRaises(ValueError):
            self.manager.query_by_risk("critical")
        with self.assertRaises(ValueError):
            self.manager.save_assessment(999, self.assessment(), "test")

    def test_transaction_rolls_back_and_connection_recovers(self):
        with self.assertRaises(DataManagerError), self.assertLogs("src.managers.data_manager", logging.ERROR):
            with self.manager._get_connection() as conn:
                conn.execute("INSERT INTO submission (data_origin,input_type,input_value,input_hash,interaction_type,created_at) VALUES ('test','text','rollback','hash','viewed_only','now')")
                conn.execute("INSERT INTO table_that_does_not_exist VALUES (1)")
        self.assertEqual(self.manager.search_by_keyword("rollback"), [])
        self.assertGreater(self.manager.save_submission(Submission("text", "works")), 0)

    def test_corrupt_database_has_explicit_error(self):
        path = Path(self.temp.name) / "corrupt.db"
        path.write_bytes(b"This is not a SQLite database")
        manager = DataManager(str(path))
        with self.assertRaises(DataManagerError), self.assertLogs("src.managers.data_manager", logging.ERROR):
            manager.initialize_database()
        self.assertEqual(path.read_bytes(), b"This is not a SQLite database")

    def test_unavailable_path_has_explicit_error(self):
        manager = DataManager(str(self.path / "impossible.db"))
        with self.assertRaises(DataManagerError), self.assertLogs("src.managers.data_manager", logging.ERROR):
            manager.initialize_database()

    def test_corrupt_stored_json_is_not_silently_defaulted(self):
        sub_id = self.manager.save_submission(self.complete_submission())
        with self.manager._get_connection() as conn:
            conn.execute("UPDATE final_assessment SET risk_reasons='broken json' WHERE submission_id=?", (sub_id,))
        with self.assertRaises(DataManagerError):
            self.manager.get_submission_by_id(sub_id)

    def test_composite_save_failure_rolls_back_parent(self):
        sub = self.complete_submission()
        with self.manager._get_connection() as conn:
            conn.execute("CREATE TRIGGER reject_evidence BEFORE INSERT ON detection_evidence BEGIN SELECT RAISE(ABORT, 'test failure'); END")
        with self.assertRaises(DataManagerError), self.assertLogs("src.managers.data_manager", logging.ERROR):
            self.manager.save_submission(sub)
        self.assertIsNone(sub.submission_id)
        self.assertIsNone(sub.assessment.assessment_id)
        self.assertEqual(self.manager.search_by_keyword(""), [])

    def test_in_memory_database_survives_multiple_operations(self):
        manager = DataManager(":memory:")
        try:
            manager.initialize_database()
            sub_id = manager.save_submission(Submission("text", "memory"))
            self.assertEqual(manager.get_submission_by_id(sub_id).input_value, "memory")
        finally:
            manager.close()

    def test_reporting_and_trending_queries(self):
        sub_id = self.manager.save_submission(self.complete_submission())
        with self.manager._get_connection() as conn:
            conn.execute(
                """INSERT INTO text_analysis (
                    submission_id, message_classification, primary_threat_type,
                    analysis_confidence, requested_actions, possible_intents,
                    extracted_urls, extracted_contacts, suspected_threat_types,
                    other_warning_signs, user_exposure, model_name, raw_gemini_response, created_at
                ) VALUES (?, 'scam', 'credential_phishing', 'high', '[]', '[]', '[]', '[]', '[]', '[]', '{}', 'test-model', '{}', '2026-10-31')""",
                (sub_id,)
            )

        # Test get_top_threat_types
        top_threats = self.manager.get_top_threat_types(limit=5)
        self.assertEqual(len(top_threats), 1)
        self.assertEqual(top_threats[0]["primary_threat_type"], "credential_phishing")

        # Test get_risk_category_counts
        counts = self.manager.get_risk_category_counts()
        self.assertEqual(len(counts), 1)
        self.assertEqual(counts[0]["risk_category"], "high")

        # Test get_incidents_by_threat_type
        incidents = self.manager.get_incidents_by_threat_type("credential_phishing")
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["submission_id"], sub_id)

        # Test get_submission_report
        report = self.manager.get_submission_report(sub_id)
        self.assertIsNotNone(report)
        self.assertEqual(report["submission_id"], sub_id)
        self.assertEqual(report["primary_threat_type"], "credential_phishing")

        # Test aliases
        self.assertEqual(len(self.manager.search_records("Account")), 1)
        self.assertEqual(len(self.manager.get_records_by_risk_level("high")), 1)


class TechnicalAIAnalysisPersistenceTests(unittest.TestCase):
    """Persistence of the AI verdict for URL/file submissions."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.manager = DataManager(str(Path(self.temp.name) / "tech.db"))
        self.manager.initialize_database()
        self.sub_id = self.manager.save_submission(Submission("file", "invoice.exe"))
        self.ai_data = {
            "is_malicious": True, "scam_confidence": 91,
            "threat_type": "trojan", "reasoning": "Six engines agree.",
        }

    def tearDown(self):
        self.manager.close()
        self.temp.cleanup()

    def test_ai_verdict_survives_a_new_manager_instance(self):
        self.manager.save_technical_analysis(self.sub_id, self.ai_data, "gemini-test")
        reloaded = DataManager(self.manager._db_path)  # simulates a separate run
        report = reloaded.get_submission_report(self.sub_id)
        self.assertEqual(report["ai_scam_confidence"], 91)
        self.assertEqual(report["ai_is_malicious"], 1)
        self.assertEqual(report["ai_threat_type"], "trojan")
        self.assertEqual(report["ai_reasoning"], "Six engines agree.")

    def test_saving_twice_updates_instead_of_duplicating(self):
        self.manager.save_technical_analysis(self.sub_id, self.ai_data, "m")
        self.manager.save_technical_analysis(self.sub_id, {**self.ai_data, "scam_confidence": 40}, "m")
        with sqlite3.connect(self.manager._db_path) as conn:
            rows = conn.execute("SELECT scam_confidence FROM technical_ai_analysis").fetchall()
        self.assertEqual(rows, [(40,)])

    def test_out_of_range_confidence_is_rejected_by_database(self):
        with self.assertRaises(DataManagerError):
            self.manager.save_technical_analysis(self.sub_id, {**self.ai_data, "scam_confidence": 150}, "m")

    def test_unknown_submission_and_bad_input_are_rejected(self):
        with self.assertRaises(ValueError):
            self.manager.save_technical_analysis(9999, self.ai_data, "m")
        with self.assertRaises(TypeError):
            self.manager.save_technical_analysis(self.sub_id, "not a dict", "m")

    def test_text_records_report_without_ai_technical_fields(self):
        text_id = self.manager.save_submission(Submission("text", "hello"))
        report = self.manager.get_submission_report(text_id)
        self.assertIsNone(report["ai_scam_confidence"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
