"""Offline repository tests. Only temporary databases are modified."""

import json
import logging
import sqlite3
import tempfile
import unittest
from pathlib import Path
from contextlib import closing

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

    def test_batch_submissions_returns_actual_email_ids(self):
        """Batch queries should include saved email IDs without losing submissions."""

        # Create a temporary batch.
        with self.manager._get_connection() as connection:
            connection.execute(
                """
                INSERT INTO email_batch (
                    batch_reference, created_at, processing_status,
                    total_files, accepted_count, duplicate_count,
                    import_failed_count
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                ("BATCH-TEST", "2026-11-06", "imported", 2, 2, 0, 0),
            )

        first = Submission(
            "text",
            "First test email",
            data_origin="batch",
            dataset_batch="BATCH-TEST",
        )
        first_id = self.manager.save_submission(first)

        second = Submission(
            "text",
            "Second test email",
            data_origin="batch",
            dataset_batch="BATCH-TEST",
        )
        second_id = self.manager.save_submission(second)

        # Give only the first submission an email reference.
        with self.manager._get_connection() as connection:
            connection.execute(
                """
                INSERT INTO email_metadata (
                    submission_id, item_id, source_path, file_hash,
                    subject, sender, reply_to, recipients, urls,
                    attachments, warnings
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    first_id, "EMAIL-001", "first.eml", "test-hash",
                    "Test subject", "sender@example.com", "",
                    "[]", "[]", "[]", "[]",
                ),
            )

        # Retrieve the batch records using our updated query.
        records = self.manager.get_batch_submissions("BATCH-TEST")

        # Both submissions should still exist.
        self.assertEqual(len(records), 2)

        # The first submission should contain the actual Email ID.
        self.assertEqual(records[0]["submission_id"], first_id)
        self.assertEqual(records[0]["email_id"], "EMAIL-001")

        # The second submission should remain, even without metadata.
        self.assertEqual(records[1]["submission_id"], second_id)
        self.assertIsNone(records[1]["email_id"])


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

    def test_full_saved_education_survives_reopening_in_report(self):
        """Historical reports must retrieve the complete saved AI education."""
        submission = self.complete_submission()
        submission_id = self.manager.save_submission(submission)

        education = {
            "threat_explanations": [
                {
                    "threat_type": "Credential phishing",
                    "meaning": "A deceptive attempt to obtain credentials.",
                    "typical_goal": "Gain access to an account.",
                    "evidence": ["The email asks for a password."],
                }
            ],
            "threat_summary": "A possible credential theft attempt.",
            "what_it_is": "A message requesting account credentials.",
            "why_dangerous": ["Account access could be lost."],
            "preventive_steps": ["Verify through the official website."],
            "recovery_steps": ["Change any password that was disclosed."],
            "limitations": ["The destination website was not scanned."],
            "recovery_by_action": {
                "viewed_only": {
                    "steps": ["Avoid following the email link."]
                },
                "clicked_link": {
                    "steps": ["Close the suspicious page."]
                },
                "entered_information": {
                    "steps": ["Change the disclosed password."]
                },
                "opened_or_downloaded_file": {
                    "steps": ["Do not execute the downloaded file."]
                },
                "made_payment_or_shared_banking_details": {
                    "steps": ["Contact the bank through an official channel."]
                },
            },
        }

        self.manager.save_text_analysis(
            submission_id,
            {
                "message_classification": "suspicious",
                "education": education,
            },
            "offline-test-model",
        )

        self.manager.close()
        reopened = DataManager(str(self.path))

        try:
            reopened.initialize_database()
            report = reopened.get_submission_report(submission_id)

            self.assertIsNotNone(report)

            for field, expected in education.items():
                with self.subTest(field=field):
                    self.assertEqual(report[field], expected)

            self.assertEqual(
                report["recommended_action"],
                submission.assessment.recommended_action,
            )

        finally:
            reopened.close()

    def test_text_analysis_resave_updates_extracted_fields(self):
        """A resave must keep extracted columns consistent with raw JSON."""
        submission_id = self.manager.save_submission(
            Submission("text", "Example message")
        )

        first = {
            "message_classification": "suspicious",
            "language": "English",
            "message_type": "email",
            "claimed_entity": "First organisation",
            "requested_actions": ["Visit the first page"],
            "possible_intents": ["First intent"],
            "extracted_urls": ["https://example.com/first"],
            "extracted_contacts": ["first@example.com"],
            "suspected_threat_types": ["phishing"],
            "other_warning_signs": ["First warning"],
            "user_exposure": {"description_summary": "Unknown"},
        }

        second = {
            "message_classification": "scam",
            "language": "Malay",
            "message_type": "chat_message",
            "claimed_entity": "Second organisation",
            "requested_actions": ["Enter credentials"],
            "possible_intents": ["Credential theft"],
            "extracted_urls": ["https://example.com/second"],
            "extracted_contacts": ["second@example.com"],
            "suspected_threat_types": ["credential_phishing"],
            "other_warning_signs": ["Second warning"],
            "user_exposure": {"description_summary": "Link clicked"},
        }

        self.manager.save_text_analysis(
            submission_id, first, "offline-model-1"
        )
        self.manager.save_text_analysis(
            submission_id, second, "offline-model-2"
        )

        with self.manager._get_connection() as connection:
            row = connection.execute(
                """
                SELECT *
                FROM text_analysis
                WHERE submission_id = ?
                """,
                (submission_id,),
            ).fetchone()

            count = connection.execute(
                """
                SELECT COUNT(*)
                FROM text_analysis
                WHERE submission_id = ?
                """,
                (submission_id,),
            ).fetchone()[0]

        self.assertEqual(count, 1)

        for field in (
            "language",
            "message_type",
            "claimed_entity",
            "message_classification",
        ):
            with self.subTest(field=field):
                self.assertEqual(row[field], second[field])

        for field in (
            "requested_actions",
            "possible_intents",
            "extracted_urls",
            "extracted_contacts",
            "suspected_threat_types",
            "other_warning_signs",
            "user_exposure",
        ):
            with self.subTest(field=field):
                self.assertEqual(
                    json.loads(row[field]),
                    second[field],
                )

        self.assertEqual(
            json.loads(row["raw_gemini_response"]),
            second,
        )

    def test_vt_resave_updates_timeout_count(self):
        """Repeated telemetry saves update counts without duplicate rows."""
        submission_id = self.manager.save_submission(
            Submission("url", "https://example.com")
        )

        for timeout_count in (1, 7):
            self.manager.save_vt_scan_result(
                submission_id,
                {
                    "resource_identifier": "https://example.com",
                    "parsed_result": {
                        "resource_type": "url",
                        "detection_stats": {
                            "malicious": 0,
                            "suspicious": 1,
                            "harmless": 4,
                            "undetected": 3,
                            "timeout": timeout_count,
                        },
                    },
                },
            )

        with self.manager._get_connection() as connection:
            rows = connection.execute(
                """
                SELECT timeout_count
                FROM vt_scan_result
                WHERE submission_id = ?
                """,
                (submission_id,),
            ).fetchall()

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["timeout_count"], 7)

    def test_report_rejects_corrupt_saved_ai_json(self):
        """Corrupt saved education must raise a clear repository error."""
        submission_id = self.manager.save_submission(
            Submission("text", "Example message")
        )

        self.manager.save_text_analysis(
            submission_id,
            {"message_classification": "suspicious"},
            "offline-test-model",
        )

        with self.manager._get_connection() as connection:
            connection.execute(
                """
                UPDATE text_analysis
                SET raw_gemini_response = ?
                WHERE submission_id = ?
                """,
                ("{invalid JSON", submission_id),
            )

        with self.assertRaises(DataManagerError):
            self.manager.get_submission_report(submission_id)

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
        with closing(sqlite3.connect(self.manager._db_path)) as conn:
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

    def test_vt_result_keeps_the_scanned_resource_identifier(self):
        vt_result = {
            "resource_identifier": "invoice.exe",
            "parsed_result": {"resource_type": "file", "detection_stats": {"malicious": 1}},
        }
        self.manager.save_vt_scan_result(self.sub_id, vt_result)
        with closing(sqlite3.connect(self.manager._db_path)) as conn:
            row = conn.execute("SELECT resource_identifier FROM vt_scan_result").fetchone()
        self.assertEqual(row[0], "invoice.exe")


if __name__ == "__main__":
    unittest.main(verbosity=2)
