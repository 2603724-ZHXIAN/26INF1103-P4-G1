"""Offline integration tests for batch email ingestion."""

import tempfile
import unittest
from email.message import EmailMessage
from pathlib import Path

from src.services.email_ingestion_service import EmailIngestionService
from src.services.eml_parser import EmlParser


class TestEmailIngestionService(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

        self.folder = Path(self.temp.name)
        self.service = EmailIngestionService(
            parser=EmlParser(),
            max_files=10,
            max_file_bytes=4096,
        )

    def write_email(self, filename, body="Example message."):
        message = EmailMessage()
        message["From"] = "sender@example.com"
        message["To"] = "recipient@example.com"
        message["Subject"] = filename
        message.set_content(body)

        path = self.folder / filename
        path.write_bytes(message.as_bytes())

        return path

    def test_imports_multiple_selected_files(self):
        first = self.write_email("first.eml")
        second = self.write_email("second.eml")

        result = self.service.ingest_paths(
            [str(first), str(second)]
        )

        self.assertEqual(len(result["accepted"]), 2)
        self.assertEqual(result["issues"], [])
        self.assertEqual(
            result["accepted"][0].item_id,
            "EMAIL-001",
        )
        self.assertEqual(
            result["accepted"][1].item_id,
            "EMAIL-002",
        )

    def test_folder_discovery_is_non_recursive(self):
        self.write_email("first.eml")
        self.write_email("SECOND.EML")
        (self.folder / "notes.txt").write_text("Unrelated")

        nested = self.folder / "nested"
        nested.mkdir()
        (nested / "nested.eml").write_bytes(
            b"Subject: Nested\r\n\r\nNested body"
        )

        result = self.service.ingest_paths([str(self.folder)])

        self.assertEqual(len(result["accepted"]), 2)
        self.assertEqual(result["issues"], [])

    def test_exact_duplicate_references_original(self):
        original = self.write_email("original.eml")
        duplicate = self.folder / "copy.eml"
        duplicate.write_bytes(original.read_bytes())

        result = self.service.ingest_paths(
            [str(original), str(duplicate)]
        )

        self.assertEqual(len(result["accepted"]), 1)
        self.assertEqual(len(result["issues"]), 1)
        self.assertEqual(
            result["issues"][0]["kind"],
            "duplicate",
        )
        self.assertEqual(
            result["issues"][0]["duplicate_of"],
            "EMAIL-001",
        )

    def test_duplicate_tracking_is_independent_between_batches(self):
        path = self.write_email("example.eml")

        first = self.service.ingest_paths([str(path)])
        second = self.service.ingest_paths([str(path)])

        self.assertEqual(len(first["accepted"]), 1)
        self.assertEqual(len(second["accepted"]), 1)
        self.assertEqual(second["issues"], [])

    def test_invalid_files_do_not_stop_valid_email(self):
        empty = self.folder / "empty.eml"
        empty.write_bytes(b"")

        malformed = self.folder / "malformed.eml"
        malformed.write_bytes(b"Not an email")

        valid = self.write_email("valid.eml")

        result = self.service.ingest_paths(
            [str(empty), str(malformed), str(valid)]
        )

        self.assertEqual(len(result["accepted"]), 1)
        self.assertEqual(len(result["issues"]), 2)
        self.assertEqual(
            result["accepted"][0].item_id,
            "EMAIL-003",
        )

    def test_unsupported_and_missing_files_are_reported(self):
        unsupported = self.folder / "notes.txt"
        unsupported.write_text("Example")

        missing = self.folder / "missing.eml"

        result = self.service.ingest_paths(
            [str(unsupported), str(missing)]
        )

        self.assertEqual(result["accepted"], [])
        self.assertEqual(len(result["issues"]), 2)

    def test_oversized_file_is_rejected(self):
        path = self.folder / "large.eml"
        path.write_bytes(b"x" * 4097)

        result = self.service.ingest_paths([str(path)])

        self.assertEqual(result["accepted"], [])
        self.assertEqual(
            result["issues"][0]["code"],
            "invalid_file",
        )
        self.assertIn(
            "exceeds",
            result["issues"][0]["message"],
        )

    def test_file_exactly_at_limit_is_accepted(self):
        path = self.write_email("example.eml")

        service = EmailIngestionService(
            parser=EmlParser(),
            max_file_bytes=path.stat().st_size,
        )

        result = service.ingest_paths([str(path)])

        self.assertEqual(len(result["accepted"]), 1)

    def test_batch_limit_is_enforced(self):
        first = self.write_email("first.eml")
        second = self.write_email("second.eml")

        service = EmailIngestionService(
            parser=EmlParser(),
            max_files=1,
        )

        with self.assertRaises(ValueError):
            service.ingest_paths([str(first), str(second)])

    def test_empty_body_is_not_sent_for_text_analysis(self):
        path = self.folder / "empty_body.eml"
        path.write_bytes(
            b"From: sender@example.com\r\n"
            b"Subject: Empty body\r\n"
            b"\r\n"
        )

        result = self.service.ingest_paths([str(path)])

        self.assertEqual(result["accepted"], [])
        self.assertEqual(
            result["issues"][0]["code"],
            "no_readable_body",
        )

    def test_html_email_uses_existing_parser(self):
        message = EmailMessage()
        message["Subject"] = "HTML email"
        message.set_content(
            '<p>Verify account</p>'
            '<a href="https://example.com">Continue</a>',
            subtype="html",
        )

        path = self.folder / "html.eml"
        path.write_bytes(message.as_bytes())

        result = self.service.ingest_paths([str(path)])

        email = result["accepted"][0]
        self.assertIn("Verify account", email.body_text)
        self.assertIn("https://example.com", email.urls)
        self.assertTrue(email.warnings)

    def test_empty_folder_returns_empty_result(self):
        result = self.service.ingest_paths([str(self.folder)])

        self.assertEqual(result["accepted"], [])
        self.assertEqual(result["issues"], [])

    def test_invalid_configuration_is_rejected(self):
        for value in (0, -1, True, "10"):
            with self.subTest(value=value):
                with self.assertRaises((TypeError, ValueError)):
                    EmailIngestionService(
                        parser=EmlParser(),
                        max_files=value,
                    )

    def test_invalid_path_input_is_rejected(self):
        cases = (
            ("not-a-list", TypeError),
            ([], ValueError),
            ([" "], ValueError),
            ([123], TypeError),
        )

        for paths, expected_error in cases:
            with self.subTest(paths=paths):
                with self.assertRaises(expected_error):
                    self.service.ingest_paths(paths)


if __name__ == "__main__":
    unittest.main()