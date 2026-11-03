"""Offline tests for the initial EML parser."""

import hashlib
import unittest
from email.message import EmailMessage

from src.models.email_ingestion import IngestedEmail
from src.services.eml_parser import EmlParser


class TestEmlParser(unittest.TestCase):
    """Verify parsing without AI, databases or real email files."""

    def setUp(self):
        self.parser = EmlParser()

    def parse_content(self, content):
        return self.parser.parse(
            content=content,
            source_path="emails/example.eml",
            item_id="EMAIL-001",
            file_hash=hashlib.sha256(content).hexdigest(),
        )

    def make_message(self):
        message = EmailMessage()
        message["From"] = "Support <support@example.com>"
        message["To"] = "recipient@example.com"
        message["Subject"] = "Account notice"
        message["Reply-To"] = "reply@example.com"
        message.set_content("Please verify your account.")
        return message

    def test_returns_existing_ingested_email_model(self):
        message = self.make_message()

        result = self.parse_content(message.as_bytes())

        self.assertIsInstance(result, IngestedEmail)
        self.assertEqual(result.item_id, "EMAIL-001")
        self.assertEqual(result.subject, "Account notice")
        self.assertEqual(
            result.sender,
            "Support <support@example.com>",
        )
        self.assertEqual(result.reply_to, "reply@example.com")
        self.assertEqual(
            result.recipients,
            ["recipient@example.com"],
        )
        self.assertIn(
            "Please verify your account.",
            result.body_text,
        )

    def test_decodes_encoded_subject(self):
        content = (
            b"From: sender@example.com\r\n"
            b"Subject: =?utf-8?b?Q2Fmw6k=?=\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n"
            b"\r\n"
            b"Example message."
        )

        result = self.parse_content(content)

        self.assertEqual(result.subject, "Café")

    def test_prefers_plain_text_without_duplicate_html_body(self):
        message = self.make_message()
        message.add_alternative(
            "<html><body>HTML alternative</body></html>",
            subtype="html",
        )

        result = self.parse_content(message.as_bytes())

        self.assertIn(
            "Please verify your account.",
            result.body_text,
        )
        self.assertNotIn("HTML alternative", result.body_text)

    def test_extracts_attachment_metadata_without_body_content(self):
        message = self.make_message()
        message.add_attachment(
            b"attachment-content",
            maintype="application",
            subtype="octet-stream",
            filename="invoice.bin",
        )

        result = self.parse_content(message.as_bytes())

        self.assertEqual(len(result.attachments), 1)
        self.assertEqual(
            result.attachments[0]["filename"],
            "invoice.bin",
        )
        self.assertEqual(
            result.attachments[0]["size_bytes"],
            len(b"attachment-content"),
        )
        self.assertNotIn(
            "attachment-content",
            result.body_text,
        )

    def test_missing_optional_headers_produce_warnings(self):
        content = (
            b"To: recipient@example.com\r\n"
            b"\r\n"
            b"Example message."
        )

        result = self.parse_content(content)

        self.assertIn(
            "The email has no subject.",
            result.warnings,
        )
        self.assertIn(
            "The email has no From header.",
            result.warnings,
        )

    def test_invalid_charset_uses_recovery(self):
        content = (
            b"From: sender@example.com\r\n"
            b"Content-Type: text/plain; charset=unknown-charset\r\n"
            b"\r\n"
            b"Example message."
        )

        result = self.parse_content(content)

        self.assertIn("Example message.", result.body_text)
        self.assertTrue(
            any(
                "UTF-8 recovery" in warning
                for warning in result.warnings
            )
        )

    def test_html_only_email_has_explicit_stage_warning(self):
        message = EmailMessage()
        message["Subject"] = "HTML example"
        message.set_content(
            "<html><body>Example</body></html>",
            subtype="html",
        )

        result = self.parse_content(message.as_bytes())

        self.assertEqual(result.body_text, "")
        self.assertTrue(
            any(
                "No plain-text body" in warning
                for warning in result.warnings
            )
        )

    def test_empty_content_is_rejected(self):
        with self.assertRaises(ValueError):
            self.parse_content(b"")

    def test_arbitrary_text_without_email_headers_is_rejected(self):
        with self.assertRaises(ValueError):
            self.parse_content(b"This is not an email file.")

    def test_non_bytes_content_is_rejected(self):
        with self.assertRaises(TypeError):
            self.parser.parse(
                content="Example",
                source_path="example.eml",
                item_id="EMAIL-001",
                file_hash="a" * 64,
            )


if __name__ == "__main__":
    unittest.main()