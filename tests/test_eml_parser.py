"""Offline tests for EmlParser.

Verifies:
- Header and character decoding.
- Plain-text preference and HTML fallback.
- Visible URL and HTML hyperlink extraction.
- Attachment metadata and body separation.
- Recoverable warnings and invalid input handling.
- Independent parsing between emails.

No live APIs, databases or filesystem access are required.
"""

import hashlib
import unittest
from email.message import EmailMessage

from src.models.email_ingestion import IngestedEmail
from src.services.eml_parser import EmlParser


class TestEmlParser(unittest.TestCase):
    """Test email parsing through its public interface."""

    def setUp(self):
        self.parser = EmlParser()

    # -------------------------------------------------------------------------
    # Test Helpers
    # -------------------------------------------------------------------------

    def parse_content(self, content):
        """Supply the references normally provided by ingestion."""
        return self.parser.parse(
            content=content,
            source_path="emails/example.eml",
            item_id="EMAIL-001",
            file_hash=hashlib.sha256(content).hexdigest(),
        )

    def make_message(self):
        """Create a plain-text email that individual tests can extend."""
        message = EmailMessage()
        message["From"] = "Support <support@example.com>"
        message["To"] = "recipient@example.com"
        message["Subject"] = "Account notice"
        message["Reply-To"] = "reply@example.com"
        message.set_content("Please verify your account.")
        return message

    # -------------------------------------------------------------------------
    # Domain Model and Headers
    # -------------------------------------------------------------------------

    def test_returns_existing_ingested_email_model(self):
        content = self.make_message().as_bytes()

        result = self.parse_content(content)

        self.assertIsInstance(result, IngestedEmail)
        self.assertEqual(result.item_id, "EMAIL-001")
        self.assertEqual(
            result.source_path,
            "emails/example.eml",
        )
        self.assertEqual(
            result.file_hash,
            hashlib.sha256(content).hexdigest(),
        )
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
        self.assertIn("Example message.", result.body_text)

    # -------------------------------------------------------------------------
    # Character and Transfer Decoding
    # -------------------------------------------------------------------------

    def test_decodes_declared_character_encoding(self):
        content = (
            b"From: sender@example.com\r\n"
            b"Content-Type: text/plain; charset=iso-8859-1\r\n"
            b"Content-Transfer-Encoding: 8bit\r\n"
            b"\r\n"
            b"Caf\xe9"
        )

        result = self.parse_content(content)

        self.assertEqual(result.body_text, "Café")

    def test_decodes_base64_body(self):
        content = (
            b"From: sender@example.com\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n"
            b"Content-Transfer-Encoding: base64\r\n"
            b"\r\n"
            b"SGVsbG8gd29ybGQ="
        )

        result = self.parse_content(content)

        self.assertEqual(result.body_text, "Hello world")

    def test_invalid_charset_uses_recovery(self):
        content = (
            b"From: sender@example.com\r\n"
            b"Content-Type: text/plain; charset=unknown-charset\r\n"
            b"\r\n"
            b"Example message."
        )

        result = self.parse_content(content)

        self.assertIn("Example message.", result.body_text)
        self.assertIn(
            "The declared body encoding could not be used. "
            "UTF-8 recovery was applied.",
            result.warnings,
        )

    def test_invalid_text_bytes_produce_decoding_warning(self):
        content = (
            b"From: sender@example.com\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n"
            b"\r\n"
            b"Invalid byte: \xff"
        )

        result = self.parse_content(content)

        self.assertIn("\ufffd", result.body_text)
        self.assertIn(
            "The body contains replacement characters; "
            "some original text may not have decoded correctly.",
            result.warnings,
        )

    # -------------------------------------------------------------------------
    # Body Selection and HTML Fallback
    # -------------------------------------------------------------------------

    def test_prefers_plain_text_without_duplicate_html_body(self):
        message = self.make_message()
        message.add_alternative(
            "<html><body>HTML alternative</body></html>",
            subtype="html",
        )

        result = self.parse_content(message.as_bytes())

        self.assertEqual(
            result.body_text.strip(),
            "Please verify your account.",
        )
        self.assertNotIn("HTML alternative", result.body_text)

    def test_html_only_email_is_converted_to_readable_text(self):
        message = EmailMessage()
        message["Subject"] = "HTML example"
        message.set_content(
            "<html><body>"
            "<p>Please verify your account.</p>"
            '<a href="https://example.com/verify">Continue</a>'
            "</body></html>",
            subtype="html",
        )

        result = self.parse_content(message.as_bytes())

        self.assertIn(
            "Please verify your account.",
            result.body_text,
        )
        self.assertIn("Continue", result.body_text)
        self.assertNotIn("<html>", result.body_text)
        self.assertIn(
            "https://example.com/verify",
            result.urls,
        )
        self.assertIn(
            "The body was extracted from HTML. "
            "Original visual formatting is not preserved.",
            result.warnings,
        )

    def test_blank_plain_text_falls_back_to_html(self):
        message = self.make_message()
        message.set_content(" ")
        message.add_alternative(
            "<p>Usable HTML message</p>",
            subtype="html",
        )

        result = self.parse_content(message.as_bytes())

        self.assertEqual(
            result.body_text,
            "Usable HTML message",
        )

    def test_html_scripts_and_styles_are_not_in_body(self):
        message = EmailMessage()
        message["Subject"] = "HTML example"
        message.set_content(
            "<html><body>"
            "<style>body { color: red; }</style>"
            "<script>alert('example')</script>"
            "<p>Visible message</p>"
            "</body></html>",
            subtype="html",
        )

        result = self.parse_content(message.as_bytes())

        self.assertEqual(result.body_text, "Visible message")
        self.assertNotIn("alert", result.body_text)
        self.assertNotIn("color: red", result.body_text)

    def test_empty_body_produces_explicit_warning(self):
        content = (
            b"From: sender@example.com\r\n"
            b"Subject: Empty message\r\n"
            b"\r\n"
        )

        result = self.parse_content(content)

        self.assertEqual(result.body_text, "")
        self.assertIn(
            "No usable message body was extracted.",
            result.warnings,
        )

    # -------------------------------------------------------------------------
    # URL Extraction
    # -------------------------------------------------------------------------

    def test_extracts_plain_text_urls_without_duplicates(self):
        message = self.make_message()
        message.set_content(
            "Visit https://example.com/verify. "
            "Again: https://example.com/verify"
        )

        result = self.parse_content(message.as_bytes())

        self.assertEqual(
            result.urls,
            ["https://example.com/verify"],
        )

    def test_extracts_html_destination_when_plain_text_is_preferred(self):
        message = self.make_message()
        message.add_alternative(
            "<p>HTML alternative</p>"
            '<a href="https://example.com/destination">'
            "Continue"
            "</a>",
            subtype="html",
        )

        result = self.parse_content(message.as_bytes())

        self.assertEqual(
            result.body_text.strip(),
            "Please verify your account.",
        )
        self.assertNotIn("HTML alternative", result.body_text)
        self.assertIn(
            "https://example.com/destination",
            result.urls,
        )

    def test_extracts_visible_urls_from_html_alternative(self):
        message = self.make_message()
        message.add_alternative(
            "<p>Visit https://example.com/html-only-link</p>",
            subtype="html",
        )

        result = self.parse_content(message.as_bytes())

        self.assertIn(
            "https://example.com/html-only-link",
            result.urls,
        )
        self.assertNotIn(
            "html-only-link",
            result.body_text,
        )

    def test_deduplicates_url_shared_between_body_alternatives(self):
        message = self.make_message()
        message.set_content("Visit https://example.com/verify")
        message.add_alternative(
            '<a href="https://example.com/verify">Verify</a>',
            subtype="html",
        )

        result = self.parse_content(message.as_bytes())

        self.assertEqual(
            result.urls,
            ["https://example.com/verify"],
        )

    def test_preserves_query_parameters_and_decodes_html_entities(self):
        message = EmailMessage()
        message["Subject"] = "Query example"
        message.set_content(
            '<a href="https://example.com/?a=1&amp;b=2">'
            "Continue"
            "</a>",
            subtype="html",
        )

        result = self.parse_content(message.as_bytes())

        self.assertEqual(
            result.urls,
            ["https://example.com/?a=1&b=2"],
        )

    def test_excludes_non_http_html_destinations(self):
        message = EmailMessage()
        message["Subject"] = "Link example"
        message.set_content(
            '<a href="javascript:alert(1)">One</a>'
            '<a href="mailto:test@example.com">Two</a>'
            '<a href="/relative">Three</a>'
            '<a href="https://example.com">Four</a>',
            subtype="html",
        )

        result = self.parse_content(message.as_bytes())

        self.assertEqual(
            result.urls,
            ["https://example.com"],
        )

    def test_preserves_balanced_parentheses_in_text_url(self):
        message = self.make_message()
        message.set_content(
            "See (https://example.com/page_(detail))."
        )

        result = self.parse_content(message.as_bytes())

        self.assertEqual(
            result.urls,
            ["https://example.com/page_(detail)"],
        )

    # -------------------------------------------------------------------------
    # Attachments
    # -------------------------------------------------------------------------

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
            result.attachments[0],
            {
                "filename": "invoice.bin",
                "content_type": "application/octet-stream",
                "size_bytes": len(b"attachment-content"),
            },
        )
        self.assertNotIn(
            "attachment-content",
            result.body_text,
        )

    def test_text_attachment_is_not_used_as_message_body(self):
        message = self.make_message()
        message.add_attachment(
            "Attachment-only message https://attachment.example",
            subtype="plain",
            filename="note.txt",
        )

        result = self.parse_content(message.as_bytes())

        self.assertEqual(
            result.body_text.strip(),
            "Please verify your account.",
        )
        self.assertEqual(len(result.attachments), 1)
        self.assertNotIn(
            "https://attachment.example",
            result.urls,
        )

    def test_attached_email_container_produces_warning(self):
        message = self.make_message()

        attached_message = EmailMessage()
        attached_message["Subject"] = "Attached message"
        attached_message.set_content("Nested email body.")

        message.add_attachment(
            attached_message,
            filename="forwarded.eml",
        )

        result = self.parse_content(message.as_bytes())

        self.assertIn(
            "A non-body MIME part could not be decoded "
            "directly; its attachment metadata was not included.",
            result.warnings,
        )
        self.assertNotIn("Nested email body.", result.body_text)

    # -------------------------------------------------------------------------
    # Failure Handling and Parser State
    # -------------------------------------------------------------------------

    def test_empty_content_is_rejected(self):
        for content in (b"", b" \r\n\t"):
            with self.subTest(content=content):
                with self.assertRaises(ValueError):
                    self.parse_content(content)

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

    def test_recoverable_mime_defect_is_reported(self):
        content = (
            b"From: sender@example.com\r\n"
            b"Content-Type: multipart/mixed\r\n"
            b"\r\n"
            b"Body without a MIME boundary."
        )

        result = self.parse_content(content)

        self.assertIn(
            "Email parsing issue: NoBoundaryInMultipartDefect.",
            result.warnings,
        )

    def test_links_do_not_leak_between_parse_calls(self):
        first_message = EmailMessage()
        first_message["Subject"] = "First"
        first_message.set_content(
            '<a href="https://example.com/first">Continue</a>',
            subtype="html",
        )

        first_result = self.parse_content(
            first_message.as_bytes()
        )
        second_result = self.parse_content(
            self.make_message().as_bytes()
        )

        self.assertEqual(
            first_result.urls,
            ["https://example.com/first"],
        )
        self.assertEqual(second_result.urls, [])


if __name__ == "__main__":
    unittest.main()