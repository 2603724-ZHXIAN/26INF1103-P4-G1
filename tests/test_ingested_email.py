"""Offline tests for the IngestedEmail domain model.

Verifies:
- Valid construction and property access.
- Invalid input rejection.
- Defensive copying of mutable data.
- Serialisation and deserialisation.
- Independent state between email instances.
"""

import unittest

from src.models.email_ingestion import IngestedEmail


class TestIngestedEmail(unittest.TestCase):
    """Test prepared email data without APIs or persistence."""

    def setUp(self):
        self.sample_data = {
            "item_id": "EMAIL-001",
            "source_path": "emails/account_notice.eml",
            "file_hash": "a" * 64,
            "body_text": "Please verify your account.",
            "subject": "Account notice",
            "sender": "Support <notice@example.com>",
            "reply_to": "reply@example.com",
            "recipients": ["recipient@example.com"],
            "urls": ["https://example.com/verify"],
            "attachments": [
                {
                    "filename": "invoice.pdf",
                    "content_type": "application/pdf",
                    "size_bytes": 100,
                }
            ],
            "warnings": ["Sender authenticity has not been verified."],
        }

    def make_email(self, **changes):
        data = dict(self.sample_data)
        data.update(changes)
        return IngestedEmail(**data)

    def test_valid_instantiation(self):
        email = self.make_email()

        self.assertEqual(email.item_id, "EMAIL-001")
        self.assertEqual(
            email.source_path,
            "emails/account_notice.eml",
        )
        self.assertEqual(email.file_hash, "a" * 64)
        self.assertEqual(email.subject, "Account notice")
        self.assertEqual(email.body_text, "Please verify your account.")
        self.assertEqual(
            email.sender,
            "Support <notice@example.com>",
        )
        self.assertEqual(email.reply_to, "reply@example.com")
        self.assertEqual(
            email.recipients,
            ["recipient@example.com"],
        )

    def test_required_references_reject_blank_values(self):
        for field_name in ("item_id", "source_path"):
            with self.subTest(field=field_name):
                with self.assertRaises(ValueError):
                    self.make_email(**{field_name: " "})

    def test_text_fields_reject_non_string_values(self):
        fields = (
            "item_id",
            "source_path",
            "body_text",
            "subject",
            "sender",
            "reply_to",
        )

        for field_name in fields:
            with self.subTest(field=field_name):
                with self.assertRaises(TypeError):
                    self.make_email(**{field_name: 123})

    def test_invalid_hashes_are_rejected(self):
        for file_hash in ("short", "g" * 64, " " * 64):
            with self.subTest(file_hash=file_hash):
                with self.assertRaises(ValueError):
                    self.make_email(file_hash=file_hash)

    def test_hash_requires_string(self):
        with self.assertRaises(TypeError):
            self.make_email(file_hash=123)

    def test_uppercase_hash_is_normalised(self):
        email = self.make_email(file_hash="A" * 64)

        self.assertEqual(email.file_hash, "a" * 64)

    def test_optional_collections_default_to_empty_lists(self):
        email = IngestedEmail(
            item_id="EMAIL-002",
            source_path="emails/example.eml",
            file_hash="b" * 64,
            body_text="Example message.",
        )

        self.assertEqual(email.recipients, [])
        self.assertEqual(email.urls, [])
        self.assertEqual(email.attachments, [])
        self.assertEqual(email.warnings, [])

    def test_empty_subject_and_body_are_preserved(self):
        email = self.make_email(subject="", body_text="")

        self.assertEqual(email.subject, "")
        self.assertEqual(email.body_text, "")

    def test_string_collections_reject_invalid_values(self):
        for field_name in ("recipients", "urls", "warnings"):
            for invalid_value in ("not-a-list", [123], [" "]):
                with self.subTest(
                    field=field_name,
                    value=invalid_value,
                ):
                    with self.assertRaises((TypeError, ValueError)):
                        self.make_email(
                            **{field_name: invalid_value}
                        )

    def test_attachment_collection_requires_list_of_dictionaries(self):
        for invalid_value in ({}, ["invoice.pdf"]):
            with self.subTest(value=invalid_value):
                with self.assertRaises(TypeError):
                    self.make_email(attachments=invalid_value)

    def test_attachment_requires_expected_fields(self):
        missing_field = {
            "filename": "invoice.pdf",
            "content_type": "application/pdf",
        }
        extra_field = {
            "filename": "invoice.pdf",
            "content_type": "application/pdf",
            "size_bytes": 100,
            "unexpected": True,
        }

        for attachment in (missing_field, extra_field):
            with self.subTest(attachment=attachment):
                with self.assertRaises(ValueError):
                    self.make_email(attachments=[attachment])

    def test_attachment_rejects_invalid_field_values(self):
        cases = (
            ("filename", 123, TypeError),
            ("content_type", 123, TypeError),
            ("content_type", " ", ValueError),
            ("size_bytes", True, TypeError),
            ("size_bytes", "100", TypeError),
            ("size_bytes", -1, ValueError),
        )

        for field_name, value, expected_error in cases:
            with self.subTest(field=field_name, value=value):
                attachment = {
                    "filename": "invoice.pdf",
                    "content_type": "application/pdf",
                    "size_bytes": 100,
                }
                attachment[field_name] = value

                with self.assertRaises(expected_error):
                    self.make_email(attachments=[attachment])

    def test_unnamed_zero_byte_attachment_is_allowed(self):
        email = self.make_email(
            attachments=[
                {
                    "filename": None,
                    "content_type": "application/octet-stream",
                    "size_bytes": 0,
                }
            ]
        )

        self.assertIsNone(email.attachments[0]["filename"])
        self.assertEqual(email.attachments[0]["size_bytes"], 0)

    def test_constructor_copies_mutable_inputs(self):
        email = self.make_email()

        self.sample_data["recipients"].clear()
        self.sample_data["urls"].clear()
        self.sample_data["warnings"].clear()
        self.sample_data["attachments"][0]["filename"] = "changed.pdf"

        self.assertEqual(len(email.recipients), 1)
        self.assertEqual(len(email.urls), 1)
        self.assertEqual(len(email.warnings), 1)
        self.assertEqual(
            email.attachments[0]["filename"],
            "invoice.pdf",
        )

    def test_properties_return_independent_collections(self):
        email = self.make_email()

        recipients = email.recipients
        urls = email.urls
        warnings = email.warnings
        attachments = email.attachments

        recipients.clear()
        urls.clear()
        warnings.clear()
        attachments[0]["size_bytes"] = 999

        self.assertEqual(len(email.recipients), 1)
        self.assertEqual(len(email.urls), 1)
        self.assertEqual(len(email.warnings), 1)
        self.assertEqual(email.attachments[0]["size_bytes"], 100)

    def test_serialisation_returns_independent_data(self):
        email = self.make_email()
        data = email.to_dict()

        data["urls"].clear()
        data["attachments"][0]["filename"] = "changed.pdf"

        self.assertEqual(len(email.urls), 1)
        self.assertEqual(
            email.attachments[0]["filename"],
            "invoice.pdf",
        )

    def test_serialisation_roundtrip(self):
        original = self.make_email()
        restored = IngestedEmail.from_dict(original.to_dict())

        self.assertIsInstance(restored, IngestedEmail)
        self.assertEqual(restored.to_dict(), original.to_dict())

    def test_from_dict_rejects_missing_required_fields(self):
        for field_name in (
            "item_id",
            "source_path",
            "file_hash",
            "body_text",
        ):
            with self.subTest(field=field_name):
                data = self.make_email().to_dict()
                del data[field_name]

                with self.assertRaises(ValueError):
                    IngestedEmail.from_dict(data)

    def test_from_dict_reuses_constructor_validation(self):
        data = self.make_email().to_dict()
        data["file_hash"] = "invalid"

        with self.assertRaises(ValueError):
            IngestedEmail.from_dict(data)

    def test_from_dict_requires_dictionary(self):
        with self.assertRaises(TypeError):
            IngestedEmail.from_dict([])

    def test_public_identity_property_is_read_only(self):
        email = self.make_email()

        with self.assertRaises(AttributeError):
            email.item_id = "EMAIL-999"

    def test_default_collections_are_independent_between_instances(self):
        first = IngestedEmail(
            item_id="EMAIL-001",
            source_path="first.eml",
            file_hash="a" * 64,
            body_text="First message.",
        )
        second = IngestedEmail(
            item_id="EMAIL-002",
            source_path="second.eml",
            file_hash="b" * 64,
            body_text="Second message.",
        )

        self.assertIsNot(first._urls, second._urls)
        self.assertIsNot(first._attachments, second._attachments)


if __name__ == "__main__":
    unittest.main()