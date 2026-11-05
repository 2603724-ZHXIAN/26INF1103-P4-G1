"""Domain model for an email prepared through batch ingestion.

Stores extracted content and metadata before AI analysis.

Design:
- SRP: represents and validates prepared email data only.
- Encapsulation: protected attributes and read-only properties.
- Defensive copying: callers cannot modify internal collections
  through constructor arguments, properties or serialised output.

Parsing, hashing, AI analysis, risk scoring, threading and
persistence belong to other components.
"""

from copy import deepcopy
from typing import Any, Dict, List, Optional


class IngestedEmail:
    """Represent one email prepared for the analysis pipeline.

    Sender information is extracted from email headers and is
    not proof of an authenticated sender.

    The file hash must be calculated from the original email bytes
    by the ingestion component.
    """

    def __init__(
        self,
        item_id: str,
        source_path: str,
        file_hash: str,
        body_text: str,
        subject: str = "",
        sender: str = "",
        reply_to: str = "",
        recipients: Optional[List[str]] = None,
        urls: Optional[List[str]] = None,
        attachments: Optional[List[Dict[str, Any]]] = None,
        warnings: Optional[List[str]] = None,
    ) -> None:
        self._item_id = self._validate_required_text(
            item_id, "item_id"
        )
        self._source_path = self._validate_required_text(
            source_path, "source_path"
        )
        self._file_hash = self._validate_file_hash(file_hash)

        self._body_text = self._validate_text(
            body_text, "body_text"
        )
        self._subject = self._validate_text(subject, "subject")
        self._sender = self._validate_text(sender, "sender")
        self._reply_to = self._validate_text(reply_to, "reply_to")

        self._recipients = self._validate_string_list(
            recipients, "recipients"
        )
        self._urls = self._validate_string_list(urls, "urls")
        self._warnings = self._validate_string_list(
            warnings, "warnings"
        )
        self._attachments = self._validate_attachments(attachments)

    # -------------------------------------------------------------------------
    # Validation Helpers
    # -------------------------------------------------------------------------

    @staticmethod
    def _validate_text(value: str, field_name: str) -> str:
        """Validate text while preserving its original content."""
        if not isinstance(value, str):
            raise TypeError(f"{field_name} must be a string.")

        return value

    @staticmethod
    def _validate_required_text(
        value: str,
        field_name: str,
    ) -> str:
        """Validate a required identifier or source reference."""
        if not isinstance(value, str):
            raise TypeError(f"{field_name} must be a string.")

        if not value.strip():
            raise ValueError(f"{field_name} cannot be empty.")

        return value

    @staticmethod
    def _validate_file_hash(file_hash: str) -> str:
        """Validate a supplied SHA-256 hexadecimal digest.

        This validates an existing hash; it does not calculate one.
        """
        if not isinstance(file_hash, str):
            raise TypeError("file_hash must be a string.")

        normalised_hash = file_hash.lower()

        if len(normalised_hash) != 64:
            raise ValueError(
                "file_hash must contain 64 hexadecimal characters."
            )

        for character in normalised_hash:
            if character not in "0123456789abcdef":
                raise ValueError(
                    "file_hash contains a non-hexadecimal character."
                )

        return normalised_hash

    @staticmethod
    def _validate_string_list(
        values: Optional[List[str]],
        field_name: str,
    ) -> List[str]:
        """Validate and copy a collection of extracted strings."""
        if values is None:
            return []

        if not isinstance(values, list):
            raise TypeError(f"{field_name} must be a list.")

        validated_values = []

        for value in values:
            if not isinstance(value, str):
                raise TypeError(
                    f"Every value in {field_name} must be a string."
                )

            if not value.strip():
                raise ValueError(
                    f"{field_name} cannot contain empty strings."
                )

            validated_values.append(value)

        return validated_values

    @staticmethod
    def _validate_attachments(
        attachments: Optional[List[Dict[str, Any]]],
    ) -> List[Dict[str, Any]]:
        """Validate attachment metadata without storing file contents."""
        if attachments is None:
            return []

        if not isinstance(attachments, list):
            raise TypeError("attachments must be a list.")

        required_fields = {
            "filename",
            "content_type",
            "size_bytes",
        }
        validated_attachments = []

        for attachment in attachments:
            if not isinstance(attachment, dict):
                raise TypeError(
                    "Every attachment must be a dictionary."
                )

            if set(attachment) != required_fields:
                raise ValueError(
                    "Each attachment must contain only filename, "
                    "content_type and size_bytes."
                )

            filename = attachment["filename"]
            content_type = attachment["content_type"]
            size_bytes = attachment["size_bytes"]

            if filename is not None:
                if not isinstance(filename, str):
                    raise TypeError(
                        "Attachment filename must be a string or None."
                    )

            if not isinstance(content_type, str):
                raise TypeError(
                    "Attachment content_type must be a string."
                )

            if not content_type.strip():
                raise ValueError(
                    "Attachment content_type cannot be empty."
                )

            if isinstance(size_bytes, bool):
                raise TypeError(
                    "Attachment size_bytes must be an integer."
                )

            if not isinstance(size_bytes, int):
                raise TypeError(
                    "Attachment size_bytes must be an integer."
                )

            if size_bytes < 0:
                raise ValueError(
                    "Attachment size_bytes cannot be negative."
                )

            validated_attachments.append(
                {
                    "filename": filename,
                    "content_type": content_type,
                    "size_bytes": size_bytes,
                }
            )

        return validated_attachments

    # -------------------------------------------------------------------------
    # Encapsulation / Properties
    # -------------------------------------------------------------------------

    @property
    def item_id(self) -> str:
        return self._item_id

    @property
    def source_path(self) -> str:
        return self._source_path

    @property
    def file_hash(self) -> str:
        return self._file_hash

    @property
    def body_text(self) -> str:
        return self._body_text

    @property
    def subject(self) -> str:
        return self._subject

    @property
    def sender(self) -> str:
        return self._sender

    @property
    def reply_to(self) -> str:
        return self._reply_to

    @property
    def recipients(self) -> List[str]:
        return list(self._recipients)

    @property
    def urls(self) -> List[str]:
        return list(self._urls)

    @property
    def attachments(self) -> List[Dict[str, Any]]:
        return deepcopy(self._attachments)

    @property
    def warnings(self) -> List[str]:
        return list(self._warnings)

    # -------------------------------------------------------------------------
    # Serialisation / Deserialisation
    # -------------------------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        """Return an independent, JSON-serialisable dictionary."""
        return {
            "item_id": self._item_id,
            "source_path": self._source_path,
            "file_hash": self._file_hash,
            "body_text": self._body_text,
            "subject": self._subject,
            "sender": self._sender,
            "reply_to": self._reply_to,
            "recipients": self.recipients,
            "urls": self.urls,
            "attachments": self.attachments,
            "warnings": self.warnings,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "IngestedEmail":
        """Reconstruct an email using the same constructor validation."""
        if not isinstance(data, dict):
            raise TypeError("data must be a dictionary.")

        required_fields = (
            "item_id",
            "source_path",
            "file_hash",
            "body_text",
        )

        for field_name in required_fields:
            if field_name not in data:
                raise ValueError(
                    f"Missing required field: {field_name}."
                )

        return cls(
            item_id=data["item_id"],
            source_path=data["source_path"],
            file_hash=data["file_hash"],
            body_text=data["body_text"],
            subject=data.get("subject", ""),
            sender=data.get("sender", ""),
            reply_to=data.get("reply_to", ""),
            recipients=data.get("recipients"),
            urls=data.get("urls"),
            attachments=data.get("attachments"),
            warnings=data.get("warnings"),
        )

    def __repr__(self) -> str:
        return (
            f"IngestedEmail(item_id={self._item_id!r}, "
            f"source_path={self._source_path!r})"
        )

    def __str__(self) -> str:
        subject = self._subject or "(No subject)"
        return f"{self._item_id}: {subject}"