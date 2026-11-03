"""Parse EML bytes into the existing ingestion domain model.

Responsibilities:
- Parse MIME email structure.
- Extract decoded headers and the plain-text body.
- Detect attachment metadata.
- Preserve recoverable parsing warnings.

File discovery, file-size validation, duplicate detection,
AI analysis and threading belong to other components.
"""

from email import policy
from email.parser import BytesParser
from typing import List

from src.models.email_ingestion import IngestedEmail


class EmlParser:
    """Convert validated email bytes into an IngestedEmail."""

    def parse(
        self,
        content: bytes,
        source_path: str,
        item_id: str,
        file_hash: str,
    ) -> IngestedEmail:
        """Parse one email.

        The ingestion service supplies validated bytes and their hash.
        This method performs no filesystem or network operations.
        """
        if not isinstance(content, bytes):
            raise TypeError("content must be bytes.")

        if not content.strip():
            raise ValueError("The email content is empty.")

        message = BytesParser(
            policy=policy.default
        ).parsebytes(content)

        warnings: List[str] = []

        # Reject arbitrary text that has no recognised email headers.
        recognised_headers = (
            "From",
            "To",
            "Subject",
            "Date",
            "Message-ID",
            "MIME-Version",
            "Content-Type",
        )

        has_email_header = False

        for header_name in recognised_headers:
            if message.get(header_name) is not None:
                has_email_header = True
                break

        if not has_email_header:
            raise ValueError(
                "No recognised email headers were found."
            )

        subject = str(message.get("Subject", ""))
        sender = str(message.get("From", ""))
        reply_to = str(message.get("Reply-To", ""))

        recipients = []

        for header in message.get_all("To", []):
            recipients.append(str(header))

        if not subject.strip():
            warnings.append("The email has no subject.")

        if not sender.strip():
            warnings.append("The email has no From header.")

        body_text = ""

        # get_body selects the body and avoids joining alternative copies.
        body_part = message.get_body(
            preferencelist=("plain",)
        )

        if body_part is not None:
            body_text = self._decode_text(body_part, warnings)
        else:
            warnings.append(
                "No plain-text body was found. "
                "HTML extraction is not implemented at this stage."
            )

        attachments = []

        # iter_attachments examines immediate non-body MIME parts.
        for part in message.iter_attachments():
            payload = part.get_payload(decode=True)

            if payload is None:
                warnings.append(
                    "An attachment could not be decoded; "
                    "its metadata was not included."
                )
                continue

            attachments.append(
                {
                    "filename": part.get_filename(),
                    "content_type": part.get_content_type(),
                    "size_bytes": len(payload),
                }
            )

        # Some defects are recorded only after decoding a part.
        for part in message.walk():
            for defect in part.defects:
                warning = (
                    f"Email parsing issue: "
                    f"{type(defect).__name__}."
                )

                if warning not in warnings:
                    warnings.append(warning)

        for header_name, header in message.items():
            for defect in getattr(header, "defects", ()):
                warning = (
                    f"Header parsing issue in {header_name}: "
                    f"{type(defect).__name__}."
                )

                if warning not in warnings:
                    warnings.append(warning)

        return IngestedEmail(
            item_id=item_id,
            source_path=source_path,
            file_hash=file_hash,
            body_text=body_text,
            subject=subject,
            sender=sender,
            reply_to=reply_to,
            recipients=recipients,
            urls=[],
            attachments=attachments,
            warnings=warnings,
        )

    def _decode_text(self, part, warnings: List[str]) -> str:
        """Decode body text, recovering from invalid character encoding."""
        try:
            text = part.get_content()

            if not isinstance(text, str):
                raise ValueError(
                    "The selected body did not decode to text."
                )

            if "\ufffd" in text:
                warnings.append(
                    "The body contains replacement characters; "
                    "some original text may not have decoded correctly."
                )

            return text

        except (LookupError, UnicodeError, ValueError) as error:
            payload = part.get_payload(decode=True)

            if not isinstance(payload, bytes):
                raise ValueError(
                    "The email body could not be decoded."
                ) from error

            warnings.append(
                "The declared body encoding could not be used. "
                "UTF-8 recovery was applied."
            )

            return payload.decode("utf-8", errors="replace")