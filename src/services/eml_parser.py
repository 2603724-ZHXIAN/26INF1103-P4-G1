"""Parse EML bytes into the existing ingestion domain model.

Responsibilities:
- Parse MIME email structure and decoded headers.
- Prefer usable plain text, with HTML-to-text fallback.
- Extract HTTP(S) URLs from body text and HTML hyperlinks.
- Detect attachment metadata.
- Preserve recoverable parsing and decoding warnings.

File discovery, bounded reading, duplicate detection, AI analysis,
risk assessment, persistence and threading belong to other components.
"""

import re

from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from typing import List
from urllib.parse import urlsplit

from src.models.email_ingestion import IngestedEmail
from src.services.html_email_parser import HtmlEmailParser


class EmlParser:
    """Convert validated email bytes into an IngestedEmail.

    Collaborates with HtmlEmailParser for HTML content extraction.
    This parser performs no filesystem or network operations.
    """

    def parse(
        self,
        content: bytes,
        source_path: str,
        item_id: str,
        file_hash: str,
    ) -> IngestedEmail:
        """Parse one email and return its prepared content.

        Args:
            content: Email bytes supplied by the ingestion service.
            source_path: Original email file reference.
            item_id: Stable reference assigned to this batch item.
            file_hash: SHA-256 digest calculated from the original bytes.

        Raises:
            TypeError: Content or model fields have invalid types.
            ValueError: Content is empty, lacks recognised email headers,
                or cannot be prepared successfully.

        The supplied hash is validated by IngestedEmail. It is not
        recalculated here.
        """
        if not isinstance(content, bytes):
            raise TypeError("content must be bytes.")

        if not content.strip():
            raise ValueError("The email content is empty.")

        message = BytesParser(
            policy=policy.default
        ).parsebytes(content)

        warnings: List[str] = []

        # This is a basic eligibility check, not proof that the email
        # is valid, authentic or safe.
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

        # The default email policy decodes encoded header values.
        # These values remain unverified claims from the email.
        subject = str(message.get("Subject", ""))
        sender = str(message.get("From", ""))
        reply_to = str(message.get("Reply-To", ""))

        recipients = []

        for header in message.get_all("To", []):
            header_value = str(header)

            if header_value.strip():
                recipients.append(header_value)

        if not subject.strip():
            warnings.append("The email has no subject.")

        if not sender.strip():
            warnings.append("The email has no From header.")

        # Select alternative body representations independently.
        # get_body avoids treating ordinary attachment parts as the body.
        plain_part = message.get_body(
            preferencelist=("plain",)
        )
        html_part = message.get_body(
            preferencelist=("html",)
        )

        plain_text = ""
        html_text = ""
        urls: List[str] = []

        if plain_part is not None:
            plain_text = self._decode_text(
                plain_part,
                warnings,
            )

        if html_part is not None:
            html_content = self._decode_text(
                html_part,
                warnings,
            )

            # A fresh helper prevents data from a previous email
            # leaking into this email's extracted text or links.
            html_parser = HtmlEmailParser()
            html_parser.feed(html_content)
            html_parser.close()

            html_text = html_parser.text

            # Collect actual hyperlink destinations even when the
            # plain-text alternative is selected for analysis.
            for link in html_parser.links:
                if link not in urls:
                    urls.append(link)

        # Keep one body representation so multipart alternatives
        # do not duplicate the message supplied to AI.
        if plain_text.strip():
            body_text = plain_text

        elif html_text.strip():
            body_text = html_text
            warnings.append(
                "The body was extracted from HTML. "
                "Original visual formatting is not preserved."
            )

        else:
            body_text = ""
            warnings.append(
                "No usable message body was extracted."
            )

        # Inspect visible URLs in both alternatives without combining
        # the alternatives into the selected body.
        for text in (plain_text, html_text):
            for link in self._extract_text_urls(text):
                if link not in urls:
                    urls.append(link)

        attachments = []

        # This inspects immediate non-body MIME parts. More complex
        # nested attachments require additional handling and tests.
        for part in message.iter_attachments():
            payload = part.get_payload(decode=True)

            # Container parts, including some attached emails, do not
            # provide a directly decoded byte payload.
            if not isinstance(payload, bytes):
                warnings.append(
                    "A non-body MIME part could not be decoded "
                    "directly; its attachment metadata was not included."
                )
                continue

            attachments.append(
                {
                    "filename": part.get_filename(),
                    "content_type": part.get_content_type(),
                    "size_bytes": len(payload),
                }
            )

        # Collect defects after body and attachment decoding because
        # decoding can add defects to MIME parts.
        for part in message.walk():
            for defect in part.defects:
                warning = (
                    "Email parsing issue: "
                    f"{type(defect).__name__}."
                )

                if warning not in warnings:
                    warnings.append(warning)

            # Include header defects from nested MIME parts as well
            # as the top-level email.
            for header_name, header in part.items():
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
            urls=urls,
            attachments=attachments,
            warnings=warnings,
        )

    # -------------------------------------------------------------------------
    # Character Decoding
    # -------------------------------------------------------------------------

    def _decode_text(
        self,
        part: EmailMessage,
        warnings: List[str],
    ) -> str:
        """Decode a text MIME part using its declared encoding.

        If the declared encoding cannot be used, recover with UTF-8
        replacement decoding and record the limitation.
        """
        try:
            text = part.get_content()

            if not isinstance(text, str):
                raise ValueError(
                    "The selected body did not decode to text."
                )

            if "\ufffd" in text:
                warning = (
                    "The body contains replacement characters; "
                    "some original text may not have decoded correctly."
                )

                if warning not in warnings:
                    warnings.append(warning)

            return text

        except (LookupError, UnicodeError, ValueError) as error:
            payload = part.get_payload(decode=True)

            if not isinstance(payload, bytes):
                raise ValueError(
                    "The email body could not be decoded."
                ) from error

            warning = (
                "The declared body encoding could not be used. "
                "UTF-8 recovery was applied."
            )

            if warning not in warnings:
                warnings.append(warning)

            return payload.decode(
                "utf-8",
                errors="replace",
            )

    # -------------------------------------------------------------------------
    # URL Extraction
    # -------------------------------------------------------------------------

    @staticmethod
    def _extract_text_urls(text: str) -> List[str]:
        """Extract explicit HTTP(S) URLs without visiting them.

        Uses conservative syntax checks and removes common trailing
        sentence punctuation. Extraction is heuristic, not a security
        verdict or a complete URL validator.

        Bare domains, relative links and obfuscated URLs are outside
        this method's scope.
        """
        matches = re.findall(
            r"""https?://[^\s<>"']+""",
            text,
            flags=re.IGNORECASE,
        )

        urls: List[str] = []

        for match in matches:
            link = match.rstrip(".,;!?")

            # Remove unmatched closing parentheses while preserving
            # balanced parentheses that may belong to a URL.
            while (
                link.endswith(")")
                and link.count(")") > link.count("(")
            ):
                link = link[:-1]

            try:
                parsed = urlsplit(link)

                if parsed.scheme.lower() not in {"http", "https"}:
                    continue

                if not parsed.hostname:
                    continue

            except ValueError:
                continue

            # Preserve the extracted spelling and query parameters.
            # Deduplication here is by exact URL string.
            if link not in urls:
                urls.append(link)

        return urls