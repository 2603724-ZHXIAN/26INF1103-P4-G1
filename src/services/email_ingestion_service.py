"""Coordinate batch email ingestion.

Responsibilities:
- Discover explicitly selected files or emails in a folder.
- Enforce batch and file-size limits.
- Read email bytes with a bounded read.
- Detect exact duplicates within the current batch.
- Delegate email parsing to EmlParser.
- Collect accepted emails and per-file issues.

Terminal interaction, analysis, threading and persistence remain
outside this service.
"""

import hashlib
import os
from pathlib import Path
from typing import Any, Dict, List

from src.services.eml_parser import EmlParser


class EmailIngestionService:
    """Prepare email files through an injected parser."""

    def __init__(
        self,
        parser: EmlParser,
        max_files: int = 100,
        max_file_bytes: int = 10 * 1024 * 1024,
    ) -> None:
        if not callable(getattr(parser, "parse", None)):
            raise TypeError("parser must provide a parse method.")

        for field_name, value in (
            ("max_files", max_files),
            ("max_file_bytes", max_file_bytes),
        ):
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{field_name} must be an integer.")

            if value <= 0:
                raise ValueError(f"{field_name} must be positive.")

        self._parser = parser
        self._max_files = max_files
        self._max_file_bytes = max_file_bytes

    # -------------------------------------------------------------------------
    # Encapsulation / Properties
    # -------------------------------------------------------------------------

    @property
    def max_files(self) -> int:
        return self._max_files

    @property
    def max_file_bytes(self) -> int:
        return self._max_file_bytes

    # -------------------------------------------------------------------------
    # Public Ingestion Operation
    # -------------------------------------------------------------------------

    def ingest_paths(
        self,
        paths: List[str],
    ) -> Dict[str, Any]:
        """Prepare selected files and/or folders.

        Folder discovery is non-recursive. Unrelated files inside
        folders are ignored. Explicitly selected unsupported files
        are returned as issues.

        References are stable within this returned result. A future
        batch-history component can prefix them with its batch ID.

        Raises:
            TypeError: Input or configuration types are invalid.
            ValueError: Paths are empty or the candidate limit is exceeded.
        """
        if not isinstance(paths, list):
            raise TypeError("paths must be a list of strings.")

        if not paths:
            raise ValueError("Select at least one file or folder.")

        for value in paths:
            if not isinstance(value, str):
                raise TypeError("Every path must be a string.")

            if not value.strip():
                raise ValueError("Paths cannot contain empty values.")

        # Discovery completes before processing starts. Exceeding the
        # candidate limit rejects the operation instead of silently
        # returning a partially processed batch.
        candidates, discovery_issues = self._discover(paths)

        accepted = []
        issues = list(discovery_issues)

        # Local state ensures separate batches do not share duplicates.
        accepted_hashes = {}

        for index, path in enumerate(candidates, start=1):
            item_id = f"EMAIL-{index:03d}"

            try:
                content = self._read_email(path)

            except OSError as error:
                issues.append(
                    self._make_issue(
                        item_id,
                        path,
                        "failed",
                        "file_access_error",
                        f"Cannot read file: {error}",
                    )
                )
                continue

            except ValueError as error:
                issues.append(
                    self._make_issue(
                        item_id,
                        path,
                        "failed",
                        "invalid_file",
                        str(error),
                    )
                )
                continue

            # Hash the bytes actually passed to the parser.
            # Text hashes from Submission are not equivalent.
            file_hash = hashlib.sha256(content).hexdigest()

            if file_hash in accepted_hashes:
                original_id = accepted_hashes[file_hash]

                issues.append(
                    self._make_issue(
                        item_id,
                        path,
                        "duplicate",
                        "duplicate_file",
                        f"Exact duplicate of {original_id}.",
                        duplicate_of=original_id,
                    )
                )
                continue

            try:
                email = self._parser.parse(
                    content=content,
                    source_path=str(path),
                    item_id=item_id,
                    file_hash=file_hash,
                )

            except (ValueError, UnicodeError, RecursionError) as error:
                issues.append(
                    self._make_issue(
                        item_id,
                        path,
                        "failed",
                        "parse_error",
                        f"Email could not be prepared: {error}",
                    )
                )
                continue

            # This initial analysis policy requires a readable body.
            # Attachment-only records must not accidentally be sent
            # through the existing text-analysis pipeline.
            if not email.body_text.strip():
                issues.append(
                    self._make_issue(
                        item_id,
                        path,
                        "failed",
                        "no_readable_body",
                        "No readable email body was extracted.",
                    )
                )
                continue

            accepted.append(email)
            accepted_hashes[file_hash] = item_id

        return {
            "accepted": accepted,
            "issues": issues,
        }

    # -------------------------------------------------------------------------
    # Candidate Discovery
    # -------------------------------------------------------------------------

    def _discover(self, paths: List[str]):
        """Discover candidates without following symbolic links."""
        candidates = []
        issues = []

        for source_index, value in enumerate(paths, start=1):
            path = Path(value)
            source_id = f"SOURCE-{source_index:03d}"

            try:
                if path.is_symlink():
                    raise ValueError(
                        "Symbolic-link sources are not supported."
                    )

                if not path.is_dir():
                    self._append_candidate(candidates, path)
                    continue

                folder_candidates = []

                # scandir avoids loading every unrelated file into memory.
                # Subfolders are not traversed.
                with os.scandir(path) as entries:
                    for entry in entries:
                        candidate = Path(entry.path)

                        if candidate.suffix.lower() != ".eml":
                            continue

                        if entry.is_dir(follow_symlinks=False):
                            continue

                        folder_candidates.append(candidate)

                        if (
                            len(candidates) + len(folder_candidates)
                            > self._max_files
                        ):
                            raise OverflowError(
                                "Too many email candidates."
                            )

                folder_candidates = sorted(folder_candidates)

                for candidate in folder_candidates:
                    self._append_candidate(candidates, candidate)

            except (OSError, ValueError) as error:
                issues.append(
                    self._make_issue(
                        source_id,
                        path,
                        "failed",
                        "source_access_error",
                        str(error),
                    )
                )

            except OverflowError as error:
                raise ValueError(
                    f"Batch exceeds the limit of {self._max_files} "
                    "file candidates. Select a smaller batch."
                ) from error

        return candidates, issues

    def _append_candidate(self, candidates, path: Path) -> None:
        if len(candidates) >= self._max_files:
            raise OverflowError("Too many email candidates.")

        candidates.append(path)

    # -------------------------------------------------------------------------
    # Bounded File Reading
    # -------------------------------------------------------------------------

    def _read_email(self, path: Path) -> bytes:
        """Read a supported regular file within the configured limit."""
        if path.is_symlink():
            raise ValueError("Symbolic-link files are not supported.")

        if path.suffix.lower() != ".eml":
            raise ValueError("Only .eml files are supported.")

        if not path.is_file():
            raise ValueError(
                "The selected path is not an existing regular file."
            )

        with path.open("rb") as email_file:
            content = email_file.read(self._max_file_bytes + 1)

        if len(content) > self._max_file_bytes:
            raise ValueError(
                f"File exceeds the {self._max_file_bytes}-byte limit."
            )

        if not content.strip():
            raise ValueError("The selected email file is empty.")

        return content

    # -------------------------------------------------------------------------
    # Outcome Formatting
    # -------------------------------------------------------------------------

    @staticmethod
    def _make_issue(
        item_id: str,
        path: Path,
        kind: str,
        code: str,
        message: str,
        duplicate_of=None,
    ) -> Dict[str, Any]:
        """Return a consistent issue structure for terminal/report use."""
        return {
            "item_id": item_id,
            "source_path": str(path),
            "kind": kind,
            "code": code,
            "message": message,
            "duplicate_of": duplicate_of,
        }