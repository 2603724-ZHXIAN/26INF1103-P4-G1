from datetime import datetime, timezone
"""SQLite persistence for submissions, AI results and email batches.

SRP: Handles storage and queries; terminal presentation, AI requests and
risk classification remain in their respective managers.

Database failures raise DataManagerError for the coordinator to handle.
None from get_submission_by_id means not found, not database failure.
"""

import json
import logging
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Optional
from uuid import uuid4

from ..models import AssessmentResult, Submission, ThreatEvidence
from ..models.email_ingestion import IngestedEmail

LOGGER = logging.getLogger(__name__)
SCHEMA = """
    CREATE TABLE IF NOT EXISTS email_batch (
        batch_id INTEGER PRIMARY KEY AUTOINCREMENT,
        batch_reference TEXT NOT NULL UNIQUE,
        created_at TEXT NOT NULL,

        processing_status TEXT NOT NULL DEFAULT 'imported' CHECK (
            processing_status IN (
                'imported',
                'processing',
                'completed',
                'partially_failed',
                'failed'
            )
        ),

        total_files INTEGER NOT NULL CHECK (total_files >= 0),
        accepted_count INTEGER NOT NULL CHECK (accepted_count >= 0),
        duplicate_count INTEGER NOT NULL CHECK (duplicate_count >= 0),
        import_failed_count INTEGER NOT NULL CHECK (
            import_failed_count >= 0
        ),

        CHECK (
            total_files =
                accepted_count + duplicate_count + import_failed_count
        )
    );

    CREATE TABLE IF NOT EXISTS email_batch_issue (
        issue_id INTEGER PRIMARY KEY AUTOINCREMENT,
        batch_reference TEXT NOT NULL,
        item_id TEXT NOT NULL,
        source_path TEXT NOT NULL,
        kind TEXT NOT NULL CHECK (kind IN ('duplicate', 'failed')),
        code TEXT NOT NULL,
        message TEXT NOT NULL,
        duplicate_of TEXT,

        FOREIGN KEY (batch_reference)
            REFERENCES email_batch(batch_reference)
            ON DELETE CASCADE
    );


    CREATE TABLE IF NOT EXISTS submission (
        submission_id INTEGER PRIMARY KEY AUTOINCREMENT,
        data_origin TEXT NOT NULL,
        dataset_batch TEXT,
        input_type TEXT NOT NULL CHECK (
            input_type IN ('text', 'url', 'file')
        ),
        input_value TEXT NOT NULL,
        input_hash TEXT NOT NULL,
        file_path TEXT,
        interaction_type TEXT NOT NULL,
        interaction_description TEXT,
        processing_status TEXT NOT NULL DEFAULT 'pending' CHECK (
            processing_status IN (
                'pending',
                'processing',
                'completed',
                'failed'
            )
        ),
        error_message TEXT,
        created_at TEXT NOT NULL,
        completed_at TEXT
    );

        CREATE TABLE IF NOT EXISTS email_metadata (
        submission_id INTEGER PRIMARY KEY,

        item_id TEXT NOT NULL CHECK (length(trim(item_id)) > 0),
        source_path TEXT NOT NULL,
        file_hash TEXT NOT NULL,

        subject TEXT NOT NULL,
        sender TEXT NOT NULL,
        reply_to TEXT NOT NULL,

        recipients TEXT NOT NULL,
        urls TEXT NOT NULL,
        attachments TEXT NOT NULL,
        warnings TEXT NOT NULL,

        FOREIGN KEY (submission_id)
            REFERENCES submission(submission_id)
            ON DELETE CASCADE
    );


    CREATE TABLE IF NOT EXISTS text_analysis (
        text_analysis_id INTEGER PRIMARY KEY AUTOINCREMENT,
        submission_id INTEGER NOT NULL UNIQUE,

        message_classification TEXT NOT NULL CHECK (
            message_classification IN (
                'legitimate',
                'suspicious',
                'scam',
                'uncertain'
            )
        ),
        primary_threat_type TEXT NOT NULL,
        analysis_confidence TEXT NOT NULL CHECK (
            analysis_confidence IN ('low', 'medium', 'high')
        ),

        language TEXT,
        message_type TEXT,
        claimed_entity TEXT,

        requested_actions TEXT NOT NULL,
        possible_intents TEXT NOT NULL,
        extracted_urls TEXT NOT NULL,
        extracted_contacts TEXT NOT NULL,
        suspected_threat_types TEXT NOT NULL,
        other_warning_signs TEXT NOT NULL,
        user_exposure TEXT NOT NULL,

        model_name TEXT NOT NULL,
        raw_gemini_response TEXT NOT NULL,
        created_at TEXT NOT NULL,

        FOREIGN KEY (submission_id)
            REFERENCES submission(submission_id)
            ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS detection_evidence (
        evidence_id INTEGER PRIMARY KEY AUTOINCREMENT,
        submission_id INTEGER NOT NULL,
        evidence_source TEXT NOT NULL CHECK (
            evidence_source IN (
                'gemini',
                'virustotal',
                'business_rule',
                'manual'
            )
        ),
        evidence_type TEXT NOT NULL,
        evidence_name TEXT NOT NULL,
        evidence_value TEXT,
        evidence_excerpt TEXT,
        severity TEXT NOT NULL CHECK (
            severity IN (
                'informational',
                'low',
                'medium',
                'high',
                'critical'
            )
        ),
        created_at TEXT NOT NULL,

        FOREIGN KEY (submission_id)
            REFERENCES submission(submission_id)
            ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS educational_guidance (
        guidance_id INTEGER PRIMARY KEY AUTOINCREMENT,
        submission_id INTEGER NOT NULL UNIQUE,

        threat_explanations TEXT NOT NULL,
        threat_summary TEXT NOT NULL,
        what_it_is TEXT NOT NULL,
        why_dangerous TEXT NOT NULL,
        preventive_steps TEXT NOT NULL,
        recovery_steps TEXT NOT NULL,
        limitations TEXT NOT NULL,

        model_name TEXT NOT NULL,
        created_at TEXT NOT NULL,

        FOREIGN KEY (submission_id)
            REFERENCES submission(submission_id)
            ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS final_assessment (
        assessment_id INTEGER PRIMARY KEY AUTOINCREMENT,
        submission_id INTEGER NOT NULL UNIQUE,

        is_scam INTEGER NOT NULL CHECK (
            is_scam IN (0, 1)
        ),
        risk_score INTEGER CHECK (
            risk_score IS NULL
            OR risk_score BETWEEN 0 AND 100
        ),
        risk_category TEXT NOT NULL CHECK (
            risk_category IN (
                'low',
                'medium',
                'high'
            )
        ),

        message_risk TEXT NOT NULL CHECK (
            message_risk IN ('low', 'medium', 'high')
        ),
        exposure_level TEXT NOT NULL CHECK (
            exposure_level IN ('low', 'medium', 'high')
        ),
        overall_risk TEXT NOT NULL CHECK (
            overall_risk IN ('low', 'medium', 'high')
        ),

        decision TEXT NOT NULL,
        route TEXT NOT NULL,
        priority TEXT NOT NULL CHECK (
            priority IN ('low', 'medium', 'high', 'urgent')
        ),
        recommended_action TEXT NOT NULL,

        risk_reasons TEXT NOT NULL,
        flags TEXT NOT NULL,
        active_indicators TEXT NOT NULL,
        matched_rules TEXT NOT NULL,
        matched_exposures TEXT NOT NULL,
        exposure_reason TEXT NOT NULL DEFAULT '',
        unknown_warning_signs TEXT NOT NULL,
        invalid_indicators TEXT NOT NULL,

        created_at TEXT NOT NULL,

        FOREIGN KEY (submission_id)
            REFERENCES submission(submission_id)
            ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS vt_scan_result (
        vt_result_id INTEGER PRIMARY KEY AUTOINCREMENT,
        submission_id INTEGER NOT NULL UNIQUE,

        resource_type TEXT NOT NULL,
        resource_identifier TEXT NOT NULL,
        malicious_count INTEGER NOT NULL DEFAULT 0,
        suspicious_count INTEGER NOT NULL DEFAULT 0,
        harmless_count INTEGER NOT NULL DEFAULT 0,
        undetected_count INTEGER NOT NULL DEFAULT 0,
        timeout_count INTEGER NOT NULL DEFAULT 0,
        reputation INTEGER,
        raw_vt_response TEXT NOT NULL,
        created_at TEXT NOT NULL,

        FOREIGN KEY (submission_id)
            REFERENCES submission(submission_id)
            ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS interaction_analysis (
        interaction_analysis_id INTEGER PRIMARY KEY AUTOINCREMENT,
        submission_id INTEGER NOT NULL UNIQUE,
        user_exposure TEXT NOT NULL,
        model_name TEXT NOT NULL,
        raw_gemini_response TEXT NOT NULL,
        created_at TEXT NOT NULL,

        FOREIGN KEY (submission_id)
            REFERENCES submission(submission_id)
            ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS technical_ai_analysis (
        technical_ai_id INTEGER PRIMARY KEY AUTOINCREMENT,
        submission_id INTEGER NOT NULL UNIQUE,
        is_malicious INTEGER NOT NULL CHECK (
            is_malicious IN (0, 1)
        ),
        scam_confidence INTEGER NOT NULL CHECK (
            scam_confidence BETWEEN 0 AND 100
        ),
        threat_type TEXT NOT NULL,
        reasoning TEXT NOT NULL,
        model_name TEXT NOT NULL,
        raw_ai_response TEXT NOT NULL,
        created_at TEXT NOT NULL,

        FOREIGN KEY (submission_id)
            REFERENCES submission(submission_id)
            ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_submission_hash
        ON submission(input_hash);

    CREATE INDEX IF NOT EXISTS idx_submission_type
        ON submission(input_type);

    CREATE INDEX IF NOT EXISTS idx_submission_created
        ON submission(created_at);

    CREATE INDEX IF NOT EXISTS idx_text_primary_threat
        ON text_analysis(primary_threat_type);

    CREATE INDEX IF NOT EXISTS idx_text_classification
        ON text_analysis(message_classification);

    CREATE INDEX IF NOT EXISTS idx_text_claimed_entity
        ON text_analysis(claimed_entity);

    CREATE INDEX IF NOT EXISTS idx_evidence_name
        ON detection_evidence(evidence_name);

    CREATE INDEX IF NOT EXISTS idx_evidence_source
        ON detection_evidence(evidence_source);

    CREATE INDEX IF NOT EXISTS idx_assessment_category
        ON final_assessment(risk_category);

    CREATE INDEX IF NOT EXISTS idx_assessment_route
        ON final_assessment(route);

    CREATE INDEX IF NOT EXISTS idx_assessment_priority
        ON final_assessment(priority);
    """


class DataManagerError(Exception):
    """Specialise Exception to identify persistence failures.

    Callers can handle database failures separately from invalid input.
    """

class DataManager:
    """Persist domain objects without exposing SQL to other layers.

    Encapsulation: Protected attributes and helpers hide connection and
    SQL details behind public save, load and query methods.

    Association: Collaborates with Submission, AssessmentResult,
    ThreatEvidence and IngestedEmail without owning their lifecycles.

    SRP: Manages persistence without generating AI responses, calculating
    risk scores or displaying terminal menus.
    """

    def __init__(self, db_path: str = "data/database.db"):
        self._db_path = str(db_path)
        # Keep an in-memory connection alive across repository operations.
        self._memory_connection = None
        if self._db_path == ":memory:":
            self._memory_connection = sqlite3.connect(":memory:")

    @contextmanager
    def _get_connection(self):
        """Manage a connection and transaction for one repository operation.

        Commit on success, roll back on failure and close file connections.
        Retain the owned in-memory connection until close() is called.
        """
        connection = None
        try:
            if self._db_path != ":memory:":
                Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
            connection = self._memory_connection or sqlite3.connect(self._db_path)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            yield connection
            connection.commit()
        except (sqlite3.Error, OSError) as error:
            if connection is not None:
                try:
                    connection.rollback()
                except sqlite3.Error:
                    LOGGER.exception("Database rollback failed.")
            LOGGER.exception("Database operation failed.")
            raise DataManagerError("The database operation could not be completed.") from error
        except Exception:
            if connection is not None:
                connection.rollback()
            raise
        finally:
            if connection is not None and connection is not self._memory_connection:
                connection.close()

    def close(self):
        """Release an optional in-memory database connection."""
        if self._memory_connection is not None:
            self._memory_connection.close()
            self._memory_connection = None

    # Shared validation keeps identifier checks consistent across operations.
    @staticmethod
    def _check_id(submission_id):
        if type(submission_id) is not int or submission_id <= 0:
            raise ValueError("submission_id must be a positive integer.")

    @staticmethod
    def _require_submission(connection, submission_id):
        row = connection.execute(
            "SELECT submission_id FROM submission WHERE submission_id = ?",
            (submission_id,),
        ).fetchone()
        if row is None:
            raise ValueError("No submission exists with that ID.")

    def initialize_database(self) -> None:
        """Create the existing application tables and indexes if absent."""
        with self._get_connection() as connection:
            connection.executescript(SCHEMA)

    def create_email_batch(
        self,
        *,
        total_files: int,
        accepted_count: int,
        duplicate_count: int,
        import_failed_count: int,
    ) -> str:
        """Save import totals and return a unique batch reference."""
        counts = {
            "total_files": total_files,
            "accepted_count": accepted_count,
            "duplicate_count": duplicate_count,
            "import_failed_count": import_failed_count,
        }

        for name, value in counts.items():
            if type(value) is not int or value < 0:
                raise ValueError(
                    f"{name} must be a non-negative integer."
                )

        expected_total = (
            accepted_count
            + duplicate_count
            + import_failed_count
        )

        if total_files != expected_total:
            raise ValueError(
                "total_files must equal accepted_count + "
                "duplicate_count + import_failed_count."
            )

        batch_reference = f"BATCH-{uuid4().hex.upper()}"
        created_at = datetime.now(timezone.utc).isoformat()

        with self._get_connection() as connection:
            connection.execute(
                """
                INSERT INTO email_batch (
                    batch_reference,
                    created_at,
                    processing_status,
                    total_files,
                    accepted_count,
                    duplicate_count,
                    import_failed_count
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    batch_reference,
                    created_at,
                    "imported",
                    total_files,
                    accepted_count,
                    duplicate_count,
                    import_failed_count,
                ),
            )

        return batch_reference

    def save_batch_import_issues(
        self,
        batch_reference: str,
        issues: list[dict],
    ) -> None:
        """Replace a batch's import-issue snapshot atomically."""
        if not isinstance(batch_reference, str):
            raise TypeError("batch_reference must be a string.")

        batch_reference = batch_reference.strip()

        if not batch_reference:
            raise ValueError("batch_reference cannot be empty.")

        if not isinstance(issues, list):
            raise TypeError("issues must be a list.")

        values = []

        for issue in issues:
            if not isinstance(issue, dict):
                raise TypeError("Each issue must be a dictionary.")

            required_fields = (
                "item_id",
                "source_path",
                "kind",
                "code",
                "message",
            )

            for field in required_fields:
                value = issue.get(field)

                if not isinstance(value, str) or not value.strip():
                    raise ValueError(
                        f"Issue {field} must be a non-empty string."
                    )

            if issue["kind"] not in {"duplicate", "failed"}:
                raise ValueError(
                    "Issue kind must be duplicate or failed."
                )

            duplicate_of = issue.get("duplicate_of")

            if duplicate_of is not None:
                if (
                    not isinstance(duplicate_of, str)
                    or not duplicate_of.strip()
                ):
                    raise ValueError(
                        "duplicate_of must be a non-empty string or None."
                    )

            values.append(
                (
                    batch_reference,
                    issue["item_id"],
                    issue["source_path"],
                    issue["kind"],
                    issue["code"],
                    issue["message"],
                    duplicate_of,
                )
            )

        with self._get_connection() as connection:
            batch = connection.execute(
                """
                SELECT batch_reference
                FROM email_batch
                WHERE batch_reference = ?
                """,
                (batch_reference,),
            ).fetchone()

            if batch is None:
                raise ValueError("No batch exists with that reference.")

            connection.execute(
                """
                DELETE FROM email_batch_issue
                WHERE batch_reference = ?
                """,
                (batch_reference,),
            )

            connection.executemany(
                """
                INSERT INTO email_batch_issue (
                    batch_reference,
                    item_id,
                    source_path,
                    kind,
                    code,
                    message,
                    duplicate_of
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                values,
            )

    def get_batch_import_issues(
        self,
        batch_reference: str,
    ) -> list[dict]:
        """Retrieve saved duplicate and failed-import details."""
        if not isinstance(batch_reference, str):
            raise TypeError("batch_reference must be a string.")

        batch_reference = batch_reference.strip()

        if not batch_reference:
            raise ValueError("batch_reference cannot be empty.")

        with self._get_connection() as connection:
            batch = connection.execute(
                """
                SELECT batch_reference
                FROM email_batch
                WHERE batch_reference = ?
                """,
                (batch_reference,),
            ).fetchone()

            if batch is None:
                raise ValueError("No batch exists with that reference.")

            rows = connection.execute(
                """
                SELECT item_id, source_path, kind, code, message, duplicate_of
                FROM email_batch_issue
                WHERE batch_reference = ?
                ORDER BY issue_id
                """,
                (batch_reference,),
            ).fetchall()

        return [dict(row) for row in rows]

    def update_email_batch_status(
        self,
        batch_reference: str,
        status: str,
    ) -> None:
        """Persist a workflow status selected by the coordinator."""
        if not isinstance(batch_reference, str):
            raise TypeError("batch_reference must be a string.")

        batch_reference = batch_reference.strip()

        if not batch_reference:
            raise ValueError("batch_reference cannot be empty.")

        valid_statuses = {
            "imported",
            "processing",
            "completed",
            "partially_failed",
            "failed",
        }

        if not isinstance(status, str) or status not in valid_statuses:
            raise ValueError("Invalid email batch status.")

        with self._get_connection() as connection:
            cursor = connection.execute(
                """
                UPDATE email_batch
                SET processing_status = ?
                WHERE batch_reference = ?
                """,
                (status, batch_reference),
            )

            if cursor.rowcount != 1:
                raise ValueError("No batch exists with that reference.")

    # Persist batch membership using the existing submission field.
    # A database relationship does not itself establish OOP ownership.
    def link_submission_to_batch(
        self,
        batch_reference: str,
        submission_id: int,
    ) -> None:
        """Link a saved text submission to an existing email batch."""
        self._check_id(submission_id)

        if not isinstance(batch_reference, str):
            raise TypeError("batch_reference must be a string.")

        batch_reference = batch_reference.strip()

        if not batch_reference:
            raise ValueError("batch_reference cannot be empty.")

        with self._get_connection() as connection:
            batch = connection.execute(
                """
                SELECT batch_reference
                FROM email_batch
                WHERE batch_reference = ?
                """,
                (batch_reference,),
            ).fetchone()

            if batch is None:
                raise ValueError("No batch exists with that reference.")

            submission = connection.execute(
                """
                SELECT input_type, dataset_batch
                FROM submission
                WHERE submission_id = ?
                """,
                (submission_id,),
            ).fetchone()

            if submission is None:
                raise ValueError("No submission exists with that ID.")

            if submission["input_type"] != "text":
                raise ValueError(
                    "Email batch submissions must use input_type='text'."
                )

            current_batch = submission["dataset_batch"]

            if current_batch not in (None, "", batch_reference):
                raise ValueError(
                    "This submission already belongs to another batch."
                )

            connection.execute(
                """
                UPDATE submission
                SET dataset_batch = ?
                WHERE submission_id = ?
                """,
                (batch_reference, submission_id),
            )

    def get_batch_submissions(
        self,
        batch_reference: str,
    ) -> list[dict]:
        """Retrieve saved submissions belonging to one email batch."""
        if not isinstance(batch_reference, str):
            raise TypeError("batch_reference must be a string.")

        batch_reference = batch_reference.strip()

        if not batch_reference:
            raise ValueError("batch_reference cannot be empty.")

        with self._get_connection() as connection:
            batch = connection.execute(
                """
                SELECT batch_reference
                FROM email_batch
                WHERE batch_reference = ?
                """,
                (batch_reference,),
            ).fetchone()

            if batch is None:
                raise ValueError("No batch exists with that reference.")

            rows = connection.execute(
                """
                SELECT
                    s.*,
                    em.item_id AS email_id
                FROM submission AS s
                LEFT JOIN email_metadata AS em
                    ON s.submission_id = em.submission_id
                WHERE s.dataset_batch = ?
                ORDER BY s.submission_id
                """,
                (batch_reference,),
            ).fetchall()

        return [dict(row) for row in rows]

    def list_email_batches(self) -> list[dict]:
        """List saved batches with counts calculated from saved submissions."""
        with self._get_connection() as connection:
            rows = connection.execute(
                """
                SELECT
                    b.*,
                    COUNT(s.submission_id) AS saved_email_count,

                    SUM(
                        CASE WHEN s.processing_status = 'completed'
                        THEN 1 ELSE 0 END
                    ) AS completed_count,

                    SUM(
                        CASE WHEN s.processing_status = 'failed'
                        THEN 1 ELSE 0 END
                    ) AS analysis_failed_count,

                    SUM(
                        CASE
                            WHEN s.processing_status = 'completed'
                                AND a.overall_risk = 'high'
                            THEN 1 ELSE 0
                        END
                    ) AS high_risk_count,

                    SUM(
                        CASE
                            WHEN s.processing_status = 'completed'
                                AND a.overall_risk = 'medium'
                            THEN 1 ELSE 0
                        END
                    ) AS medium_risk_count,

                    SUM(
                        CASE
                            WHEN s.processing_status = 'completed'
                                AND a.overall_risk = 'low'
                            THEN 1 ELSE 0
                        END
                    ) AS low_risk_count

                FROM email_batch AS b

                LEFT JOIN submission AS s
                    ON s.dataset_batch = b.batch_reference

                LEFT JOIN final_assessment AS a
                    ON a.submission_id = s.submission_id

                GROUP BY b.batch_id

                ORDER BY b.created_at DESC, b.batch_id DESC
                """
            ).fetchall()

        batches = []

        for row in rows:
            batches.append(dict(row))

        return batches

    def _query_batch_emails(
        self,
        batch_reference: str,
        *,
        keyword: str = "",
        item_id: Optional[str] = None,
        high_risk_only: bool = False,
    ) -> list[dict]:
        """Run the shared batch-scoped email query."""
        if not isinstance(batch_reference, str):
            raise TypeError("batch_reference must be a string.")

        batch_reference = batch_reference.strip()

        if not batch_reference:
            raise ValueError("batch_reference cannot be empty.")

        if not isinstance(keyword, str):
            raise TypeError("keyword must be a string.")

        if not isinstance(high_risk_only, bool):
            raise TypeError("high_risk_only must be a boolean.")

        if item_id is not None:
            if not isinstance(item_id, str):
                raise TypeError("item_id must be a string or None.")

            item_id = item_id.strip()

            if not item_id:
                raise ValueError("item_id cannot be empty.")

        conditions = ["s.dataset_batch = ?"]
        parameters = [batch_reference]

        if item_id is not None:
            conditions.append("m.item_id = ?")
            parameters.append(item_id)

        keyword = keyword.strip()

        if keyword:
            # Treat %, _ and backslashes as literal search characters.
            escaped_keyword = keyword.replace("\\", "\\\\")
            escaped_keyword = escaped_keyword.replace("%", "\\%")
            escaped_keyword = escaped_keyword.replace("_", "\\_")

            pattern = f"%{escaped_keyword}%"

            conditions.append(
                r"""(
                    COALESCE(m.subject, '') LIKE ? ESCAPE '\'
                    OR COALESCE(m.sender, '') LIKE ? ESCAPE '\'
                    OR COALESCE(m.source_path, '') LIKE ? ESCAPE '\'
                    OR s.input_value LIKE ? ESCAPE '\'
                )"""
            )

            for _ in range(4):
                parameters.append(pattern)

        if high_risk_only:
            conditions.append("s.processing_status = 'completed'")
            conditions.append("a.overall_risk = ?")
            parameters.append("high")

        query = """
            SELECT
                s.submission_id,
                s.dataset_batch AS batch_reference,
                s.processing_status,
                s.error_message,
                s.created_at,

                m.item_id,
                m.source_path,
                m.subject,
                m.sender,

                a.overall_risk,
                a.message_risk,
                a.exposure_level,
                a.priority

            FROM submission AS s

            LEFT JOIN email_metadata AS m
                ON m.submission_id = s.submission_id

            LEFT JOIN final_assessment AS a
                ON a.submission_id = s.submission_id

            WHERE
        """

        query += " AND ".join(conditions)
        query += " ORDER BY s.submission_id"

        with self._get_connection() as connection:
            batch = connection.execute(
                """
                SELECT batch_reference
                FROM email_batch
                WHERE batch_reference = ?
                """,
                (batch_reference,),
            ).fetchone()

            if batch is None:
                raise ValueError("No batch exists with that reference.")

            rows = connection.execute(
                query,
                parameters,
            ).fetchall()

        emails = []

        for row in rows:
            emails.append(dict(row))

        return emails

    def search_batch_emails(
        self,
        batch_reference: str,
        keyword: str = "",
    ) -> list[dict]:
        """Search one batch by subject, sender, source path or body.

        An empty keyword lists all saved submissions in that batch.
        """
        return self._query_batch_emails(
            batch_reference,
            keyword=keyword,
        )

    def get_batch_high_risk_emails(
        self,
        batch_reference: str,
    ) -> list[dict]:
        """Return completed emails with a saved overall risk of high."""
        return self._query_batch_emails(
            batch_reference,
            high_risk_only=True,
        )

    # Shared retrieval avoids separate education-loading implementations
    # for batch details and historical reports.
    def _load_saved_education(self, submission_id: int) -> dict:
        """Load education from the saved AI response without another API call."""
        self._check_id(submission_id)

        with self._get_connection() as connection:
            row = connection.execute(
                """
                SELECT
                    CASE
                        WHEN s.input_type = 'text'
                        THEN ta.raw_gemini_response
                        ELSE tai.raw_ai_response
                    END AS raw_response
                FROM submission AS s
                LEFT JOIN text_analysis AS ta
                    ON ta.submission_id = s.submission_id
                LEFT JOIN technical_ai_analysis AS tai
                    ON tai.submission_id = s.submission_id
                WHERE s.submission_id = ?
                """,
                (submission_id,),
            ).fetchone()

        if row is None or row["raw_response"] is None:
            return {}

        try:
            ai_result = json.loads(row["raw_response"])
        except (TypeError, ValueError) as error:
            raise DataManagerError(
                "The saved AI response contains invalid JSON."
            ) from error

        if not isinstance(ai_result, dict):
            raise DataManagerError(
                "The saved AI response must be a JSON object."
            )

        education = ai_result.get("education", {})

        if not isinstance(education, dict):
            raise DataManagerError(
                "The saved education must be a JSON object."
            )

        return education
    
    def get_batch_email_details(
        self,
        batch_reference: str,
        item_id: str,
    ) -> Optional[dict]:
        """Load an email's content, metadata, assessment and education.

        The email reference is resolved within the selected batch.
        No new AI request is made.
        """
        matches = self._query_batch_emails(
            batch_reference,
            item_id=item_id,
        )

        if not matches:
            return None

        if len(matches) != 1:
            raise DataManagerError(
                "Multiple emails have the same reference in this batch."
            )

        submission_id = matches[0]["submission_id"]

        submission = self.get_submission_by_id(submission_id)
        metadata = self.get_email_metadata(submission_id)

        if submission is None or metadata is None:
            raise DataManagerError(
                "The saved email details are incomplete."
            )

        submission = self.get_submission_by_id(submission_id)
        metadata = self.get_email_metadata(submission_id)

        if submission is None or metadata is None:
            raise DataManagerError(
                "The saved email details are incomplete."
            )

        education = self._load_saved_education(submission_id)

        return {
            "submission": submission,
            "metadata": metadata,
            "education": education,
        }

    def save_email_metadata(
        self,
        submission_id: int,
        email: IngestedEmail,
    ) -> None:
        """Save parsed metadata for an email already linked to a batch."""
        self._check_id(submission_id)

        if not isinstance(email, IngestedEmail):
            raise TypeError("email must be an IngestedEmail object.")

        metadata = email.to_dict()

        with self._get_connection() as connection:
            submission = connection.execute(
                """
                SELECT s.input_type, s.dataset_batch
                FROM submission AS s
                JOIN email_batch AS b
                    ON b.batch_reference = s.dataset_batch
                WHERE s.submission_id = ?
                """,
                (submission_id,),
            ).fetchone()

            if submission is None:
                raise ValueError(
                    "The submission must exist and belong to an email batch."
                )

            if submission["input_type"] != "text":
                raise ValueError(
                    "Email metadata requires a text submission."
                )

            # EMAIL-001 may appear in different batches, but cannot
            # identify two submissions within the same batch.
            duplicate = connection.execute(
                """
                SELECT m.submission_id
                FROM email_metadata AS m
                JOIN submission AS s
                    ON s.submission_id = m.submission_id
                WHERE s.dataset_batch = ?
                    AND m.item_id = ?
                    AND m.submission_id != ?
                """,
                (
                    submission["dataset_batch"],
                    metadata["item_id"],
                    submission_id,
                ),
            ).fetchone()

            if duplicate is not None:
                raise ValueError(
                    "This email reference already exists in the batch."
                )

            existing = connection.execute(
                """
                SELECT item_id, file_hash, source_path
                FROM email_metadata
                WHERE submission_id = ?
                """,
                (submission_id,),
            ).fetchone()

            if existing is not None:
                identity_fields = (
                    "item_id",
                    "file_hash",
                    "source_path",
                )

                for field in identity_fields:
                    if existing[field] != metadata[field]:
                        raise ValueError(
                            "Saved metadata belongs to a different email."
                        )

            connection.execute(
                """
                INSERT INTO email_metadata (
                    submission_id,
                    item_id,
                    source_path,
                    file_hash,
                    subject,
                    sender,
                    reply_to,
                    recipients,
                    urls,
                    attachments,
                    warnings
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(submission_id) DO UPDATE SET
                    subject = excluded.subject,
                    sender = excluded.sender,
                    reply_to = excluded.reply_to,
                    recipients = excluded.recipients,
                    urls = excluded.urls,
                    attachments = excluded.attachments,
                    warnings = excluded.warnings
                """,
                (
                    submission_id,
                    metadata["item_id"],
                    metadata["source_path"],
                    metadata["file_hash"],
                    metadata["subject"],
                    metadata["sender"],
                    metadata["reply_to"],
                    json.dumps(
                        metadata["recipients"],
                        ensure_ascii=False,
                    ),
                    json.dumps(
                        metadata["urls"],
                        ensure_ascii=False,
                    ),
                    json.dumps(
                        metadata["attachments"],
                        ensure_ascii=False,
                    ),
                    json.dumps(
                        metadata["warnings"],
                        ensure_ascii=False,
                    ),
                ),
            )

    def get_email_metadata(
        self,
        submission_id: int,
    ) -> Optional[dict]:
        """Load email metadata, returning None if it has not been saved."""
        self._check_id(submission_id)

        with self._get_connection() as connection:
            row = connection.execute(
                """
                SELECT *
                FROM email_metadata
                WHERE submission_id = ?
                """,
                (submission_id,),
            ).fetchone()

        if row is None:
            return None

        metadata = dict(row)

        list_fields = (
            "recipients",
            "urls",
            "attachments",
            "warnings",
        )

        for field in list_fields:
            metadata[field] = self._decode_json(
                metadata[field],
                field,
            )

        # Reuse the existing model's validation instead of duplicating
        # its rules for recipients, attachment metadata and file hashes.
        try:
            validation_data = dict(metadata)
            validation_data["body_text"] = ""

            IngestedEmail.from_dict(validation_data)

        except (TypeError, ValueError, KeyError) as error:
            raise DataManagerError(
                "Stored email metadata is invalid."
            ) from error

        return metadata


    def save_submission(self, submission: Submission) -> int:
        """Save a submission while preserving existing batch membership.

        Existing evidence rows are replaced by the object's collection.
        Object IDs are updated only after the transaction commits.
        An empty batch reference on an older object cannot clear a saved link.
        """
        if not isinstance(submission, Submission):
            raise TypeError("submission must be a Submission object.")

        data = submission.to_dict()

        fields = (
            "data_origin",
            "dataset_batch",
            "input_type",
            "input_value",
            "input_hash",
            "file_path",
            "interaction_type",
            "interaction_description",
            "processing_status",
            "error_message",
            "created_at",
            "completed_at",
        )

        requested_batch = data["dataset_batch"]

        if requested_batch is not None:
            if not isinstance(requested_batch, str):
                raise TypeError("dataset_batch must be a string or None.")

            requested_batch = requested_batch.strip() or None

        with self._get_connection() as connection:
            sub_id = submission.submission_id
            saved_batch = None

            if sub_id is not None:
                self._check_id(sub_id)

                existing = connection.execute(
                    """
                    SELECT dataset_batch
                    FROM submission
                    WHERE submission_id = ?
                    """,
                    (sub_id,),
                ).fetchone()

                if existing is None:
                    raise ValueError("No submission exists with that ID.")

                saved_batch = existing["dataset_batch"]

            if saved_batch:
                if requested_batch not in (None, saved_batch):
                    raise ValueError(
                        "This submission already belongs to another batch."
                    )

                # Preserve the database link when an older object has None.
                data["dataset_batch"] = saved_batch
            else:
                data["dataset_batch"] = requested_batch

            effective_batch = data["dataset_batch"]

            # dataset_batch also supports pre-existing dataset labels.
            # Validate email batch references without rejecting those labels.
            is_email_batch = (
                data["data_origin"] == "batch_email"
                or (
                    effective_batch is not None
                    and effective_batch.startswith("BATCH-")
                )
            )

            if effective_batch and is_email_batch:
                batch = connection.execute(
                    """
                    SELECT batch_reference
                    FROM email_batch
                    WHERE batch_reference = ?
                    """,
                    (effective_batch,),
                ).fetchone()

                if batch is None:
                    raise ValueError(
                        "No email batch exists with that reference."
                    )

                if data["input_type"] != "text":
                    raise ValueError(
                        "Email batch submissions must use input_type='text'."
                    )

            values = []

            for name in fields:
                values.append(data[name])

            if sub_id is None:
                cursor = connection.execute(
                    "INSERT INTO submission ("
                    + ", ".join(fields)
                    + ") VALUES ("
                    + ", ".join("?" for _ in fields)
                    + ")",
                    values,
                )

                sub_id = cursor.lastrowid
            else:
                connection.execute(
                    "UPDATE submission SET "
                    + ", ".join(
                        f"{name} = ?" for name in fields
                    )
                    + " WHERE submission_id = ?",
                    values + [sub_id],
                )

            # Save the submission's attached assessment and evidence using
            # the same transaction as its parent record.
            assessment_id = None

            if submission.assessment is not None:
                assessment_id = self._write_assessment(
                    connection,
                    sub_id,
                    submission.assessment,
                    "unknown",
                )

            evidence_ids = self._write_evidences(
                connection,
                sub_id,
                submission.evidences,
            )

        # Update domain objects only after the database transaction commits.
        submission.submission_id = sub_id

        if assessment_id is not None:
            submission.assessment.assessment_id = assessment_id

        for evidence, evidence_id in zip(
            submission.evidences,
            evidence_ids,
        ):
            evidence.evidence_id = evidence_id

        return sub_id

    def _write_assessment(self, connection, submission_id, assessment, model_name):
        data = assessment.to_dict()
        fields = (
            "is_scam", "risk_score", "risk_category", "message_risk",
            "exposure_level", "overall_risk", "decision", "route", "priority",
            "recommended_action", "risk_reasons", "flags", "active_indicators",
            "matched_rules", "matched_exposures", "exposure_reason", "created_at",
        )
        json_fields = {"risk_reasons", "flags", "active_indicators", "matched_rules", "matched_exposures"}
        values = []
        for name in fields:
            value = data[name]
            if name in json_fields:
                value = json.dumps(value, ensure_ascii=False)
            elif name == "is_scam":
                value = int(value)
            values.append(value)
        columns = ("submission_id",) + fields + ("unknown_warning_signs", "invalid_indicators")
        connection.execute(
            "INSERT INTO final_assessment (" + ", ".join(columns) + ") VALUES ("
            + ", ".join("?" for _ in columns) + ") ON CONFLICT(submission_id) DO UPDATE SET "
            + ", ".join(f"{name} = excluded.{name}" for name in fields),
            [submission_id] + values + ["[]", "[]"],
        )
        connection.execute(
            """INSERT INTO educational_guidance (
                submission_id, threat_explanations, threat_summary, what_it_is,
                why_dangerous, preventive_steps, recovery_steps, limitations,
                model_name, created_at
            ) VALUES (?, '[]', ?, ?, '[]', '[]', ?, '[]', ?, ?)
            ON CONFLICT(submission_id) DO UPDATE SET
                threat_summary = excluded.threat_summary,
                what_it_is = excluded.what_it_is,
                recovery_steps = excluded.recovery_steps,
                model_name = CASE WHEN excluded.model_name = 'unknown'
                    THEN educational_guidance.model_name ELSE excluded.model_name END,
                created_at = excluded.created_at""",
            (submission_id, assessment.threat_summary, assessment.what_it_is,
             json.dumps(assessment.recovery_steps, ensure_ascii=False), model_name,
             assessment.created_at),
        )
        return connection.execute(
            "SELECT assessment_id FROM final_assessment WHERE submission_id = ?",
            (submission_id,),
        ).fetchone()["assessment_id"]

    def save_assessment(self, submission_id: int, assessment: AssessmentResult, model_name: str) -> None:
        """Upsert the assessment and its available educational fields together."""
        self._check_id(submission_id)
        if not isinstance(assessment, AssessmentResult):
            raise TypeError("assessment must be an AssessmentResult object.")
        if not isinstance(model_name, str) or not model_name.strip():
            raise ValueError("model_name must be a non-empty string.")
        if assessment.submission_id not in (None, submission_id):
            raise ValueError("Assessment belongs to a different submission.")
        with self._get_connection() as connection:
            self._require_submission(connection, submission_id)
            assessment_id = self._write_assessment(connection, submission_id, assessment, model_name.strip())
        assessment.submission_id = submission_id
        assessment.assessment_id = assessment_id

    def _write_evidences(self, connection, submission_id, evidences):
        for evidence in evidences:
            if not isinstance(evidence, ThreatEvidence):
                raise TypeError("Every evidence must be a ThreatEvidence object.")
            if evidence.submission_id not in (None, submission_id):
                raise ValueError("Evidence belongs to a different submission.")
        connection.execute("DELETE FROM detection_evidence WHERE submission_id = ?", (submission_id,))
        evidence_ids = []
        for evidence in evidences:
            cursor = connection.execute(
                """INSERT INTO detection_evidence (
                    submission_id, evidence_source, evidence_type, evidence_name,
                    evidence_value, evidence_excerpt, severity, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (submission_id, evidence.source, evidence.evidence_type,
                 evidence.evidence_name, evidence.evidence_value,
                 evidence.evidence_excerpt, evidence.severity, evidence.created_at),
            )
            evidence_ids.append(cursor.lastrowid)
        return evidence_ids

    def save_evidences(self, submission_id: int, evidences: list[ThreatEvidence]) -> None:
        """Atomically replace this submission's evidence snapshot.

        Repeated saves do not duplicate evidence. An empty list clears it.
        """
        self._check_id(submission_id)
        if not isinstance(evidences, list):
            raise TypeError("evidences must be a list of ThreatEvidence objects.")
        with self._get_connection() as connection:
            self._require_submission(connection, submission_id)
            ids = self._write_evidences(connection, submission_id, evidences)
        for evidence, evidence_id in zip(evidences, ids):
            evidence.submission_id = submission_id
            evidence.evidence_id = evidence_id

    @staticmethod
    def _decode_json(value, field):
        try:
            decoded = json.loads(value)
            if not isinstance(decoded, list):
                raise ValueError("Expected a JSON list.")
            return decoded
        except (ValueError, TypeError) as error:
            raise DataManagerError(f"Stored {field} is invalid.") from error

    def get_submission_by_id(self, submission_id: int):
        """Reconstruct a submission with its saved assessment and evidence.

        Return None when absent; raise DataManagerError for invalid storage.
        """
        self._check_id(submission_id)
        with self._get_connection() as connection:
            row = connection.execute("SELECT * FROM submission WHERE submission_id = ?", (submission_id,)).fetchone()
            if row is None:
                return None
            data = dict(row)
            result = connection.execute("SELECT * FROM final_assessment WHERE submission_id = ?", (submission_id,)).fetchone()
            guidance = connection.execute("SELECT * FROM educational_guidance WHERE submission_id = ?", (submission_id,)).fetchone()
            evidences = connection.execute("SELECT * FROM detection_evidence WHERE submission_id = ? ORDER BY evidence_id", (submission_id,)).fetchall()
            if result is not None:
                assessment = dict(result)
                assessment["is_scam"] = bool(assessment["is_scam"])
                for field in ("risk_reasons", "flags", "active_indicators", "matched_rules", "matched_exposures"):
                    assessment[field] = self._decode_json(assessment[field], field)
                if guidance is not None:
                    assessment.update(
                        recovery_steps=self._decode_json(guidance["recovery_steps"], "recovery_steps"),
                        threat_summary=guidance["threat_summary"], what_it_is=guidance["what_it_is"],
                    )
                data["assessment"] = assessment
            data["evidences"] = [dict(evidence) for evidence in evidences]
            try:
                return Submission.from_dict(data)
            except (ValueError, TypeError, KeyError) as error:
                raise DataManagerError("Stored submission could not be reconstructed.") from error

    def query_by_risk(self, risk_category: str) -> list[dict]:
        """Return historical rows filtered by a validated risk category."""
        if not isinstance(risk_category, str):
            raise ValueError("risk_category must be low, medium or high.")
        risk_category = risk_category.strip().lower()
        if risk_category not in AssessmentResult.VALID_RISK_LEVELS:
            raise ValueError("risk_category must be low, medium or high.")
        with self._get_connection() as connection:
            rows = connection.execute(
                """SELECT s.*, a.risk_category, a.overall_risk, a.priority, a.route
                FROM submission s JOIN final_assessment a USING (submission_id)
                WHERE a.risk_category = ? ORDER BY s.created_at DESC, s.submission_id DESC""",
                (risk_category,),
            ).fetchall()
        return [dict(row) for row in rows]

    def search_by_keyword(self, keyword: str) -> list[dict]:
        """Search literal text/URL fragments; empty text returns all records."""
        if not isinstance(keyword, str):
            raise TypeError("keyword must be a string.")
        escaped = keyword.strip().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        with self._get_connection() as connection:
            rows = connection.execute(
                """SELECT s.*, a.risk_category, a.overall_risk, a.priority, a.route
                FROM submission s LEFT JOIN final_assessment a USING (submission_id)
                WHERE s.input_value LIKE ? ESCAPE '\\'
                ORDER BY s.created_at DESC, s.submission_id DESC""",
                (f"%{escaped}%",),
            ).fetchall()
        return [dict(row) for row in rows]

    def search_records(self, keyword: str) -> list[dict]:
        """Compatibility alias for search_by_keyword."""
        return self.search_by_keyword(keyword)

    def get_records_by_risk_level(self, risk_category: str) -> list[dict]:
        """Compatibility alias for query_by_risk."""
        return self.query_by_risk(risk_category)

    # One row per analysed submission with its threat type, whether it was
    # analysed as text or as a URL/file. Fixed SQL text (no user input).
    _ALL_THREAT_TYPES_SQL = """
        SELECT submission_id, primary_threat_type FROM text_analysis
        UNION ALL
        SELECT submission_id, threat_type AS primary_threat_type
        FROM technical_ai_analysis"""

    def get_top_threat_types(self, *args, **kwargs) -> list[dict]:
        limit = kwargs.get('limit', 10)
        for arg in args:
            if isinstance(arg, int):
                limit = arg
        """Return the most common threat types across text, URL and file analyses.

        Text verdicts live in text_analysis.primary_threat_type and URL/file
        verdicts in technical_ai_analysis.threat_type, so both are counted.
        """
        with self._get_connection() as connection:
            rows = connection.execute(
                f"""SELECT primary_threat_type, COUNT(*) AS total
                FROM ({self._ALL_THREAT_TYPES_SQL})
                GROUP BY primary_threat_type
                ORDER BY total DESC, primary_threat_type
                LIMIT ?""",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_risk_category_counts(self) -> list[dict]:
        """Return incident distribution counts by risk category."""
        with self._get_connection() as connection:
            rows = connection.execute(
                """SELECT risk_category, COUNT(*) AS total
                FROM final_assessment
                GROUP BY risk_category
                ORDER BY total DESC"""
            ).fetchall()
        return [dict(row) for row in rows]

    def get_incidents_by_threat_type(self, *args, **kwargs) -> list[dict]:
        threat_type = kwargs.get('threat_type')
        limit = kwargs.get('limit', 10)
        positional = [a for a in args]
        if threat_type is None:
            if len(positional) >= 2 and isinstance(positional[0], str) and ('/' in positional[0] or '\\' in positional[0] or positional[0].endswith('.db')):
                threat_type = positional[1]
                if len(positional) >= 3 and isinstance(positional[2], int):
                    limit = positional[2]
            elif positional:
                threat_type = positional[0]
                if len(positional) >= 2 and isinstance(positional[1], int):
                    limit = positional[1]
            else:
                threat_type = ''
        """Return the latest text, URL or file incidents of one threat type."""
        with self._get_connection() as connection:
            rows = connection.execute(
                f"""SELECT
                    s.submission_id,
                    s.input_type,
                    s.input_value,
                    s.created_at,
                    ta.primary_threat_type,
                    fa.risk_category
                FROM submission AS s
                JOIN ({self._ALL_THREAT_TYPES_SQL}) AS ta
                    ON ta.submission_id = s.submission_id
                LEFT JOIN final_assessment AS fa ON fa.submission_id = s.submission_id
                WHERE ta.primary_threat_type = ?
                ORDER BY s.created_at DESC
                LIMIT ?""",
                (threat_type, limit),
            ).fetchall()
        return [dict(row) for row in rows]


    def save_text_analysis(self, submission_id: int, ai_data: dict, model_name: str) -> None:
        """Persist structured AI semantic indicators to the text_analysis table."""
        self._check_id(submission_id)
        if not isinstance(ai_data, dict):
            return
        now = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as connection:
            self._require_submission(connection, submission_id)
            connection.execute(
                """INSERT INTO text_analysis (
                    submission_id, message_classification, primary_threat_type,
                    analysis_confidence, language, message_type, claimed_entity,
                    requested_actions, possible_intents, extracted_urls,
                    extracted_contacts, suspected_threat_types, other_warning_signs,
                    user_exposure, model_name, raw_gemini_response, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(submission_id) DO UPDATE SET
                    message_classification = excluded.message_classification,
                    primary_threat_type = excluded.primary_threat_type,
                    analysis_confidence = excluded.analysis_confidence,
                    language = excluded.language,
                    message_type = excluded.message_type,
                    claimed_entity = excluded.claimed_entity,
                    requested_actions = excluded.requested_actions,
                    possible_intents = excluded.possible_intents,
                    extracted_urls = excluded.extracted_urls,
                    extracted_contacts = excluded.extracted_contacts,
                    suspected_threat_types = excluded.suspected_threat_types,
                    other_warning_signs = excluded.other_warning_signs,
                    user_exposure = excluded.user_exposure,
                    model_name = excluded.model_name,
                    raw_gemini_response = excluded.raw_gemini_response""",
                (
                    submission_id,
                    ai_data.get("message_classification", "uncertain"),
                    ai_data.get("primary_threat_type", "unknown"),
                    ai_data.get("analysis_confidence", "medium"),
                    ai_data.get("language", "English"),
                    ai_data.get("message_type", "unknown"),
                    ai_data.get("claimed_entity", ""),
                    json.dumps(ai_data.get("requested_actions", []), ensure_ascii=False),
                    json.dumps(ai_data.get("possible_intents", []), ensure_ascii=False),
                    json.dumps(ai_data.get("extracted_urls", []), ensure_ascii=False),
                    json.dumps(ai_data.get("extracted_contacts", []), ensure_ascii=False),
                    json.dumps(ai_data.get("suspected_threat_types", []), ensure_ascii=False),
                    json.dumps(ai_data.get("other_warning_signs", []), ensure_ascii=False),
                    json.dumps(ai_data.get("user_exposure", {}), ensure_ascii=False),
                    str(model_name),
                    json.dumps(ai_data, ensure_ascii=False),
                    now,
                ),
            )

    def save_vt_scan_result(self, submission_id: int, vt_result: dict) -> None:
        """Persist VirusTotal scan telemetry to the vt_scan_result table."""
        self._check_id(submission_id)
        if not isinstance(vt_result, dict):
            return
        parsed = vt_result.get("parsed_result", vt_result)
        stats = parsed.get("detection_stats", {})
        now = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as connection:
            self._require_submission(connection, submission_id)
            connection.execute(
                """INSERT INTO vt_scan_result (
                    submission_id, resource_type, resource_identifier,
                    malicious_count, suspicious_count, harmless_count,
                    undetected_count, timeout_count, reputation,
                    raw_vt_response, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(submission_id) DO UPDATE SET
                    resource_type = excluded.resource_type,
                    resource_identifier = excluded.resource_identifier,
                    malicious_count = excluded.malicious_count,
                    suspicious_count = excluded.suspicious_count,
                    harmless_count = excluded.harmless_count,
                    undetected_count = excluded.undetected_count,
                    timeout_count = excluded.timeout_count,
                    reputation = excluded.reputation,
                    raw_vt_response = excluded.raw_vt_response""",
                (
                    submission_id,
                    parsed.get("resource_type", "resource"),
                    parsed.get("resource_identifier") or vt_result.get("resource_identifier", "unknown"),
                    stats.get("malicious", 0),
                    stats.get("suspicious", 0),
                    stats.get("harmless", 0),
                    stats.get("undetected", 0),
                    stats.get("timeout", 0),
                    parsed.get("reputation", 0),
                    json.dumps(vt_result, ensure_ascii=False),
                    now,
                ),
            )

    def save_technical_analysis(self, submission_id: int, ai_data: dict, model_name: str) -> None:
        """Persist the AI's URL/file verdict to the technical_ai_analysis table."""
        self._check_id(submission_id)
        if not isinstance(ai_data, dict):
            raise TypeError("ai_data must be a dictionary.")
        now = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as connection:
            self._require_submission(connection, submission_id)
            connection.execute(
                """INSERT INTO technical_ai_analysis (
                    submission_id, is_malicious, scam_confidence, threat_type,
                    reasoning, model_name, raw_ai_response, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(submission_id) DO UPDATE SET
                    is_malicious = excluded.is_malicious,
                    scam_confidence = excluded.scam_confidence,
                    threat_type = excluded.threat_type,
                    reasoning = excluded.reasoning,
                    model_name = excluded.model_name,
                    raw_ai_response = excluded.raw_ai_response""",
                (
                    submission_id,
                    int(bool(ai_data.get("is_malicious", False))),
                    ai_data.get("scam_confidence", 0),
                    str(ai_data.get("threat_type", "unknown")),
                    str(ai_data.get("reasoning", "")),
                    str(model_name),
                    json.dumps(ai_data, ensure_ascii=False),
                    now,
                ),
            )

    def get_submission_report(self, submission_id: int) -> Optional[dict]:
        """Return a formatted report dictionary for an incident."""
        self._check_id(submission_id)
        with self._get_connection() as connection:
            row = connection.execute(
                """SELECT
                    s.*,
                    ta.message_classification,
                    ta.primary_threat_type,
                    ta.analysis_confidence,
                    ta.language,
                    ta.message_type,
                    ta.claimed_entity,
                    ta.requested_actions,
                    ta.possible_intents,
                    ta.extracted_urls,
                    ta.extracted_contacts,
                    ta.suspected_threat_types,
                    ta.other_warning_signs,
                    ta.user_exposure,
                    eg.threat_explanations,
                    eg.threat_summary,
                    eg.what_it_is,
                    eg.why_dangerous,
                    eg.preventive_steps,
                    eg.recovery_steps,
                    eg.limitations,
                    fa.is_scam,
                    fa.risk_score,
                    fa.risk_category,
                    fa.message_risk,
                    fa.exposure_level,
                    fa.overall_risk,
                    fa.decision,
                    fa.route,
                    fa.priority,
                    fa.recommended_action,
                    fa.risk_reasons,
                    fa.flags,
                    fa.active_indicators,
                    fa.matched_rules,
                    fa.matched_exposures,
                    fa.exposure_reason,
                    tai.is_malicious AS ai_is_malicious,
                    tai.scam_confidence AS ai_scam_confidence,
                    tai.threat_type AS ai_threat_type,
                    tai.reasoning AS ai_reasoning
                FROM submission AS s
                LEFT JOIN text_analysis AS ta ON ta.submission_id = s.submission_id
                LEFT JOIN educational_guidance AS eg ON eg.submission_id = s.submission_id
                LEFT JOIN final_assessment AS fa ON fa.submission_id = s.submission_id
                LEFT JOIN technical_ai_analysis AS tai ON tai.submission_id = s.submission_id
                WHERE s.submission_id = ?""",
                (submission_id,),
            ).fetchone()

        if row is None:
            return None

        report = dict(row)
        json_fields = [
            "requested_actions", "possible_intents", "extracted_urls",
            "extracted_contacts", "suspected_threat_types", "other_warning_signs",
            "user_exposure", "threat_explanations", "why_dangerous", "preventive_steps",
            "recovery_steps", "limitations", "risk_reasons", "flags", "active_indicators",
            "matched_rules", "matched_exposures",
        ]
        for field in json_fields:
            value = report.get(field)

            if value is None:
                continue

            try:
                decoded = json.loads(value)
            except (ValueError, TypeError) as error:
                raise DataManagerError(
                    f"Stored report field '{field}' contains invalid JSON."
                ) from error

            expected_type = dict if field == "user_exposure" else list

            if not isinstance(decoded, expected_type):
                raise DataManagerError(
                    f"Stored report field '{field}' has an invalid type."
                )

            report[field] = decoded

        education = self._load_saved_education(submission_id)

        education_fields = {
            "threat_explanations": list,
            "threat_summary": str,
            "what_it_is": str,
            "why_dangerous": list,
            "preventive_steps": list,
            "recovery_steps": list,
            "limitations": list,
            "recovery_by_action": dict,
        }

        for field, expected_type in education_fields.items():
            if field not in education:
                continue

            value = education[field]

            if not isinstance(value, expected_type):
                raise DataManagerError(
                    f"Saved education field '{field}' has an invalid type."
                )

            report[field] = value

        return report