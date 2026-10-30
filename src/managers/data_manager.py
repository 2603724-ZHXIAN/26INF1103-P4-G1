"""SQLite repository for the Phase 2 domain models.

Database failures raise DataManagerError for the coordinator to handle.
None from get_submission_by_id means not found, not database failure.
"""

import json
import logging
import sqlite3
from contextlib import contextmanager
from pathlib import Path

from ..models import AssessmentResult, Submission, ThreatEvidence

LOGGER = logging.getLogger(__name__)
SCHEMA = """
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
    """A persistence operation could not be completed."""


class DataManager:
    """Persist domain objects without exposing SQL to other layers."""

    def __init__(self, db_path: str = "data/database.db"):
        self._db_path = str(db_path)
        # Keep an in-memory connection alive across repository operations.
        self._memory_connection = None
        if self._db_path == ":memory:":
            self._memory_connection = sqlite3.connect(":memory:")

    @contextmanager
    def _get_connection(self):
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

    def save_submission(self, submission: Submission) -> int:
        """Insert/update a submission and its attached children atomically.

        A previously assigned ID must identify an existing record.
        Existing evidence rows are replaced by the object's evidence collection.
        Object IDs are updated only after the transaction commits successfully.
        """
        if not isinstance(submission, Submission):
            raise TypeError("submission must be a Submission object.")
        data = submission.to_dict()
        fields = (
            "data_origin", "dataset_batch", "input_type", "input_value",
            "input_hash", "file_path", "interaction_type", "interaction_description",
            "processing_status", "error_message", "created_at", "completed_at",
        )
        with self._get_connection() as connection:
            sub_id = submission.submission_id
            values = [data[name] for name in fields]
            if sub_id is None:
                cursor = connection.execute(
                    "INSERT INTO submission (" + ", ".join(fields) + ") VALUES ("
                    + ", ".join("?" for _ in fields) + ")", values,
                )
                sub_id = cursor.lastrowid
            else:
                self._check_id(sub_id)
                self._require_submission(connection, sub_id)
                connection.execute(
                    "UPDATE submission SET " + ", ".join(f"{name} = ?" for name in fields)
                    + " WHERE submission_id = ?", values + [sub_id],
                )
            assessment_id = None
            if submission.assessment is not None:
                assessment_id = self._write_assessment(
                    connection, sub_id, submission.assessment, "unknown"
                )
            evidence_ids = self._write_evidences(connection, sub_id, submission.evidences)
        submission.submission_id = sub_id
        if assessment_id is not None:
            submission.assessment.assessment_id = assessment_id
        for evidence, evidence_id in zip(submission.evidences, evidence_ids):
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
        """Return the composed domain object, or None when the ID is absent."""
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
