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

    def initialize_database(self) -> None:
        """Create the existing application tables and indexes if absent."""
        with self._get_connection() as connection:
            connection.executescript(SCHEMA)

