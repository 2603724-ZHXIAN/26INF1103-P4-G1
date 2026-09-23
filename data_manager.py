"""
db_manager.py
--------------
SQLite database manager for the Security Scam Analysis project.
Plain functions only — no classes.

Implements the 5-table schema:
    submission           -> every input (synthetic or CLI)
    vt_scan_result        -> VirusTotal results for files/URLs
    text_analysis          -> Gemini's semantic analysis of text
    detection_evidence       -> individual technical/semantic evidence items
    final_assessment          -> business-rule score + Gemini's educational output

"""

import sqlite3
import json
from datetime import datetime, timezone
from contextlib import contextmanager

DEAULT_DB_PATH = "scam_analysis.db"

def _now() -> str:
    """Return current UTC timestamp as ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


def _to_json(value):
    """Convert Python lists/dicts to JSON text for storage. None stays None."""
    if value is None:
        return None
    if isinstance(value, str):
        return value  # already a string (already JSON, or plain text)
    return json.dumps(value)


def _from_json(value):
    """Convert stored JSON text back into a Python list/dict. None stays None."""
    if value is None:
        return None
    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return value


@contextmanager
def _connect(db_path: str):
    """Open a connection with foreign keys enforced, row access by column name."""
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


# SCHEMA CREATION
def create_tables(db_path: str = DEFAULT_DB_PATH):
    schema = """
    CREATE TABLE IF NOT EXISTS submission (
        submission_id       INTEGER PRIMARY KEY AUTOINCREMENT,
        data_origin         TEXT NOT NULL CHECK (data_origin IN ('synthetic', 'cli')),
        dataset_batch       TEXT,
        input_type          TEXT NOT NULL CHECK (input_type IN ('text', 'file', 'url')),
        input_value         TEXT NOT NULL,
        input_hash          TEXT NOT NULL,
        file_path           TEXT,

        interaction_type    TEXT NOT NULL CHECK (
            interaction_type IN (
                'viewed_only',
                'clicked_link',
                'entered_information',
                'opened_or_downloaded_file',
                'made_payment_or_shared_banking_details',
                'other'
            )
        ),

        interaction_description TEXT,

        processing_status   TEXT NOT NULL CHECK (
            processing_status IN (
                'pending',
                'processing',
                'completed',
                'failed'
            )
        ),

        created_at          TEXT NOT NULL
    );

        CREATE TABLE IF NOT EXISTS vt_scan_result (
        vt_scan_id          INTEGER PRIMARY KEY AUTOINCREMENT,
        submission_id       INTEGER NOT NULL,
        scanned_type        TEXT NOT NULL CHECK (scanned_type IN ('file', 'url')),
        scanned_value       TEXT NOT NULL,
        sha256              TEXT,
        file_type           TEXT,
        malicious_count     INTEGER NOT NULL,
        suspicious_count    INTEGER NOT NULL,
        harmless_count      INTEGER NOT NULL,
        undetected_count    INTEGER NOT NULL,
        detection_ratio     REAL NOT NULL,
        threat_label        TEXT,
        sandbox_verdict     TEXT,
        last_analysis_date  TEXT,
        raw_vt_response     TEXT,
        created_at          TEXT NOT NULL,
        FOREIGN KEY (submission_id) REFERENCES submission(submission_id)
    );

    CREATE TABLE IF NOT EXISTS text_analysis (
        text_analysis_id     INTEGER PRIMARY KEY AUTOINCREMENT,
        submission_id        INTEGER NOT NULL,
        classification        TEXT NOT NULL CHECK (classification IN
                                ('scam', 'suspicious', 'legitimate', 'uncertain')),
        scam_type            TEXT NOT NULL,
        confidence_level      TEXT NOT NULL CHECK (confidence_level IN ('low', 'medium', 'high')),
        claimed_entity        TEXT,
        requested_action      TEXT,
        possible_intent       TEXT,
        extracted_urls        TEXT,
        extracted_contacts    TEXT,
        model_name            TEXT,
        raw_gemini_response   TEXT,
        created_at            TEXT NOT NULL,
        FOREIGN KEY (submission_id) REFERENCES submission(submission_id)
    );

    CREATE TABLE IF NOT EXISTS detection_evidence (
        evidence_id          INTEGER PRIMARY KEY AUTOINCREMENT,
        submission_id        INTEGER NOT NULL,
        evidence_source       TEXT NOT NULL CHECK (evidence_source IN ('virustotal', 'gemini')),
        evidence_type         TEXT NOT NULL,
        evidence_name         TEXT NOT NULL,
        evidence_value        TEXT NOT NULL,
        evidence_excerpt      TEXT,
        severity              TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
        created_at             TEXT NOT NULL,
        FOREIGN KEY (submission_id) REFERENCES submission(submission_id)
    );

    CREATE TABLE IF NOT EXISTS final_assessment (
        assessment_id        INTEGER PRIMARY KEY AUTOINCREMENT,
        submission_id        INTEGER NOT NULL,
        is_scam              INTEGER NOT NULL CHECK (is_scam IN (0, 1)),
        risk_score           INTEGER NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
        risk_category         TEXT NOT NULL CHECK (risk_category IN
                                ('safe', 'low', 'medium', 'high', 'critical')),
        risk_reasons          TEXT,
        is_new_scam_type      INTEGER CHECK (is_new_scam_type IN (0, 1)),
        summary               TEXT,
        what_it_is            TEXT,
        why_dangerous          TEXT,
        possible_impact        TEXT,
        preventive_steps        TEXT,
        recovery_steps          TEXT,
        limitations             TEXT,
        model_name              TEXT,
        created_at               TEXT NOT NULL,
        FOREIGN KEY (submission_id) REFERENCES submission(submission_id)
    );
    """
    with _connect(db_path) as conn:
        conn.executescript(schema)
