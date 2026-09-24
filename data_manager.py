"""
db_manager.py

Creates and manages the unified SQLite database.

Gemini output is stored in:
- text_analysis
- detection_evidence
- educational_guidance

Logic Manager output is stored in:
- final_assessment

VirusTotal output is stored in:
- vt_scan_result

Functions only. No classes.
"""

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone


def utc_now():
    """Return the current UTC time in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


def to_json(value):
    """Convert a Python value into JSON text."""
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True
    )


def from_json(value, default=None):
    """Convert stored JSON text back into a Python value."""
    if value is None:
        return default

    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return default


@contextmanager
def database_connection(db_path):
    """Open a SQLite connection with safe commit and rollback."""
    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")

    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def create_tables(db_path):
    """Create all application tables and indexes."""
    schema = """
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

    with database_connection(db_path) as connection:
        connection.executescript(schema)


def insert_submission(
    db_path,
    data_origin,
    input_type,
    input_value,
    input_hash,
    interaction_type,
    interaction_description=None,
    file_path=None,
    dataset_batch=None,
    processing_status="pending"
):
    """Insert a submission and return its ID."""
    query = """
    INSERT INTO submission (
        data_origin,
        dataset_batch,
        input_type,
        input_value,
        input_hash,
        file_path,
        interaction_type,
        interaction_description,
        processing_status,
        created_at
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """

    values = (
        data_origin,
        dataset_batch,
        input_type,
        input_value,
        input_hash,
        file_path,
        interaction_type,
        interaction_description,
        processing_status,
        utc_now()
    )

    with database_connection(db_path) as connection:
        cursor = connection.execute(query, values)
        return cursor.lastrowid


def update_submission_status(
    db_path,
    submission_id,
    processing_status,
    error_message=None
):
    """Update a submission's processing status."""
    completed_at = None

    if processing_status in {"completed", "failed"}:
        completed_at = utc_now()

    query = """
    UPDATE submission
    SET processing_status = ?,
        error_message = ?,
        completed_at = ?
    WHERE submission_id = ?
    """

    with database_connection(db_path) as connection:
        connection.execute(
            query,
            (
                processing_status,
                error_message,
                completed_at,
                submission_id
            )
        )


def get_evidence_severity(indicator_name):
    """Return display severity for an active Gemini indicator."""
    severity_map = {
        "urgency_pressure": "medium",
        "authority_impersonation": "medium",
        "credential_request": "high",
        "personal_information_request": "high",
        "payment_request": "high",
        "otp_request": "critical",
        "suspicious_link": "high",
        "download_request": "high",
        "threatening_language": "medium",
        "reward_or_prize": "medium"
    }

    return severity_map.get(indicator_name, "medium")


def save_text_analysis_results(
    db_path,
    submission_id,
    gemini_result,
    logic_result,
    model_name
):
    """
    Store Gemini and Logic Manager results in one transaction.

    If one insert fails, every insert in this function is rolled back.
    """
    education = gemini_result.get("education", {})
    now = utc_now()

    text_query = """
    INSERT INTO text_analysis (
        submission_id,
        message_classification,
        primary_threat_type,
        analysis_confidence,
        language,
        message_type,
        claimed_entity,
        requested_actions,
        possible_intents,
        extracted_urls,
        extracted_contacts,
        suspected_threat_types,
        other_warning_signs,
        user_exposure,
        model_name,
        raw_gemini_response,
        created_at
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """

    guidance_query = """
    INSERT INTO educational_guidance (
        submission_id,
        threat_explanations,
        threat_summary,
        what_it_is,
        why_dangerous,
        preventive_steps,
        recovery_steps,
        limitations,
        model_name,
        created_at
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """

    evidence_query = """
    INSERT INTO detection_evidence (
        submission_id,
        evidence_source,
        evidence_type,
        evidence_name,
        evidence_value,
        evidence_excerpt,
        severity,
        created_at
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """

    assessment_query = """
    INSERT INTO final_assessment (
        submission_id,
        is_scam,
        risk_score,
        risk_category,
        message_risk,
        exposure_level,
        overall_risk,
        decision,
        route,
        priority,
        recommended_action,
        risk_reasons,
        flags,
        active_indicators,
        matched_rules,
        matched_exposures,
        unknown_warning_signs,
        invalid_indicators,
        created_at
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """

    with database_connection(db_path) as connection:
        connection.execute(
            text_query,
            (
                submission_id,
                gemini_result.get(
                    "message_classification",
                    "uncertain"
                ),
                gemini_result.get(
                    "primary_threat_type",
                    "unknown"
                ),
                gemini_result.get(
                    "analysis_confidence",
                    "low"
                ),
                gemini_result.get("language", ""),
                gemini_result.get("message_type", "unknown"),
                gemini_result.get("claimed_entity", ""),
                to_json(
                    gemini_result.get("requested_actions", [])
                ),
                to_json(
                    gemini_result.get("possible_intents", [])
                ),
                to_json(
                    gemini_result.get("extracted_urls", [])
                ),
                to_json(
                    gemini_result.get("extracted_contacts", [])
                ),
                to_json(
                    gemini_result.get(
                        "suspected_threat_types",
                        []
                    )
                ),
                to_json(
                    gemini_result.get("other_warning_signs", [])
                ),
                to_json(
                    gemini_result.get("user_exposure", {})
                ),
                model_name,
                to_json(gemini_result),
                now
            )
        )

        connection.execute(
            guidance_query,
            (
                submission_id,
                to_json(
                    education.get("threat_explanations", [])
                ),
                education.get("threat_summary", ""),
                education.get("what_it_is", ""),
                to_json(
                    education.get("why_dangerous", [])
                ),
                to_json(
                    education.get("preventive_steps", [])
                ),
                to_json(
                    education.get("recovery_steps", [])
                ),
                to_json(
                    education.get("limitations", [])
                ),
                model_name,
                now
            )
        )

        indicators = gemini_result.get("indicators", {})

        for indicator_name, indicator_data in indicators.items():
            if not indicator_data.get("present", False):
                continue

            connection.execute(
                evidence_query,
                (
                    submission_id,
                    "gemini",
                    "message_indicator",
                    indicator_name,
                    "present",
                    indicator_data.get("evidence", ""),
                    get_evidence_severity(indicator_name),
                    now
                )
            )

        for warning_sign in gemini_result.get(
            "other_warning_signs",
            []
        ):
            if isinstance(warning_sign, dict):
                evidence_name = warning_sign.get(
                    "name",
                    "other_warning_sign"
                )
                evidence_excerpt = warning_sign.get(
                    "evidence",
                    ""
                )
            else:
                evidence_name = "other_warning_sign"
                evidence_excerpt = str(warning_sign)

            connection.execute(
                evidence_query,
                (
                    submission_id,
                    "gemini",
                    "other_warning_sign",
                    evidence_name,
                    "present",
                    evidence_excerpt,
                    "medium",
                    now
                )
            )

        risk_reasons = logic_result.get(
            "risk_reasons",
            logic_result.get("message_reasons", [])
        )

        connection.execute(
            assessment_query,
            (
                submission_id,
                int(logic_result.get("is_scam", False)),
                logic_result.get("risk_score"),
                logic_result.get(
                    "risk_category",
                    logic_result.get("overall_risk", "low")
                ),
                logic_result.get("message_risk", "low"),
                logic_result.get("exposure_level", "low"),
                logic_result.get("overall_risk", "low"),
                logic_result.get("decision", "accept"),
                logic_result.get("route", "standard_review"),
                logic_result.get("priority", "low"),
                logic_result.get(
                    "recommended_action",
                    "No immediate action required."
                ),
                to_json(risk_reasons),
                to_json(logic_result.get("flags", [])),
                to_json(
                    logic_result.get("active_indicators", [])
                ),
                to_json(
                    logic_result.get("matched_rules", [])
                ),
                to_json(
                    logic_result.get("matched_exposures", [])
                ),
                to_json(
                    logic_result.get(
                        "unknown_warning_signs",
                        []
                    )
                ),
                to_json(
                    logic_result.get("invalid_indicators", [])
                ),
                now
            )
        )

        connection.execute(
            """
            UPDATE submission
            SET processing_status = 'completed',
                error_message = NULL,
                completed_at = ?
            WHERE submission_id = ?
            """,
            (now, submission_id)
        )


def insert_vt_scan_result(
    db_path,
    submission_id,
    resource_type,
    resource_identifier,
    malicious_count,
    suspicious_count,
    harmless_count,
    undetected_count,
    timeout_count,
    reputation,
    raw_vt_response
):
    """Insert one VirusTotal result."""
    query = """
    INSERT INTO vt_scan_result (
        submission_id,
        resource_type,
        resource_identifier,
        malicious_count,
        suspicious_count,
        harmless_count,
        undetected_count,
        timeout_count,
        reputation,
        raw_vt_response,
        created_at
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """

    with database_connection(db_path) as connection:
        cursor = connection.execute(
            query,
            (
                submission_id,
                resource_type,
                resource_identifier,
                malicious_count,
                suspicious_count,
                harmless_count,
                undetected_count,
                timeout_count,
                reputation,
                to_json(raw_vt_response),
                utc_now()
            )
        )

        return cursor.lastrowid


def get_submission_report(db_path, submission_id):
    """Return the complete stored report for one submission."""
    query = """
    SELECT
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
        ta.raw_gemini_response,
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
        fa.matched_exposures
    FROM submission AS s
    LEFT JOIN text_analysis AS ta
        ON ta.submission_id = s.submission_id
    LEFT JOIN educational_guidance AS eg
        ON eg.submission_id = s.submission_id
    LEFT JOIN final_assessment AS fa
        ON fa.submission_id = s.submission_id
    WHERE s.submission_id = ?
    """

    with database_connection(db_path) as connection:
        row = connection.execute(
            query,
            (submission_id,)
        ).fetchone()

    if row is None:
        return None

    report = dict(row)

    json_columns = [
        "requested_actions",
        "possible_intents",
        "extracted_urls",
        "extracted_contacts",
        "suspected_threat_types",
        "other_warning_signs",
        "user_exposure",
        "raw_gemini_response",
        "threat_explanations",
        "why_dangerous",
        "preventive_steps",
        "recovery_steps",
        "limitations",
        "risk_reasons",
        "flags",
        "active_indicators",
        "matched_rules",
        "matched_exposures"
    ]

    for column_name in json_columns:
        report[column_name] = from_json(
            report.get(column_name),
            []
        )

    return report


def get_submission_evidence(db_path, submission_id):
    """Return evidence rows for one submission."""
    query = """
    SELECT *
    FROM detection_evidence
    WHERE submission_id = ?
    ORDER BY evidence_id
    """

    with database_connection(db_path) as connection:
        rows = connection.execute(
            query,
            (submission_id,)
        ).fetchall()

    return [dict(row) for row in rows]


def get_risk_category_counts(db_path):
    """Return counts for graphing risk categories."""
    query = """
    SELECT
        risk_category,
        COUNT(*) AS total
    FROM final_assessment
    GROUP BY risk_category
    ORDER BY total DESC
    """

    with database_connection(db_path) as connection:
        rows = connection.execute(query).fetchall()

    return [dict(row) for row in rows]


def get_top_threat_types(db_path, limit=10):
    """Return the most common primary threat types."""
    query = """
    SELECT
        primary_threat_type,
        COUNT(*) AS total
    FROM text_analysis
    GROUP BY primary_threat_type
    ORDER BY total DESC
    LIMIT ?
    """

    with database_connection(db_path) as connection:
        rows = connection.execute(
            query,
            (limit,)
        ).fetchall()

    return [dict(row) for row in rows]


def get_top_indicators(db_path, limit=10):
    """Return the most frequently detected Gemini indicators."""
    query = """
    SELECT
        evidence_name,
        COUNT(*) AS total
    FROM detection_evidence
    WHERE evidence_source = 'gemini'
      AND evidence_type = 'message_indicator'
    GROUP BY evidence_name
    ORDER BY total DESC
    LIMIT ?
    """

    with database_connection(db_path) as connection:
        rows = connection.execute(
            query,
            (limit,)
        ).fetchall()

    return [dict(row) for row in rows]


def search_records(db_path, keyword):
    """Search text, threats, organisations and evidence."""
    search_value = f"%{keyword}%"

    query = """
    SELECT DISTINCT
        s.submission_id,
        s.input_type,
        s.input_value,
        s.created_at,
        ta.message_classification,
        ta.primary_threat_type,
        ta.claimed_entity,
        fa.risk_category,
        fa.route
    FROM submission AS s
    LEFT JOIN text_analysis AS ta
        ON ta.submission_id = s.submission_id
    LEFT JOIN final_assessment AS fa
        ON fa.submission_id = s.submission_id
    LEFT JOIN detection_evidence AS de
        ON de.submission_id = s.submission_id
    WHERE s.input_value LIKE ?
       OR ta.primary_threat_type LIKE ?
       OR ta.claimed_entity LIKE ?
       OR ta.suspected_threat_types LIKE ?
       OR de.evidence_name LIKE ?
       OR de.evidence_excerpt LIKE ?
    ORDER BY s.created_at DESC
    """

    parameters = (
        search_value,
        search_value,
        search_value,
        search_value,
        search_value,
        search_value
    )

    with database_connection(db_path) as connection:
        rows = connection.execute(
            query,
            parameters
        ).fetchall()

    return [dict(row) for row in rows]