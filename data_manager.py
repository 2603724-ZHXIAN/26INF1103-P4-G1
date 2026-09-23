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

DEFAULT_DB_PATH = "scam_analysis.db"

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
        

# INSERT: submission
def insert_submission(db_path, data_origin, input_type, input_value, input_hash,
                       interaction_type, interaction_description=None,
                       processing_status="pending",
                       dataset_batch=None, file_path=None):
    with _connect(db_path) as conn:
        cur = conn.execute(
            """INSERT INTO submission
            (data_origin, dataset_batch, input_type, input_value, input_hash,
                file_path, interaction_type, interaction_description,
                processing_status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (data_origin, dataset_batch, input_type, input_value, input_hash,
            file_path, interaction_type, interaction_description,
            processing_status, _now()),
        )
        return cur.lastrowid

def update_submission_status(db_path, submission_id, processing_status):
    with _connect(db_path) as conn:
        conn.execute(
            "UPDATE submission SET processing_status = ? WHERE submission_id = ?",
            (processing_status, submission_id),
        )



# INSERT: vt_scan_result
# ----------------------------------------------------------------------
def insert_vt_scan_result(db_path, submission_id, scanned_type, scanned_value,
                           malicious_count, suspicious_count, harmless_count,
                           undetected_count, sha256=None, file_type=None,
                           threat_label=None, sandbox_verdict=None,
                           last_analysis_date=None, raw_vt_response=None):
    total = malicious_count + suspicious_count + harmless_count + undetected_count
    detection_ratio = (malicious_count + suspicious_count) / total if total else 0.0

    with _connect(db_path) as conn:
        cur = conn.execute(
            """INSERT INTO vt_scan_result
               (submission_id, scanned_type, scanned_value, sha256, file_type,
                malicious_count, suspicious_count, harmless_count, undetected_count,
                detection_ratio, threat_label, sandbox_verdict, last_analysis_date,
                raw_vt_response, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (submission_id, scanned_type, scanned_value, sha256, file_type,
             malicious_count, suspicious_count, harmless_count, undetected_count,
             detection_ratio, threat_label, sandbox_verdict, last_analysis_date,
             _to_json(raw_vt_response), _now()),
        )
        return cur.lastrowid


# INSERT: text_analysis

def insert_text_analysis(db_path, submission_id, classification, scam_type,
                          confidence_level, claimed_entity=None,
                          requested_action=None, possible_intent=None,
                          extracted_urls=None, extracted_contacts=None,
                          model_name=None, raw_gemini_response=None):
    with _connect(db_path) as conn:
        cur = conn.execute(
            """INSERT INTO text_analysis
               (submission_id, classification, scam_type, confidence_level,
                claimed_entity, requested_action, possible_intent, extracted_urls,
                extracted_contacts, model_name, raw_gemini_response, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (submission_id, classification, scam_type, confidence_level,
             claimed_entity, requested_action, _to_json(possible_intent),
             _to_json(extracted_urls), _to_json(extracted_contacts),
             model_name, _to_json(raw_gemini_response), _now()),
        )
        return cur.lastrowid



# INSERT: detection_evidence (used for both VT and Gemini evidence)

def insert_evidence(db_path, submission_id, evidence_source, evidence_type,
                     evidence_name, evidence_value, severity,
                     evidence_excerpt=None):
    with _connect(db_path) as conn:
        cur = conn.execute(
            """INSERT INTO detection_evidence
               (submission_id, evidence_source, evidence_type, evidence_name,
                evidence_value, evidence_excerpt, severity, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (submission_id, evidence_source, evidence_type, evidence_name,
             evidence_value, evidence_excerpt, severity, _now()),
        )
        return cur.lastrowid



# INSERT: final_assessment

def insert_final_assessment(db_path, submission_id, is_scam, risk_score,
                             risk_category, risk_reasons=None,
                             is_new_scam_type=None, summary=None,
                             what_it_is=None, why_dangerous=None,
                             possible_impact=None, preventive_steps=None,
                             recovery_steps=None, limitations=None,
                             model_name=None):
    with _connect(db_path) as conn:
        cur = conn.execute(
            """INSERT INTO final_assessment
               (submission_id, is_scam, risk_score, risk_category, risk_reasons,
                is_new_scam_type, summary, what_it_is, why_dangerous,
                possible_impact, preventive_steps, recovery_steps, limitations,
                model_name, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (submission_id, int(is_scam), risk_score, risk_category,
             _to_json(risk_reasons), is_new_scam_type, summary, what_it_is,
             why_dangerous, _to_json(possible_impact), _to_json(preventive_steps),
             _to_json(recovery_steps), _to_json(limitations), model_name, _now()),
        )
        return cur.lastrowid


# READ helpers
def get_submission(db_path, submission_id):
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM submission WHERE submission_id = ?", (submission_id,)
        ).fetchone()
        return dict(row) if row else None


def get_vt_scan_results(db_path, submission_id):
    with _connect(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM vt_scan_result WHERE submission_id = ?", (submission_id,)
        ).fetchall()
        return [dict(r) for r in rows]


def get_text_analysis(db_path, submission_id):
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM text_analysis WHERE submission_id = ?", (submission_id,)
        ).fetchone()
        if not row:
            return None
        record = dict(row)
        for field in ("possible_intent", "extracted_urls", "extracted_contacts"):
            record[field] = _from_json(record[field])
        return record


def get_evidence(db_path, submission_id):
    with _connect(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM detection_evidence WHERE submission_id = ? ORDER BY severity",
            (submission_id,),
        ).fetchall()
        return [dict(r) for r in rows]


def get_final_assessment(db_path, submission_id):
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM final_assessment WHERE submission_id = ?", (submission_id,)
        ).fetchone()
        if not row:
            return None
        record = dict(row)
        for field in ("risk_reasons", "possible_impact", "preventive_steps",
                      "recovery_steps", "limitations"):
            record[field] = _from_json(record[field])
        return record


def get_full_submission(db_path, submission_id):
    """Pull everything related to one submission into a single dict — handy
    for building the filtered JSON payload sent to Gemini, or for a report."""
    return {
        "submission": get_submission(db_path, submission_id),
        "vt_scan_results": get_vt_scan_results(db_path, submission_id),
        "text_analysis": get_text_analysis(db_path, submission_id),
        "evidence": get_evidence(db_path, submission_id),
        "final_assessment": get_final_assessment(db_path, submission_id),
    }


def find_by_input_hash(db_path, input_hash):
    """Check for duplicate submissions before re-processing the same input."""
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM submission WHERE input_hash = ?", (input_hash,)
        ).fetchone()
        return dict(row) if row else None


# count matching scam type records
# get scam type distribution
# find similar by claimed entity
# get risk category counts

# ----------------------------------------------------------------------
def count_matching_scam_type(db_path, scam_type, data_origin="synthetic"):
    """How many past (default: synthetic baseline) records share this
    scam_type. A business rule can call this and say: count == 0 means
    is_new_scam_type = 1."""
    with _connect(db_path) as conn:
        row = conn.execute(
            """SELECT COUNT(*) AS match_count
               FROM text_analysis ta
               JOIN submission s ON s.submission_id = ta.submission_id
               WHERE ta.scam_type = ? AND s.data_origin = ?""",
            (scam_type, data_origin),
        ).fetchone()
        return row["match_count"]


def get_scam_type_distribution(db_path, data_origin=None):
    """Count of records per scam_type, optionally filtered to
    'synthetic' or 'cli'. Useful for a baseline snapshot or a dashboard."""
    query = """SELECT ta.scam_type, COUNT(*) AS count
               FROM text_analysis ta
               JOIN submission s ON s.submission_id = ta.submission_id"""
    params = ()
    if data_origin:
        query += " WHERE s.data_origin = ?"
        params = (data_origin,)
    query += " GROUP BY ta.scam_type ORDER BY count DESC"
    with _connect(db_path) as conn:
        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]


def find_similar_by_claimed_entity(db_path, claimed_entity, exclude_submission_id=None, limit=10):
    """Past cases (any origin) that impersonated the same entity — e.g.
    every prior case claiming to be 'DBS Bank'."""
    query = """SELECT s.submission_id, s.created_at, ta.scam_type,
                      ta.classification, ta.confidence_level
               FROM text_analysis ta
               JOIN submission s ON s.submission_id = ta.submission_id
               WHERE ta.claimed_entity = ?"""
    params = [claimed_entity]
    if exclude_submission_id is not None:
        query += " AND s.submission_id != ?"
        params.append(exclude_submission_id)
    query += " ORDER BY s.created_at DESC LIMIT ?"
    params.append(limit)
    with _connect(db_path) as conn:
        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]


def get_risk_category_counts(db_path, data_origin=None):
    """Count of final assessments per risk_category — e.g. for a summary
    report of how many critical/high/etc. cases exist."""
    query = """SELECT fa.risk_category, COUNT(*) AS count
               FROM final_assessment fa
               JOIN submission s ON s.submission_id = fa.submission_id"""
    params = ()
    if data_origin:
        query += " WHERE s.data_origin = ?"
        params = (data_origin,)
    query += " GROUP BY fa.risk_category ORDER BY count DESC"
    with _connect(db_path) as conn:
        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]


# REPORT FORMATTING
# ----------------------------------------------------------------------
# This is presentation logic, not database logic — it just takes the raw
# dict from get_full_submission() and turns it into readable text.
def format_submission_report(data: dict) -> str:
    """Take the dict returned by get_full_submission() and turn it into a
    readable CLI report. Returns a plain-text string."""
    submission = data.get("submission") or {}
    assessment = data.get("final_assessment") or {}
    evidence = data.get("evidence") or []

    lines = []
    lines.append("=" * 60)
    lines.append(f"  SUBMISSION #{submission.get('submission_id')}")
    lines.append("=" * 60)

    if not assessment:
        lines.append("No final assessment yet — this submission hasn't finished processing.")
        return "\n".join(lines)

    # 1. Verdict
    verdict = "SCAM" if assessment.get("is_scam") else "NOT A SCAM"
    lines.append(f"\nVERDICT: {verdict}")
    lines.append(f"Risk category: {assessment.get('risk_category', 'unknown').upper()}")
    lines.append(f"Risk score: {assessment.get('risk_score', '?')}/100")

    # 2. What it is
    if assessment.get("summary"):
        lines.append(f"\nSummary: {assessment['summary']}")
    if assessment.get("what_it_is"):
        lines.append(f"What it is: {assessment['what_it_is']}")

    # 3. Why it's flagged
    if assessment.get("why_dangerous"):
        lines.append(f"\nWhy it's dangerous: {assessment['why_dangerous']}")

    if evidence:
        lines.append("\nKey evidence:")
        for item in evidence:
            lines.append(f"  - [{item.get('severity', '?').upper()}] {item.get('evidence_value', '')}")

    # 4. What to do next
    interaction_type = submission.get("interaction_type")

    if interaction_type in (
        "entered_information",
        "opened_or_downloaded_file",
        "made_payment_or_shared_banking_details",
    ):
        steps_key = "recovery_steps"
        steps_label = "Recovery steps"
    else:
        steps_key = "preventive_steps"
        steps_label = "Preventive steps"

    steps = assessment.get(steps_key)

    if steps:
        lines.append(f"\n{steps_label}:")
        for i, step in enumerate(steps, 1):
            lines.append(f"  {i}. {step}")

        # 5. Caveats
    limitations = assessment.get("limitations")
    if limitations:
        lines.append("\nLimitations:")
        for note in limitations:
            lines.append(f"  - {note}")

    lines.append("=" * 60)
    return "\n".join(lines)

# manual test/demo code
if __name__ == "__main__":
    TEST_DB = "scam_analysis_test.db"
    create_tables(TEST_DB)

    sub_id = insert_submission(
        TEST_DB,
        data_origin="cli",
        input_type="text",
        input_value="Your account has been suspended, verify immediately: https://fake-bank-login.example",
        input_hash="demo-hash-0001",
        interaction_type="clicked_link",
        interaction_description="Clicked the link in the message but did not enter any information.",
        processing_status="processing",
    )

    insert_text_analysis(
        TEST_DB,
        submission_id=sub_id,
        classification="scam",
        scam_type="bank_impersonation",
        confidence_level="high",
        claimed_entity="DBS Bank",
        requested_action="Open a link and verify the account",
        possible_intent=["credential theft", "account takeover"],
        extracted_urls=["https://fake-bank-login.example"],
        model_name="gemini-1.5-pro",
    )

    insert_evidence(
        TEST_DB,
        submission_id=sub_id,
        evidence_source="gemini",
        evidence_type="urgency",
        evidence_name="Urgency pressure",
        evidence_value="Pressures the recipient to act immediately",
        evidence_excerpt="verify immediately",
        severity="high",
    )

    insert_vt_scan_result(
        TEST_DB,
        submission_id=sub_id,
        scanned_type="url",
        scanned_value="https://fake-bank-login.example",
        malicious_count=8,
        suspicious_count=3,
        harmless_count=20,
        undetected_count=39,
        threat_label="phishing",
    )

    insert_evidence(
        TEST_DB,
        submission_id=sub_id,
        evidence_source="virustotal",
        evidence_type="engine_detection",
        evidence_name="Multiple engine detections",
        evidence_value="Multiple engines classified the URL as malicious.",
        severity="critical",
    )

    insert_final_assessment(
        TEST_DB,
        submission_id=sub_id,
        is_scam=True,
        risk_score=92,
        risk_category="critical",
        risk_reasons=[
            "Sensitive credentials were requested",
            "A financial institution was impersonated",
            "The included URL received malicious detections",
        ],
        is_new_scam_type=0,
        summary="This message is a bank-impersonation phishing scam.",
        model_name="gemini-1.5-pro",
    )

    update_submission_status(TEST_DB, sub_id, "completed")

    data = get_full_submission(TEST_DB, sub_id)
    print(format_submission_report(data))
