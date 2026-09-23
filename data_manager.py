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


