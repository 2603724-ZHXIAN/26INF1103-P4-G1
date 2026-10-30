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

