"""Start-up behaviour of src.main: database missing vs. damaged (no live APIs)."""

import io
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from src import main as app_main
from src.managers.io_manager import IOManager


class TestStartupDatabaseHandling(unittest.TestCase):
    """main() must never crash with a traceback because of the database file."""

    def setUp(self):
        self._original_cwd = os.getcwd()
        self._temp = tempfile.TemporaryDirectory()
        self.addCleanup(self._temp.cleanup)
        os.chdir(self._temp.name)                 # main() uses data/database.db relative to here
        self.addCleanup(os.chdir, self._original_cwd)
        Path("data").mkdir()

    def test_damaged_database_exits_cleanly_with_instructions(self):
        Path("data/database.db").write_text("this is not a SQLite database")
        output = io.StringIO()

        with patch.object(app_main, "EngineCoordinator") as coordinator_cls, \
                redirect_stdout(output), self.assertRaises(SystemExit) as stop:
            app_main.main()

        self.assertEqual(stop.exception.code, 1)
        coordinator_cls.return_value.run.assert_not_called()   # menu never starts
        text = output.getvalue()
        self.assertIn("could not be opened", text)
        self.assertIn("data/database.db", text)
        self.assertIn("Restart the application", text)
        self.assertNotIn("Traceback", text)

    def test_missing_database_is_created_and_app_starts(self):
        with patch.object(app_main, "EngineCoordinator") as coordinator_cls:
            app_main.main()

        coordinator_cls.return_value.run.assert_called_once()
        self.assertTrue(Path("data/database.db").exists())


class TestDatabaseStartupMessage(unittest.TestCase):
    """IOManager owns the wording shown to the user."""

    def test_message_names_the_file_and_the_fix(self):
        io_manager = IOManager(use_color=False)
        output = io.StringIO()
        with redirect_stdout(output):
            io_manager.display_database_startup_error("data/database.db")
        text = output.getvalue()
        self.assertIn("The database file could not be opened", text)
        self.assertIn("File: data/database.db", text)
        self.assertIn("python load_synthetic_data.py data/database.db", text)


if __name__ == "__main__":
    unittest.main()
