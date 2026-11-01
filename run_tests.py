"""Run the complete automated test suite with one command.

Usage (from anywhere):
    python run_tests.py              # run every test, summary per component
    python run_tests.py -v           # also list each individual test
    python run_tests.py logic ai     # run only the matching test files

All tests run offline: AI and VirusTotal calls are replaced by mocks, and
databases are temporary or in-memory, so no API keys or network are needed.
Exit code is 0 when everything passes and 1 otherwise (used by CI).
"""

import sys
import time
import unittest
from collections import OrderedDict
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
TESTS_DIR = PROJECT_ROOT / "tests"

# Test file -> the part of the system it verifies (shown in the summary).
COMPONENTS = OrderedDict([
    ("test_models", "Domain models (Submission, Assessment, Evidence)"),
    ("test_services", "Services (BaseLLMClient, Gemini, Groq, VirusTotal)"),
    ("test_ai_manager", "AI Manager (prompts, schema validation, failover)"),
    ("test_oop_logic_manager", "Logic Manager (business rules, VT + AI risk rules)"),
    ("test_data_manager", "Data Manager (SQLite persistence, reports)"),
    ("test_io_manager", "IO Manager (input validation, display)"),
    ("test_coordinator", "Engine Coordinator (end-to-end pipelines)"),
])


def _module_of(test) -> str:
    """Return the test file name a test (or failed import) belongs to."""
    module = type(test).__module__.split(".")[-1]
    if module == "loader":  # unittest's placeholder for a file that failed to import
        module = getattr(test, "_testMethodName", module).split(".")[-1]
    return module


class SummaryResult(unittest.TextTestResult):
    """Records pass/fail counts per test file."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.per_module = {}

    def _count(self, test, outcome):
        stats = self.per_module.setdefault(_module_of(test), {"run": 0, "failed": 0, "skipped": 0})
        stats[outcome] += 1

    def startTest(self, test):
        super().startTest(test)
        self._count(test, "run")

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self._count(test, "failed")

    def addError(self, test, err):
        super().addError(test, err)
        self._count(test, "failed")

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self._count(test, "skipped")

    def addSubTest(self, test, subtest, err):
        super().addSubTest(test, subtest, err)
        if err is not None:
            self._count(test, "failed")


def build_suite(filters):
    """Discover all test files, or only those whose name contains a filter word."""
    loader = unittest.TestLoader()
    if not filters:
        return loader.discover(str(TESTS_DIR), top_level_dir=str(PROJECT_ROOT))
    suite = unittest.TestSuite()
    for path in sorted(TESTS_DIR.glob("test_*.py")):
        if any(word.lower() in path.stem.lower() for word in filters):
            suite.addTests(loader.discover(str(TESTS_DIR), pattern=path.name,
                                           top_level_dir=str(PROJECT_ROOT)))
    return suite


def print_summary(result, elapsed):
    width = 78
    print("\n" + "=" * width)
    print("TEST SUMMARY".center(width))
    print("=" * width)
    print(f"{'Component':<58}{'Tests':>7}{'Result':>13}")
    print("-" * width)
    names = list(COMPONENTS) + sorted(set(result.per_module) - set(COMPONENTS))
    for name in names:
        stats = result.per_module.get(name)
        if not stats:
            continue
        status = "PASS" if stats["failed"] == 0 else f"FAIL ({stats['failed']})"
        label = COMPONENTS.get(name, name)
        print(f"{label[:57]:<58}{stats['run']:>7}{status:>13}")
    print("-" * width)
    failed = len(result.failures) + len(result.errors)
    overall = "ALL TESTS PASSED" if result.wasSuccessful() else f"{failed} PROBLEM(S) FOUND"
    print(f"{'Total':<58}{result.testsRun:>7}{'':>13}")
    print(f"{overall} in {elapsed:.2f}s".center(width))
    print("=" * width)


def main(argv):
    verbose = "-v" in argv or "--verbose" in argv
    filters = [arg for arg in argv if not arg.startswith("-")]

    sys.path.insert(0, str(PROJECT_ROOT))
    suite = build_suite(filters)
    if suite.countTestCases() == 0:
        print(f"No test files match: {', '.join(filters)}")
        return 1

    runner = unittest.TextTestRunner(verbosity=2 if verbose else 1, resultclass=SummaryResult)
    start = time.perf_counter()
    result = runner.run(suite)
    print_summary(result, time.perf_counter() - start)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
