"""Load synthetic fixtures into a SQLite database using OOP Domain Models and DataManager.

Usage:
    python load_synthetic_data.py path/to/database.db

The database path is supplied when the loader is run, so this file does not
hardcode a test or production database name.
"""

import hashlib
import json
import sys
from pathlib import Path

from src.managers.data_manager import DataManager
from src.models import AssessmentResult, Submission, ThreatEvidence

BASE_DIR = Path(__file__).resolve().parent
DATA_FILE = BASE_DIR / "data" / "synthetic_data.json"


def sha256_text(value: str) -> str:
    """Return SHA-256 hash of a string."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def load_cases():
    """Load cases from JSON fixture file."""
    data = json.loads(DATA_FILE.read_text(encoding="utf-8"))
    return data["cases"]


def load_synthetic_dataset(db_path: str):
    """Load all synthetic cases into SQLite using DataManager and Domain Models."""
    cases = load_cases()
    db_path = str(db_path)

    dm = DataManager(db_path=db_path)
    dm.initialize_database()

    inserted = 0

    for case in cases:
        input_value = case["input_value"]
        input_hash = sha256_text(input_value)

        # 1. Instantiate Submission domain model
        sub = Submission(
            input_type=case["input_type"],
            input_value=input_value,
            input_hash=input_hash,
            interaction_type=case["interaction_type"],
            interaction_description=case.get("interaction_description"),
            file_path=case.get("file_path"),
            data_origin=case.get("data_origin", "synthetic"),
            dataset_batch=case.get("dataset_batch"),
            processing_status="completed",
        )

        # 2. Instantiate AssessmentResult domain model
        logic_res = case.get("expected_logic_result", {})
        assessment = AssessmentResult.from_dict(logic_res)

        # Attach educational narrative
        if "gemini_result" in case:
            edu = case["gemini_result"].get("education", {})
            assessment.attach_educational_guidance(
                what_it_is=edu.get("what_it_is"),
                threat_summary=edu.get("threat_summary"),
                recovery_steps=edu.get("recovery_steps"),
            )
        elif "education_result" in case and isinstance(case["education_result"], dict):
            edu = case["education_result"]
            assessment.attach_educational_guidance(
                what_it_is=edu.get("what_it_is"),
                threat_summary=edu.get("threat_summary"),
                recovery_steps=edu.get("recovery_steps"),
            )

        sub.set_assessment(assessment)

        # 3. Create ThreatEvidence domain objects
        if "gemini_result" in case:
            for ind_name, ind_data in case["gemini_result"].get("indicators", {}).items():
                if isinstance(ind_data, dict) and ind_data.get("present"):
                    sub.create_evidence(
                        name=ind_name,
                        source="gemini",
                        evidence_type="indicator",
                        evidence_value=ind_data.get("evidence"),
                        severity="high" if ind_name in {"payment_request", "credential_request"} else "medium",
                    )
        elif "vt_result" in case:
            for threat in case["vt_result"].get("threat_names", []):
                sub.create_evidence(
                    name=threat,
                    source="virustotal",
                    evidence_type="detection",
                    evidence_value=threat,
                    severity="high",
                )

        # 4. Save submission and children
        submission_id = dm.save_submission(sub)

        # 5. Save structured telemetry / text analysis for reporting
        if "gemini_result" in case:
            dm.save_text_analysis(submission_id, case["gemini_result"], "synthetic-gemini")
        elif "vt_result" in case:
            dm.save_vt_scan_result(submission_id, case["vt_result"])

        inserted += 1

    print(f"Loaded {inserted} synthetic cases into {db_path}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python load_synthetic_data.py <database_path>")
        raise SystemExit(1)

    load_synthetic_dataset(sys.argv[1])
