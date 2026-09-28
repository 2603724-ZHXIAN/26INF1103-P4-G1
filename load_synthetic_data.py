"""Load synthetic fixtures into a SQLite database.

Usage:
    python load_synthetic_data.py path/to/database.db

The database path is supplied when the loader is run, so this file does not
hardcode a test or production database name.

This script does not call Gemini or VirusTotal. It uses pre-generated
synthetic Gemini/Logic/VirusTotal results from synthetic_data.json.
"""

import hashlib
import json
import sys
from pathlib import Path

import data_manager

BASE_DIR = Path(__file__).resolve().parent
DATA_FILE = BASE_DIR / "synthetic_data.json"


def sha256_text(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def load_cases():
    data = json.loads(DATA_FILE.read_text(encoding="utf-8"))
    return data["cases"]


def load_synthetic_dataset(db_path):
    cases = load_cases()
    db_path = str(db_path)

    data_manager.create_tables(db_path)

    inserted = 0

    for case in cases:
        input_value = case["input_value"]
        input_hash = sha256_text(input_value)

        submission_id = data_manager.insert_submission(
            db_path,
            data_origin=case["data_origin"],
            input_type=case["input_type"],
            input_value=input_value,
            input_hash=input_hash,
            interaction_type=case["interaction_type"],
            interaction_description=case["interaction_description"],
            file_path=case.get("file_path"),
            dataset_batch=case["dataset_batch"],
            processing_status="processing",
        )

        if "gemini_result" in case:
            data_manager.save_text_analysis_results(
                db_path,
                submission_id,
                case["gemini_result"],
                case["expected_logic_result"],
                "synthetic-gemini",
            )
        else:
            data_manager.save_vt_analysis_results(
                db_path,
                submission_id,
                case["vt_result"],
                case["expected_logic_result"],
                case["education_result"],
                case.get("interpreted_exposure"),
                "synthetic-gemini",
            )

        inserted += 1

    print(f"Loaded {inserted} synthetic cases into {db_path}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python load_synthetic_data.py <database_path>")
        raise SystemExit(1)

    load_synthetic_dataset(sys.argv[1])
