"""Retrieve and parse existing VirusTotal file and URL reports.

This module performs technical lookups only. It does not apply final risk
business rules and does not call Gemini. Files are hashed locally and are not
uploaded to VirusTotal.
"""

import base64
import hashlib
import os
import re
import time
from pathlib import Path
from urllib.parse import urlparse

import requests
from dotenv import load_dotenv


VT_BASE_URL = "https://www.virustotal.com/api/v3"
DEFAULT_TIMEOUT_SECONDS = 30
URL_ANALYSIS_POLL_SECONDS = 5
URL_ANALYSIS_MAX_ATTEMPTS = 12
DIRECT_FILE_UPLOAD_LIMIT = 32 * 1024 * 1024
MAX_FILE_UPLOAD_SIZE = 650 * 1024 * 1024
SUPPORTED_HASH_LENGTHS = {32, 40, 64}
HASH_PATTERN = re.compile(r"^[a-fA-F0-9]+$")


def load_virustotal_config():
    """Load and validate VirusTotal configuration from the environment."""
    load_dotenv()

    api_key = os.getenv("VT_API_KEY", "").strip()

    if not api_key:
        raise ValueError(
            "VT_API_KEY is missing. Add it to the .env file."
        )

    return api_key


def build_headers(api_key):
    """Build headers required by the VirusTotal v3 API."""
    return {
        "accept": "application/json",
        "x-apikey": api_key
    }


def is_supported_hash(value):
    """Return True when value resembles an MD5, SHA-1 or SHA-256 hash."""
    if not isinstance(value, str):
        return False

    candidate = value.strip()

    return (
        len(candidate) in SUPPORTED_HASH_LENGTHS
        and HASH_PATTERN.fullmatch(candidate) is not None
    )


def calculate_sha256(file_path):
    """Calculate the SHA-256 hash of a readable local file."""
    path = Path(file_path).expanduser()

    if not path.exists():
        raise FileNotFoundError(
            f"The selected file does not exist: {path}"
        )

    if not path.is_file():
        raise ValueError(
            f"The selected path is not a file: {path}"
        )

    sha256_hash = hashlib.sha256()

    try:
        with path.open("rb") as file_handle:
            for block in iter(
                lambda: file_handle.read(1024 * 1024),
                b""
            ):
                sha256_hash.update(block)
    except PermissionError as error:
        raise PermissionError(
            f"Permission was denied when reading: {path}"
        ) from error
    except OSError as error:
        raise OSError(
            f"The file could not be read: {path}. {error}"
        ) from error

    return sha256_hash.hexdigest()


def validate_url(url_input):
    """Validate and return an HTTP or HTTPS URL."""
    if not isinstance(url_input, str):
        raise ValueError("The URL must be text.")

    cleaned_url = url_input.strip()

    if not cleaned_url:
        raise ValueError("The URL cannot be empty.")

    parsed_url = urlparse(cleaned_url)

    if parsed_url.scheme.lower() not in {"http", "https"}:
        raise ValueError(
            "The URL must begin with http:// or https://."
        )

    if not parsed_url.netloc:
        raise ValueError("The URL must contain a valid host name.")

    return cleaned_url


def create_url_identifier(url_input):
    """Create the unpadded URL-safe Base64 identifier used by VT."""
    validated_url = validate_url(url_input)
    encoded_url = base64.urlsafe_b64encode(
        validated_url.encode("utf-8")
    ).decode("ascii")

    return encoded_url.rstrip("=")

