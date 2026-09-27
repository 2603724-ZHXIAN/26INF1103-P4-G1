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

def request_vt_report(endpoint, api_key, timeout_seconds):
    """Send one VirusTotal GET request and return JSON or an error."""
    try:
        response = requests.get(
            endpoint,
            headers=build_headers(api_key),
            timeout=timeout_seconds
        )
    except requests.exceptions.Timeout:
        return {
            "error": "VirusTotal did not respond before the timeout.",
            "error_type": "timeout"
        }
    except requests.exceptions.SSLError as error:
        return {
            "error": "A secure connection to VirusTotal could not be made.",
            "error_type": "ssl_error",
            "details": str(error)
        }
    except requests.exceptions.ConnectionError as error:
        return {
            "error": (
                "Could not connect to VirusTotal. Check the Internet, "
                "DNS, firewall, VPN or proxy."
            ),
            "error_type": "connection_error",
            "details": str(error)
        }
    except requests.exceptions.RequestException as error:
        return {
            "error": "The VirusTotal request failed.",
            "error_type": "request_error",
            "details": str(error)
        }

    try:
        response_data = response.json()
    except requests.exceptions.JSONDecodeError:
        response_data = None

    if response.status_code == 200:
        if not isinstance(response_data, dict):
            return {
                "error": "VirusTotal returned an invalid JSON response.",
                "error_type": "invalid_response"
            }

        return {"response_data": response_data}

    error_messages = {
        400: "VirusTotal rejected the request as invalid.",
        401: "The VirusTotal API key is missing or invalid.",
        403: "The VirusTotal project is not permitted to use this endpoint.",
        404: "No existing VirusTotal report was found.",
        429: "The VirusTotal API quota or rate limit was exceeded.",
        500: "VirusTotal encountered an internal error.",
        502: "VirusTotal returned a temporary gateway error.",
        503: "VirusTotal is temporarily unavailable.",
        504: "VirusTotal did not respond through its gateway in time."
    }

    result = {
        "error": error_messages.get(
            response.status_code,
            f"VirusTotal returned HTTP {response.status_code}."
        ),
        "error_type": "http_error",
        "status_code": response.status_code
    }

    if response_data is not None:
        result["details"] = response_data
    elif response.text:
        result["details"] = response.text[:2000]

    return result

def submit_url_for_analysis(url_input, api_key, timeout_seconds):
    """Submit an unknown URL to VirusTotal and return its analysis ID."""
    endpoint = f"{VT_BASE_URL}/urls"

    try:
        response = requests.post(
            endpoint,
            headers=build_headers(api_key),
            data={"url": url_input},
            timeout=timeout_seconds
        )
    except requests.exceptions.Timeout:
        return {
            "error": "VirusTotal did not accept the URL before timeout.",
            "error_type": "timeout"
        }
    except requests.exceptions.SSLError as error:
        return {
            "error": "A secure connection to VirusTotal could not be made.",
            "error_type": "ssl_error",
            "details": str(error)
        }
    except requests.exceptions.ConnectionError as error:
        return {
            "error": (
                "Could not connect to VirusTotal. Check the Internet, "
                "DNS, firewall, VPN or proxy."
            ),
            "error_type": "connection_error",
            "details": str(error)
        }
    except requests.exceptions.RequestException as error:
        return {
            "error": "The URL could not be submitted to VirusTotal.",
            "error_type": "request_error",
            "details": str(error)
        }

    try:
        response_data = response.json()
    except requests.exceptions.JSONDecodeError:
        response_data = None

    if response.status_code not in {200, 201}:
        error_messages = {
            400: "VirusTotal rejected the URL submission.",
            401: "The VirusTotal API key is missing or invalid.",
            403: "The API key cannot submit URLs to VirusTotal.",
            429: "The VirusTotal API quota or rate limit was exceeded.",
            500: "VirusTotal encountered an internal error.",
            502: "VirusTotal returned a temporary gateway error.",
            503: "VirusTotal is temporarily unavailable.",
            504: "VirusTotal did not respond through its gateway in time."
        }
        result = {
            "error": error_messages.get(
                response.status_code,
                f"VirusTotal returned HTTP {response.status_code}."
            ),
            "error_type": "http_error",
            "status_code": response.status_code
        }

        if response_data is not None:
            result["details"] = response_data
        elif response.text:
            result["details"] = response.text[:2000]

        return result

    analysis_id = (response_data or {}).get("data", {}).get("id")

    if not analysis_id:
        return {
            "error": "VirusTotal did not return an analysis ID.",
            "error_type": "invalid_response"
        }

    return {"analysis_id": analysis_id}

def wait_for_analysis(
    analysis_id,
    api_key,
    timeout_seconds,
    max_attempts=URL_ANALYSIS_MAX_ATTEMPTS,
    poll_seconds=URL_ANALYSIS_POLL_SECONDS
):
    """Poll VirusTotal until a submitted analysis is completed."""
    endpoint = f"{VT_BASE_URL}/analyses/{analysis_id}"

    for attempt in range(max_attempts):
        analysis_result = request_vt_report(
            endpoint,
            api_key,
            timeout_seconds
        )

        if "error" in analysis_result:
            return analysis_result

        response_data = analysis_result["response_data"]
        status = (
            response_data.get("data", {})
            .get("attributes", {})
            .get("status", "")
        )

        if status == "completed":
            return {"response_data": response_data}

        if status not in {"queued", "in-progress"}:
            return {
                "error": (
                    "VirusTotal returned an unexpected analysis status: "
                    f"{status or 'unknown'}."
                ),
                "error_type": "invalid_response"
            }

        if attempt < max_attempts - 1:
            time.sleep(poll_seconds)

    maximum_wait = max_attempts * poll_seconds

    return {
        "error": (
            "VirusTotal accepted the resource, but the analysis did not "
            f"finish within {maximum_wait} seconds. Try again shortly."
        ),
        "error_type": "analysis_timeout"
    }

def get_file_upload_endpoint(
    file_size,
    api_key,
    timeout_seconds
):
    """Return the correct VT upload endpoint for a file size."""
    if file_size <= DIRECT_FILE_UPLOAD_LIMIT:
        return {"upload_endpoint": f"{VT_BASE_URL}/files"}

    if file_size > MAX_FILE_UPLOAD_SIZE:
        return {
            "error": (
                "The selected file is larger than VirusTotal's "
                "650 MB upload limit."
            ),
            "error_type": "file_too_large"
        }

    upload_url_result = request_vt_report(
        f"{VT_BASE_URL}/files/upload_url",
        api_key,
        timeout_seconds
    )

    if "error" in upload_url_result:
        return upload_url_result

    upload_endpoint = upload_url_result.get(
        "response_data",
        {}
    ).get("data")

    if not isinstance(upload_endpoint, str) or not upload_endpoint:
        return {
            "error": "VirusTotal did not return a valid file upload URL.",
            "error_type": "invalid_response"
        }

    return {"upload_endpoint": upload_endpoint}
