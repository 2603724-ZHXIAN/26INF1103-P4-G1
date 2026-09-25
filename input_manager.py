"""Collect and validate CLI input for the cybersecurity application.

This module contains only functions. It does not call Gemini, VirusTotal,
SQLite, or any other project manager. The returned dictionary can be passed
to the relevant processing function by the application's main coordinator.
"""

import hashlib
import os
import re
import sys
from urllib.parse import urlparse


APP_TITLE = "CYBER THREAT & SCAM DETECTION ENGINE v1.0"
BANNER_WIDTH = 72
QUIT_COMMANDS = {"Q", "QUIT", "EXIT"}
QUIT_SIGNAL = object()
BACK_SIGNAL = object()

INTERACTION_OPTIONS = {
    "1": "viewed_only",
    "2": "clicked_link",
    "3": "entered_information",
    "4": "opened_or_downloaded_file",
    "5": "made_payment_or_shared_banking_details",
    "6": "other",
}

INTERACTION_DESCRIPTIONS = {
    "viewed_only": (
        "The user viewed the item but took no further action."
    ),
    "clicked_link": (
        "The user clicked a link but did not enter information."
    ),
    "entered_information": (
        "The user entered personal or login information."
    ),
    "opened_or_downloaded_file": (
        "The user opened or downloaded a file."
    ),
    "made_payment_or_shared_banking_details": (
        "The user made a payment or shared banking details."
    ),
}

USE_COLOR = sys.stdout.isatty()
RESET = "\033[0m" if USE_COLOR else ""
BOLD = "\033[1m" if USE_COLOR else ""
DIM = "\033[2m" if USE_COLOR else ""
CYAN = "\033[96m" if USE_COLOR else ""
GREEN = "\033[92m" if USE_COLOR else ""
YELLOW = "\033[93m" if USE_COLOR else ""
RED = "\033[91m" if USE_COLOR else ""
BLUE = "\033[94m" if USE_COLOR else ""


def read_input(prompt):
    """Return user input or QUIT_SIGNAL when the user requests an exit."""
    try:
        value = input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        print("\nExit requested.")
        return QUIT_SIGNAL

    if value.upper() in QUIT_COMMANDS:
        return QUIT_SIGNAL

    return value


def display_banner():
    """Display the application title and main menu."""
    print(CYAN + "=" * BANNER_WIDTH + RESET)
    title = f"{APP_TITLE}".center(BANNER_WIDTH)
    print(BOLD + CYAN + title + RESET)
    print(CYAN + "=" * BANNER_WIDTH + RESET)
    print(f"  {YELLOW}[1]{RESET} Analyze suspicious text or email")
    print(f"  {YELLOW}[2]{RESET} Analyze suspicious URL")
    print(f"  {YELLOW}[3]{RESET} Analyze file path")
    print(f"  {YELLOW}[4]{RESET} Query historical incident database")
    print(f"  {YELLOW}[5]{RESET} View top trending attacks or scams")
    print(f"  {YELLOW}[6]{RESET} Exit")
    print(DIM + "-" * BANNER_WIDTH + RESET)


def get_menu_choice():
    """Return a validated main-menu choice or QUIT_SIGNAL."""
    valid_choices = {"1", "2", "3", "4", "5", "6"}

    while True:
        choice = read_input("Select an option (1-6): > ")

        if choice is QUIT_SIGNAL:
            return QUIT_SIGNAL

        if choice in valid_choices:
            return choice

        print(
            f"  {RED}Invalid choice. Enter a number from 1 to 6."
            f"{RESET}"
        )


def get_multiline_text():
    """Return multiline text or QUIT_SIGNAL."""
    print("\nPaste the message below.")
    print("Type END to finish or QUIT to leave the application.\n")

    while True:
        lines = []

        while True:
            line = read_input("> ")

            if line is QUIT_SIGNAL:
                return QUIT_SIGNAL

            if line.strip().upper() == "END":
                break

            lines.append(line)

        text = "\n".join(lines).strip()

        if text:
            return text

        print(
            f"  {YELLOW}No text was entered. Please try again."
            f"{RESET}"
        )


def normalize_url(url_input):
    """Return a URL with an explicit scheme for consistent storage."""
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url_input):
        return f"https://{url_input}"

    return url_input


def is_valid_url(url_input):
    """Return True when the supplied URL has a valid HTTP(S) host."""
    normalized_url = normalize_url(url_input)
    parsed_url = urlparse(normalized_url)

    return (
        parsed_url.scheme in {"http", "https"}
        and bool(parsed_url.netloc)
        and "." in parsed_url.netloc
        and " " not in parsed_url.netloc
    )


def get_url_input():
    """Return a normalized URL or QUIT_SIGNAL."""
    while True:
        url_input = read_input(
            "Enter the suspicious URL or domain, or QUIT: > "
        )

        if url_input is QUIT_SIGNAL:
            return QUIT_SIGNAL

        if not url_input:
            print(f"  {YELLOW}URL cannot be empty.{RESET}")
            continue

        if is_valid_url(url_input):
            return normalize_url(url_input)

        print(
            f"  {YELLOW}Enter a valid URL, such as "
            f"https://example.com/path.{RESET}"
        )


def get_file_input():
    """Return a file path, BACK_SIGNAL, or QUIT_SIGNAL."""
    while True:
        file_path = read_input(
            "Enter the full file path, BACK, or QUIT: > "
        )

        if file_path is QUIT_SIGNAL:
            return QUIT_SIGNAL

        file_path = file_path.strip('"')

        if file_path.upper() == "BACK":
            return BACK_SIGNAL

        if not file_path:
            print(f"  {YELLOW}File path cannot be empty.{RESET}")
            continue

        if os.path.isfile(file_path):
            return os.path.abspath(file_path)

        print(f"  {RED}No file was found at '{file_path}'.{RESET}")


def display_interaction_options():
    """Display the available user-interaction choices."""
    print("\nWhat did you do with this item?")
    print("  [1] Viewed it only")
    print("  [2] Clicked the link")
    print("  [3] Entered personal or login information")
    print("  [4] Opened or downloaded a file")
    print("  [5] Made payment or shared banking details")
    print("  [6] Other")


def get_interaction_details():
    """Return interaction details or QUIT_SIGNAL."""
    while True:
        display_interaction_options()
        choice = read_input("Select an option (1-6), or QUIT: > ")

        if choice is QUIT_SIGNAL:
            return QUIT_SIGNAL

        if choice not in INTERACTION_OPTIONS:
            print(
                f"  {RED}Invalid choice. Enter a number from 1 to 6."
                f"{RESET}"
            )
            continue

        interaction_type = INTERACTION_OPTIONS[choice]

        if interaction_type != "other":
            description = INTERACTION_DESCRIPTIONS[interaction_type]
            return interaction_type, description

        while True:
            description = read_input("Describe what you did, or QUIT: > ")

            if description is QUIT_SIGNAL:
                return QUIT_SIGNAL

            if description:
                return interaction_type, description

            print(f"  {YELLOW}Description cannot be empty.{RESET}")


def create_text_hash(text_input):
    """Return the SHA-256 hash of a text value."""
    return hashlib.sha256(
        text_input.encode("utf-8")
    ).hexdigest()


def create_file_hash(file_path):
    """Return the SHA-256 hash of a readable local file."""
    sha256_hash = hashlib.sha256()

    with open(file_path, "rb") as file_handle:
        for block in iter(lambda: file_handle.read(4096), b""):
            sha256_hash.update(block)

    return sha256_hash.hexdigest()


def build_submission(
    input_type,
    input_value,
    input_hash,
    interaction_type,
    interaction_description,
    file_path=None,
):
    """Return a standard submission dictionary for another module."""
    return {
        "action": "analyze_submission",
        "input_type": input_type,
        "input_value": input_value,
        "input_hash": input_hash,
        "file_path": file_path,
        "interaction_type": interaction_type,
        "interaction_description": interaction_description,
    }


def collect_text_submission():
    """Collect and return a text submission."""
    print("\n-- Analyze Suspicious Text or Email Message --")
    text = get_multiline_text()

    if text is QUIT_SIGNAL:
        return {"action": "exit"}

    interaction_details = get_interaction_details()

    if interaction_details is QUIT_SIGNAL:
        return {"action": "exit"}

    interaction_type, description = interaction_details

    return build_submission(
        input_type="text",
        input_value=text,
        input_hash=create_text_hash(text),
        interaction_type=interaction_type,
        interaction_description=description,
    )


def collect_url_submission():
    """Collect and return a URL submission."""
    print("\n-- Analyze Suspicious URL --")
    url = get_url_input()

    if url is QUIT_SIGNAL:
        return {"action": "exit"}

    interaction_details = get_interaction_details()

    if interaction_details is QUIT_SIGNAL:
        return {"action": "exit"}

    interaction_type, description = interaction_details

    return build_submission(
        input_type="url",
        input_value=url,
        input_hash=create_text_hash(url),
        interaction_type=interaction_type,
        interaction_description=description,
    )


def collect_file_submission():
    """Collect and return a local-file submission."""
    print("\n-- Analyze Local File --")
    file_path = get_file_input()

    if file_path is QUIT_SIGNAL:
        return {"action": "exit"}

    if file_path is BACK_SIGNAL:
        return None

    interaction_details = get_interaction_details()

    if interaction_details is QUIT_SIGNAL:
        return {"action": "exit"}

    interaction_type, description = interaction_details

    try:
        input_hash = create_file_hash(file_path)
    except (OSError, PermissionError) as error:
        print(f"  {RED}The file could not be read: {error}{RESET}")
        return None

    return build_submission(
        input_type="file",
        input_value=os.path.basename(file_path),
        input_hash=input_hash,
        interaction_type=interaction_type,
        interaction_description=description,
        file_path=file_path,
    )


def collect_history_query():
    """Collect and return historical-database query parameters."""
    print("\n-- Query Historical Incident Database --")
    print("  [1] Search by keyword")
    print("  [2] Filter by risk level")
    print("  [3] Back to main menu")

    while True:
        choice = read_input("Select an option (1-3), or QUIT: > ")

        if choice is QUIT_SIGNAL:
            return {"action": "exit"}

        if choice == "1":
            keyword = read_input("Enter search keyword, or QUIT: > ")

            if keyword is QUIT_SIGNAL:
                return {"action": "exit"}

            if keyword:
                return {
                    "action": "history_query",
                    "query_type": "keyword",
                    "query_value": keyword,
                }

            print(f"  {YELLOW}Keyword cannot be empty.{RESET}")
            continue

        if choice == "2":
            levels = {
                "1": "low",
                "2": "medium",
                "3": "high",
            }
            print("  [1] Low  [2] Medium  [3] High")
            level_choice = read_input(
                "Select risk level (1-3), or QUIT: > "
            )

            if level_choice is QUIT_SIGNAL:
                return {"action": "exit"}

            if level_choice in levels:
                return {
                    "action": "history_query",
                    "query_type": "risk_level",
                    "query_value": levels[level_choice],
                }

            print(f"  {YELLOW}Invalid risk-level choice.{RESET}")
            continue

        if choice == "3":
            return None

        print(f"  {RED}Invalid choice. Enter 1, 2, or 3.{RESET}")


def collect_user_request():
    """Collect one menu request and return it to the caller."""
    display_banner()
    choice = get_menu_choice()

    if choice is QUIT_SIGNAL:
        return {"action": "exit"}

    if choice == "1":
        return collect_text_submission()

    if choice == "2":
        return collect_url_submission()

    if choice == "3":
        return collect_file_submission()

    if choice == "4":
        return collect_history_query()

    if choice == "5":
        return {"action": "view_trending_threats"}

    return {"action": "exit"}


def display_returned_request(request_data):
    """Display returned data when testing this module independently."""
    if request_data is None:
        print(f"{BLUE}[I/O Manager]{RESET} Returning to the main menu.")
        return

    print(f"\n{GREEN}[I/O Manager] Returned data:{RESET}")

    for key, value in request_data.items():
        print(f"  {key}: {value}")


def main():
    """Run this input module independently for testing."""
    while True:
        request_data = collect_user_request()

        if request_data is None:
            print()
            continue

        if request_data.get("action") == "exit":
            print("Thank you for using the Cyber Threat & Scam Detection Engine. Stay alert and stay secure.")
            return

        display_returned_request(request_data)
        print()


if __name__ == "__main__":
    main()
