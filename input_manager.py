import hashlib
import os
import subprocess
import sys


try:
    import validators
except ImportError:
    subprocess.check_call(
        [sys.executable, "-m", "pip", "install", "-r", "requirements.txt"]
    )
    import validators

import data_manager as db
from config import DB_PATH


APP_TITLE = "CYBER THREAT & SCAM DETECTION ENGINE v1.0"
BANNER_WIDTH = 72

USE_COLOR = sys.stdout.isatty()
RESET = "\033[0m" if USE_COLOR else ""
BOLD = "\033[1m" if USE_COLOR else ""
DIM = "\033[2m" if USE_COLOR else ""
CYAN = "\033[96m" if USE_COLOR else ""
GREEN = "\033[92m" if USE_COLOR else ""
YELLOW = "\033[93m" if USE_COLOR else ""
RED = "\033[91m" if USE_COLOR else ""
BLUE = "\033[94m" if USE_COLOR else ""

IO_TAG = f"{BLUE}[I/O Manager]{RESET}"


def generate_hash(value):
    """Return the SHA-256 hex digest of a string."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def collect_user_interaction():
    """Ask what the user did before submitting the item for analysis."""
    interactions = {
        "1": "viewed_only",
        "2": "clicked_link",
        "3": "entered_information",
        "4": "opened_or_downloaded_file",
        "5": "made_payment_or_shared_banking_details",
        "6": "other"
    }

    print("\nWHAT ACTIONS HAVE YOU ALREADY TAKEN?")
    print("[1] Only viewed the message or item; took no further action")
    print("[2] Clicked a link")
    print("[3] Entered personal information, login details, or an OTP")
    print("[4] Opened or downloaded a file")
    print("[5] Made a payment or shared banking details")
    print("[6] Other, or more than one of these actions")

    while True:
        choice = input("Select an option (1-6): > ").strip()

        if choice in interactions:
            break

        print("Invalid choice. Please enter a number between 1 and 6.")

    interaction_type = interactions[choice]
    interaction_description = None

    if interaction_type == "other":
        print(
            "\nDescribe every action you took. "
            "Do not include passwords, OTPs, or account numbers."
        )

        while True:
            interaction_description = input("> ").strip()

            if interaction_description:
                break

            print("Please describe what happened.")

    return interaction_type, interaction_description


def collect_user_request():
    """Show the main menu and return the user's request as a dict."""
    while True:
        # Banner Display
        print(CYAN + "=" * BANNER_WIDTH + RESET)
        print(BOLD + CYAN + f"🛡️  {APP_TITLE}".center(BANNER_WIDTH) + RESET)
        print(CYAN + "=" * BANNER_WIDTH + RESET)
        print(
            f"  {YELLOW}[1]{RESET} 📧 "
            "Analyze Suspicious Text / Scam Email Message"
        )
        print(f"  {YELLOW}[2]{RESET} 🔗 Analyze Suspicious URL")
        print(f"  {YELLOW}[3]{RESET} 📎 Analyze File (Path)")
        print(f"  {YELLOW}[4]{RESET} 🗄️  Query Historical Incident Database")
        print(f"  {YELLOW}[5]{RESET} 📈 Top Trending Attacks / Scams")
        print(
            f"  {YELLOW}[6]{RESET} 🌐 "
            "Emerging Threat & Scam Radar (Live Web Grounding)"
        )
        print(f"  {YELLOW}[7]{RESET} 🚪 Exit")
        print(DIM + "-" * BANNER_WIDTH + RESET)

        # Menu Options
        choice = input("Select an option (1-7): > ").strip()
        while choice not in {"1", "2", "3", "4", "5", "6", "7"}:
            print(
                f"  {RED}❌ Invalid choice. "
                f"Please enter a number between 1 and 7.{RESET}"
            )
            choice = input("Select an option (1-7): > ").strip()
        print(f"{IO_TAG} 🛠️  Option [{choice}] has been selected.")

        # --- Option 1: text/email body ---
        if choice == "1":
            print("\n📧 -- Analyze Suspicious Text / Scam Email Message --")
            print(
                "Paste the message below. "
                "Type END on a new line when finished.\n"
            )
            lines = []
            while True:
                line = input("> ")
                if line.strip().upper() == "END":
                    break
                lines.append(line)
            text = "\n".join(lines).strip()

            while not text:
                print(
                    f"  {YELLOW}⚠️  No text was entered. Type NO to exit, "
                    f"or type your message to continue.{RESET}"
                )
                text = input("> ").strip()
                if text.upper() == "NO":
                    text = ""
                    break
                else:
                    continue

            if text:
                interaction_type, interaction_description = (
                    collect_user_interaction()
                )

                print(
                    "\n[I/O Manager] Captured text input "
                    f"({len(text)} characters)."
                )
                print(
                    "[I/O Manager] Submission of text is being processed, "
                    "please wait..."
                )

                return {
                    "action": "analyze_submission",
                    "input_type": "text",
                    "input_value": text,
                    "input_hash": generate_hash(text),
                    "interaction_type": interaction_type,
                    "interaction_description": interaction_description
                }

        # --- Option 2: URL ---
        elif choice == "2":
            print("\n🔗 -- Analyze Suspicious URL --")
            while True:
                url = input("Enter the suspicious URL or domain: > ").strip()
                if not url:
                    print(f"  {YELLOW}⚠️  URL cannot be empty.{RESET}")
                    continue
                if validators.url(url) or validators.domain(url):
                    print(
                        f"  {GREEN}✅ URL '{url}' "
                        f"accepted for analysis.{RESET}"
                    )
                    break
                else:
                    print(
                        f"  {YELLOW}⚠️  That doesn't look like a valid "
                        "URL/domain (e.g. example.com or "
                        f"https://example.com/path). Try again.{RESET}"
                    )
                    continue

            print(
                f"{IO_TAG} 🛠️  "
                "Submission of url website is being analyse..."
            )
            interaction_type, interaction_description = (
                collect_user_interaction()
            )

            print(
                f"{IO_TAG} 🛠️  "
                "Submission of url website is being analyse..."
            )

            return {
                "action": "analyze_submission",
                "input_type": "url",
                "input_value": url,
                "input_hash": generate_hash(url),
                "interaction_type": interaction_type,
                "interaction_description": interaction_description
            }

        # --- Option 3: file path ---
        elif choice == "3":
            print("\n📎 -- Analyze File (Path) --")

            while True:
                path = input(
                    "Enter the full file path, or BACK for the menu: > "
                ).strip().strip('"')

                if path.upper() == "BACK":
                    print(f"{IO_TAG} 🛠️  Returning to main menu.")
                    break

                if not path:
                    print(f"  {YELLOW}⚠️  File path cannot be empty.{RESET}")
                    continue

                if not os.path.isfile(path):
                    print(f"  {RED}❌ No file found at '{path}'.{RESET}")

                    retry = input(
                        "    Try a different path? (y/n): > "
                    ).strip().lower()

                    if retry == "y":
                        continue

                    print(
                        f"{IO_TAG} "
                        "🛠️  Submission cancelled. Returning to main menu."
                    )
                    break

                filename = os.path.basename(path)

                print(
                    f"\n{GREEN}✅ File '{filename}' "
                    f"accepted for analysis.{RESET}\n"
                )

                interaction_type, interaction_description = (
                    collect_user_interaction()
                )

                print(
                    f"{IO_TAG} 🛠️  "
                    f"Submission of file '{filename}' "
                    "is being handed off for analysis..."
                )

                return {
                    "action": "analyze_submission",
                    "input_type": "file",
                    "input_value": filename,
                    "input_hash": generate_hash(path),
                    "file_path": path,
                    "interaction_type": interaction_type,
                    "interaction_description": interaction_description
                }

        # --- Option 4: Historical database query ---
        elif choice == "4":
            def format_result(r):
                dt = str(r.get("created_at", ""))[:16].replace("T", " ")
                val = str(r.get("input_value", "")).replace("\n", " ").strip()
                preview = (val[:40] + "...") if len(val) > 40 else val
                risk = str(r.get("risk_category", "Unknown")).lower()
                if risk == "high":
                    colored_risk = f"{RED}{risk}{RESET}"
                elif risk in ("moderate", "medium"):
                    colored_risk = f"{YELLOW}{risk}{RESET}"
                else:
                    colored_risk = f"{GREEN}{risk}{RESET}"
                return (
                    f"  - [{dt}] ID: {r['submission_id']} "
                    f"| Type: {r['input_type']} "
                    f"| Preview: \"{preview}\" "
                    f"| Risk: {colored_risk}"
                )

            print("\n🗄️  -- Query Historical Incident Database --")
            print("  [1] Search by keyword")
            print("  [2] Filter by risk level (Low / Moderate / High)")
            print("  [3] Back to main menu")

            sub_choice = input("Select an option (1-3): > ").strip()
            while sub_choice not in {"1", "2", "3"}:
                print(
                    f"  {YELLOW}⚠️  Invalid choice. "
                    f"Please enter a number 1, 2 or 3.{RESET}"
                )
                sub_choice = input("Select an option (1-3): > ").strip()

            results = []
            if sub_choice == "1":
                keyword = input("Enter search keyword: > ").strip()
                print(
                    f"{IO_TAG} 🛠️  "
                    f"Querying records for keyword '{keyword}'."
                )
                results = db.search_records(DB_PATH, keyword)
                if not results:
                    print(
                        f"  {YELLOW}⚠️  No records found for "
                        f"'{keyword}'.{RESET}"
                    )

            elif sub_choice == "2":
                levels = {"1": "Low", "2": "Moderate", "3": "High"}
                print("  [1] Low  [2] Moderate  [3] High ")
                lvl_choice = input("Select risk level (1-3): > ").strip()
                while lvl_choice not in levels:
                    print(f"  {YELLOW}⚠️  Invalid risk level.{RESET}")
                    lvl_choice = input("Select risk level (1-3): > ").strip()

                selected_level = levels[lvl_choice].lower()
                print(
                    f"{IO_TAG} 🛠️  "
                    f"Querying records at risk level '{levels[lvl_choice]}'."
                )

                with db.database_connection(DB_PATH) as conn:
                    query = (
                        "SELECT s.submission_id, s.input_type, "
                        "s.created_at, s.input_value, fa.risk_category "
                        "FROM submission s JOIN final_assessment fa "
                        "ON s.submission_id = fa.submission_id "
                        "WHERE fa.risk_category = ?"
                    )
                    rows = conn.execute(query, (selected_level,)).fetchall()
                    results = [dict(row) for row in rows]

                if not results:
                    print(
                        f"  {YELLOW}⚠️  No records found for risk "
                        f"'{levels[lvl_choice]}'.{RESET}"
                    )

            elif sub_choice == "3":
                print(f"{IO_TAG} 🛠️  Returning to main menu.")

            if results:
                for r in results:
                    print(format_result(r))

                print()
                view_id = input(
                    "Enter an ID to view full details "
                    "(or press Enter to go back): > "
                ).strip()
                if view_id.isdigit():
                    report = db.get_submission_report(DB_PATH, int(view_id))
                    if report:
                        rule = f"{CYAN}{'=' * BANNER_WIDTH}{RESET}"
                        print(f"\n{rule}")
                        print(
                            f"{BOLD}FULL INCIDENT REPORT "
                            f"(ID: {view_id}){RESET}"
                        )
                        print(rule)
                        for k, v in report.items():
                            if v is not None and v != "":
                                label = str(k).replace("_", " ").title()
                                print(f"{BOLD}{label}:{RESET} {v}")
                        print(rule)
                        input("\nPress Enter to return to menu...")
                    else:
                        print(
                            f"  {YELLOW}⚠️  No report found for ID "
                            f"{view_id}.{RESET}"
                        )

        # --- Option 5: Common Threat Summaries (Low/Moderate/High) ---
        elif choice == "5":
            from pick import pick
            print(f"{IO_TAG} 🛠️  Fetching top trending attacks/scams.")

            threats = db.get_top_threat_types(DB_PATH)
            counts = db.get_risk_category_counts(DB_PATH)

            print(f"\n{BOLD}{CYAN}📈 Top Trending Attacks / Scams{RESET}")
            print("-" * BANNER_WIDTH)
            if not threats:
                print("  No threat data available.")
            else:
                for i, t in enumerate(threats, 1):
                    threat_type = t.get("primary_threat_type", "Unknown")
                    total = t.get("total", 0)
                    print(
                        f"  {YELLOW}{i}.{RESET} "
                        f"{threat_type} ({total} incidents)"
                    )

            print(f"\n{BOLD}{CYAN}📊 Risk Category Breakdown{RESET}")
            print("-" * BANNER_WIDTH)
            if not counts:
                print("  No risk category data available.")
            else:
                for c in counts:
                    risk = c.get("risk_category", "Unknown").capitalize()
                    total = c.get("total", 0)
                    print(f"  - {risk}: {total} incidents")

            # --- Allow user to explore a trending threat ---
            if threats:
                print("\nSelect a threat type to view its latest incidents.")
                print("Enter 0 to return to the main menu.")

                while True:
                    selection = input(
                        f"Select an option (0-{len(threats)}): > "
                    ).strip()

                    if selection == "0":
                        break

                    if not selection.isdigit():
                        print(
                            f"{YELLOW}⚠️  Please enter a valid number.{RESET}"
                        )
                        continue

                    selection = int(selection)

                    if selection < 1 or selection > len(threats):
                        print(
                            f"{YELLOW}⚠️  Please select one of the "
                            f"listed threat types.{RESET}"
                        )
                        continue

                    selected_threat = threats[
                        selection - 1
                    ]["primary_threat_type"]


                    # Retrieve latest incidents for selected threat type
                    results = db.get_incidents_by_threat_type(
                        DB_PATH,
                        selected_threat
                    )

                    if not results:
                        print(
                            f"{YELLOW}⚠️  No incidents found for "
                            f"'{selected_threat}'.{RESET}"
                        )
                        break

                    # --- Display selectable incident list ---
                    BACK_LABEL = "← Back to menu"
                    PREVIEW_LEN = 70
                    QUIT_KEYS = (ord("q"), ord("Q"), 27)

                    def make_label(r):
                        val = str(
                            r.get("input_value", "")
                        ).replace("\n", " ").strip()

                        preview = (
                            val[:PREVIEW_LEN] + "..."
                            if len(val) > PREVIEW_LEN
                            else val
                        )

                        risk = str(
                            r.get("risk_category", "Unknown")
                        ).upper()

                        return (
                            f"ID:{r['submission_id']} | "
                            f"{r['input_type'][:4]} | "
                            f"{risk:8} | "
                            f"\"{preview}\""
                        )

                    while True:
                        options = [BACK_LABEL] + [
                            make_label(r) for r in results
                        ]

                        title = (
                            f"📈 {selected_threat.upper()} INCIDENTS"
                            "  —  ↑↓ navigate   Enter open   "
                            "q / Esc = back"
                        )

                        selected_label, idx = pick(
                            options,
                            title,
                            indicator="▶",
                            default_index=1,
                            quit_keys=QUIT_KEYS
                        )

                        # User selected Back, q, Q or Esc
                        if selected_label is None or idx < 1:
                            break

                        selected_r = results[idx - 1]

                        report = db.get_submission_report(
                            DB_PATH,
                            selected_r["submission_id"]
                        )

                        if report:
                            print(
                                f"\n{CYAN}"
                                f"{'=' * BANNER_WIDTH}"
                                f"{RESET}"
                            )

                            print(
                                f"{BOLD}FULL INCIDENT REPORT "
                                f"(ID: "
                                f"{selected_r['submission_id']})"
                                f"{RESET}"
                            )

                            print(
                                f"{CYAN}"
                                f"{'=' * BANNER_WIDTH}"
                                f"{RESET}"
                            )

                            for k, v in report.items():
                                if v is not None and v != "":
                                    label = (
                                        str(k)
                                        .replace("_", " ")
                                        .title()
                                    )

                                    print(
                                        f"{BOLD}{label}:{RESET} {v}"
                                    )

                            print(
                                f"{CYAN}"
                                f"{'=' * BANNER_WIDTH}"
                                f"{RESET}"
                            )

                            input(
                                "\nPress Enter to return "
                                "to results list..."
                            )

                        else:
                            print(
                                f"{YELLOW}⚠️  No report found "
                                f"for that ID.{RESET}"
                            )

                            input(
                                "\nPress Enter to continue..."
                            )

                    # Finished exploring selected threat
                    break

            print()

            # loops back to menu for option 5

        # --- Option 6: Emerging Threat & Scam Radar ---
        elif choice == "6":
            print(
                f"\n{BOLD}{CYAN}🌐 -- Emerging Threat & Scam Radar "
                f"(Live AI Web Grounding) --{RESET}"
            )
            print(
                "Enter a specific topic or keyword (e.g. 'Telegram investment', 'CPF SMS', 'Invoice fraud'),"
            )
            print(
                "or press ENTER to scan all top emerging threats right now:\n"
            )
            topic = input("> ").strip()
            return {
                "action": "emerging_threat_radar",
                "topic": topic if topic else None
            }

        # --- Option 7: Exit ---
        elif choice == "7":
            confirm = input(
                "Are you sure you want to exit? (y/n): > "
            ).strip().lower()
            if confirm == "y":
                return {"action": "exit"}
        print()