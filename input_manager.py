import os
import sys
import subprocess
import hashlib
import curses
import locale

try:
    import validators
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
    import validators


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

def generate_hash(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()

def browse_results(results, title="HISTORICAL INCIDENT RESULTS"):
    """Show results in a coloured, scrollable table.
    Returns the index of the chosen result, or None if the user quits."""
    locale.setlocale(locale.LC_ALL, "")
    os.environ.setdefault("ESCDELAY", "25")  # make Esc respond instantly

    def run(stdscr):
        curses.curs_set(0)
        curses.use_default_colors()
        for i, c in enumerate(
            (curses.COLOR_CYAN, curses.COLOR_GREEN, curses.COLOR_YELLOW, curses.COLOR_RED), 1
        ):
            curses.init_pair(i, c, -1)
        cyan, green, yellow, red = (curses.color_pair(i) for i in (1, 2, 3, 4))
        risk_colors = {"high": red, "moderate": yellow, "medium": yellow, "low": green}

        def put(y, x, text, attr=0):
            h, w = stdscr.getmaxyx()
            if 0 <= y < h and x < w - 1:
                try:
                    stdscr.addstr(y, x, text[: w - 1 - x], attr)
                except curses.error:
                    pass

        pos = top = 0
        while True:
            stdscr.erase()
            h, w = stdscr.getmaxyx()
            visible = max(1, h - 6)
            preview_w = max(10, w - 34)

            # Title + header
            put(0, 0, title.center(w - 1), cyan | curses.A_BOLD)
            put(1, 0, "═" * (w - 1), cyan)
            put(2, 0, f"  {'ID':<5}│ {'Type':<5}│ {'Risk':<9}│ Preview", curses.A_BOLD)
            put(3, 0, "─" * (w - 1), cyan)

            # Keep the cursor inside the visible window
            if pos < top:
                top = pos
            elif pos >= top + visible:
                top = pos - visible + 1

            # Rows
            for row, r in enumerate(results[top: top + visible]):
                i = top + row
                val = str(r.get("input_value", "")).replace("\n", " ").strip()
                preview = val if len(val) <= preview_w else val[: preview_w - 3] + "..."
                risk = str(r.get("risk_category", "Unknown")).lower()
                line_a = f"{r['submission_id']:<5}│ {str(r['input_type']):<5}│ "
                y = 4 + row

                if i == pos:  # highlighted row: all green + bold
                    attr = green | curses.A_BOLD
                    put(y, 0, "▶ " + line_a + f"{risk.upper():<9}│ {preview}", attr)
                else:
                    put(y, 0, "  " + line_a)
                    put(y, 2 + len(line_a), f"{risk.upper():<9}", risk_colors.get(risk, 0) | curses.A_BOLD)
                    put(y, 2 + len(line_a) + 9, f"│ {preview}")

            # Footer
            put(h - 2, 0, "─" * (w - 1), cyan)
            put(h - 1, 0, f" ↑↓ move   Enter open   q/Esc back   [{pos + 1}/{len(results)}]", curses.A_DIM)
            stdscr.refresh()

            key = stdscr.getch()
            if key in (curses.KEY_UP, ord("k")):
                pos = max(0, pos - 1)
            elif key in (curses.KEY_DOWN, ord("j")):
                pos = min(len(results) - 1, pos + 1)
            elif key == curses.KEY_PPAGE:
                pos = max(0, pos - visible)
            elif key == curses.KEY_NPAGE:
                pos = min(len(results) - 1, pos + visible)
            elif key == curses.KEY_HOME:
                pos = 0
            elif key == curses.KEY_END:
                pos = len(results) - 1
            elif key in (10, 13, curses.KEY_ENTER):
                return pos
            elif key in (ord("q"), ord("Q"), 27):
                return None

    return curses.wrapper(run)


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
    while True:
        # Banner Display
        print(CYAN + "=" * BANNER_WIDTH + RESET)
        print(BOLD + CYAN + f"🛡️  {APP_TITLE}".center(BANNER_WIDTH) + RESET)
        print(CYAN + "=" * BANNER_WIDTH + RESET)
        print(f"  {YELLOW}[1]{RESET} 📧 Analyze Suspicious Text / Scam Email Message")
        print(f"  {YELLOW}[2]{RESET} 🔗 Analyze Suspicious URL")
        print(f"  {YELLOW}[3]{RESET} 📎 Analyze File (Path)")
        print(f"  {YELLOW}[4]{RESET} 🗄️  Query Historical Incident Database")
        print(f"  {YELLOW}[5]{RESET} 📈 Top Trending Attacks / Scams")
        print(f"  {YELLOW}[6]{RESET} 🚪 Exit")
        print(DIM + "-" * BANNER_WIDTH + RESET)

        # Menu Options 
        choice = input("Select an option (1-6): > ").strip()
        while choice not in {"1", "2", "3", "4", "5", "6"}:
            print(f"  {RED}❌ Invalid choice. Please enter a number between 1 and 6.{RESET}")
            choice = input("Select an option (1-6): > ").strip()
        print(f"{BLUE}[I/O Manager]{RESET} 🛠️  Option [{choice}] has been selected.")

        # --- Option 1: text/email body ---
        if choice == "1":
            print("\n📧 -- Analyze Suspicious Text / Scam Email Message --")
            print("Paste the message below. Type END on a new line when finished.\n")
            lines = []
            while True:
                line = input("> ")
                if line.strip().upper() == "END":
                    break
                lines.append(line)
            text = "\n".join(lines).strip()
            
            while not text:
                print(f"  {YELLOW}⚠️  No text was entered. Type NO to exit, or type your message to continue.{RESET}") 
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
                    f"\n[I/O Manager] Captured text input "
                    f"({len(text)} characters)."
                )
                print("[I/O Manager] Submission of text is being processed, please wait...")

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
                    print(f"  {GREEN}✅ URL '{url}' accepted for analysis.{RESET}")
                    break
                else:
                    print(f"  {YELLOW}⚠️  That doesn't look like a valid URL/domain "
                      f"(e.g. example.com or https://example.com/path). Try again.{RESET}")
                    continue

            print(f"{BLUE}[I/O Manager]{RESET} 🛠️  Submission of url website is being analyse...")
            interaction_type, interaction_description = (
                collect_user_interaction()
            )

            print(f"{BLUE}[I/O Manager]{RESET} 🛠️  Submission of url website is being analyse...")

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
                    print(
                        f"{BLUE}[I/O Manager]{RESET} "
                        "🛠️  Returning to main menu."
                    )
                    break

                if not path:
                    print(
                        f"  {YELLOW}⚠️  File path cannot be empty.{RESET}"
                    )
                    continue

                if not os.path.isfile(path):
                    print(f"  {RED}❌ No file found at '{path}'.{RESET}")

                    retry = input(
                        "    Try a different path? (y/n): > "
                    ).strip().lower()

                    if retry == "y":
                        continue

                    print(
                        f"{BLUE}[I/O Manager]{RESET} "
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
                    f"{BLUE}[I/O Manager]{RESET} 🛠️  "
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
            import data_manager as db
            from config import DB_PATH
            
            def format_result(r):
                dt = str(r.get("created_at", ""))[:16].replace("T", " ")
                val = str(r.get("input_value", "")).replace("\n", " ").strip()
                preview = (val[:40] + "...") if len(val) > 40 else val
                risk = str(r.get("risk_category", "Unknown")).lower()
                if risk == "high": colored_risk = f"{RED}{risk}{RESET}"
                elif risk in ("moderate", "medium"): colored_risk = f"{YELLOW}{risk}{RESET}"
                else: colored_risk = f"{GREEN}{risk}{RESET}"
                return f"  - [{dt}] ID: {r['submission_id']} | Type: {r['input_type']} | Preview: \"{preview}\" | Risk: {colored_risk}"

            print("\n🗄️  -- Query Historical Incident Database --")
            print("  [1] Search by keyword")
            print("  [2] Filter by risk level (Low / Moderate / High)")
            print("  [3] Back to main menu")

            sub_choice = input("Select an option (1-3): > ").strip()
            while sub_choice not in {"1", "2", "3"}:
                print(f"  {YELLOW}⚠️  Invalid choice. Please enter a number 1, 2 or 3.{RESET}")
                sub_choice = input("Select an option (1-3): > ").strip()

            results = []
            if sub_choice == "1":
                keyword = input("Enter search keyword: > ").strip()
                print(f"{BLUE}[I/O Manager]{RESET} 🛠️  Querying records for keyword '{keyword}'.")
                results = db.search_records(DB_PATH, keyword)
                if not results:
                    print(f"  {YELLOW}⚠️  No records found for '{keyword}'.{RESET}")

            elif sub_choice == "2":
                levels = {"1": "Low", "2": "Moderate", "3": "High"}
                print("  [1] Low  [2] Moderate  [3] High ")
                lvl_choice = input("Select risk level (1-3): > ").strip()
                while lvl_choice not in levels:
                    print(f"  {YELLOW}⚠️  Invalid risk level.{RESET}")
                    lvl_choice = input("Select risk level (1-3): > ").strip()
                
                selected_level = levels[lvl_choice].lower()
                print(f"{BLUE}[I/O Manager]{RESET} 🛠️  Querying records at risk level '{levels[lvl_choice]}'.")
                
                with db.database_connection(DB_PATH) as conn:
                    results = [dict(row) for row in conn.execute(
                        "SELECT s.submission_id, s.input_type, s.created_at, s.input_value, fa.risk_category "
                        "FROM submission s JOIN final_assessment fa ON s.submission_id = fa.submission_id "
                        "WHERE fa.risk_category = ?",
                        (selected_level,)
                    ).fetchall()]
                
                if not results:
                    print(f"  {YELLOW}⚠️  No records found for risk '{levels[lvl_choice]}'.{RESET}")

            elif sub_choice == "3":
                print(f"{BLUE}[I/O Manager]{RESET} 🛠️  Returning to main menu.")

            if results:
                while True:
                    idx = browse_results(results)
                    if idx is None:
                        break

                    selected_r = results[idx]
                    report = db.get_submission_report(DB_PATH, selected_r["submission_id"])
                    if report:
                        print(f"\n{CYAN}{'='*BANNER_WIDTH}{RESET}")
                        print(f"{BOLD}FULL INCIDENT REPORT (ID: {selected_r['submission_id']}){RESET}")
                        print(f"{CYAN}{'='*BANNER_WIDTH}{RESET}")
                        for k, v in report.items():
                            if v is not None and v != "":
                                label = str(k).replace("_", " ").title()
                                print(f"{BOLD}{label}:{RESET} {v}")
                        print(f"{CYAN}{'='*BANNER_WIDTH}{RESET}")
                        input("\nPress Enter to return to results list...")
                    else:
                        print(f"  {YELLOW}⚠️  No report found for that ID.{RESET}")
                        input("\nPress Enter to continue...")


        # --- Option 5: Common Threat Summaries (Low/Moderate/High)  ---
        elif choice == "5":
            import data_manager as db
            from config import DB_PATH
            print(f"{BLUE}[I/O Manager]{RESET} 🛠️  Fetching top trending attacks/scams.")
            
            threats = db.get_top_threat_types(DB_PATH)
            counts = db.get_risk_category_counts(DB_PATH)
            
            print(f"\n{BOLD}{CYAN}📈 Top Trending Attacks / Scams{RESET}")
            print("-" * BANNER_WIDTH)
            if not threats:
                print("  No threat data available.")
            else:
                for i, t in enumerate(threats, 1):
                    threat_type = t.get('primary_threat_type', 'Unknown')
                    total = t.get('total', 0)
                    print(f"  {YELLOW}{i}.{RESET} {threat_type} ({total} incidents)")
                    
            print(f"\n{BOLD}{CYAN}📊 Risk Category Breakdown{RESET}")
            print("-" * BANNER_WIDTH)
            if not counts:
                print("  No risk category data available.")
            else:
                for c in counts:
                    risk = c.get('risk_category', 'Unknown').capitalize()
                    total = c.get('total', 0)
                    print(f"  - {risk}: {total} incidents")
            print()
            # loops back to menu for option 5

        # --- Option 6: Exit ---
        elif choice == "6":
            confirm = input("Are you sure you want to exit? (y/n): > ").strip().lower()
            if confirm == "y":
                return {"action": "exit"}
        print()