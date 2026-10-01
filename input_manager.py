import os
import re
import sys
import subprocess

try:
    import validators
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
    import validators


APP_TITLE = "CYBER THREAT & SCAM DETECTION ENGINE v1.0"
BANNER_WIDTH = 72
# VALID_FILE_EXTENSIONS = (".pdf", ".exe", ".xlsx", ".png", ".jpg", ".jpeg")
# URL_PATTERN = re.compile(
#     r"^(https?://)?([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(:\d+)?(/[^\s]*)?$"
# )

USE_COLOR = sys.stdout.isatty()
RESET = "\033[0m" if USE_COLOR else ""
BOLD = "\033[1m" if USE_COLOR else ""
DIM = "\033[2m" if USE_COLOR else ""
CYAN = "\033[96m" if USE_COLOR else ""
GREEN = "\033[92m" if USE_COLOR else ""
YELLOW = "\033[93m" if USE_COLOR else ""
RED = "\033[91m" if USE_COLOR else ""
BLUE = "\033[94m" if USE_COLOR else ""

while True:
    # Banner Display
    print(CYAN + "=" * BANNER_WIDTH + RESET)
    print(BOLD + CYAN + f"🛡️  {APP_TITLE}".center(BANNER_WIDTH) + RESET)
    print(CYAN + "=" * BANNER_WIDTH + RESET)
    print(f"  {YELLOW}[1]{RESET} 📧 Analyze Suspicious Text / Scam Email Message")
    print(f"  {YELLOW}[2]{RESET} 🔗 Analyze Suspicious URL")
    # print(f"  {YELLOW}[3]{RESET} 📎 Analyze File or Image (Path / Screenshot)")
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
     
        print(f"{BLUE}[I/O Manager]{RESET} 🛠️  Captured text input ({len(text)} characters).")
        print(f"{BLUE}[I/O Manager]{RESET} 🛠️  Submission of text is being process, please wait...")
        # TODO: pass `text` to ai_manager / logic_manager here

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
        # TODO: pass `url` to ai_manager / logic_manager here

    # --- Option 3: file path ---
    elif choice == "3":
        print("\n📎 -- Analyze File or Image (Path / Screenshot) --")
        # print(f"Accepted types: {', '.join(VALID_FILE_EXTENSIONS)}\n")
        while True:
            path = input("Enter the full file path: > ").strip().strip('"')
            if not path:
                print(f"  {YELLOW}⚠️  File path cannot be empty.{RESET}")
                continue

            # Check if it'a valid file path stored locally
            if not os.path.isfile(path): 
                print(f"  {RED}❌ No file found at '{path}'.{RESET}")
                retry = input("    Try a different path? (y/n): > ").strip().lower()
                if retry == "y":
                    continue
                else:
                    print(f"{BLUE}[I/O Manager]{RESET} 🛠️  User proceeded with an unverified file path.")
                    break

            # ext = os.path.splitext(path)[1].lower() # extension of file 
            filename = os.path.basename(path) # file name 
            # if ext not in VALID_FILE_EXTENSIONS: # restriction of files
            #     print(f"  {YELLOW}⚠️  '{ext}' is not an acceptable extension.{RESET}")
            #     proceed = input("    Analyze anyway? (y/n): > ").strip().lower()
            #     if proceed != "y":
            #         continue

            print(f"\n{GREEN}✅ File '{filename}' accepted for analysis.{RESET}\n")
            break

        print(f"{BLUE}[I/O Manager]{RESET} 🛠️  Submission of file '{filename}' is being handed off for analysis...")
        # TODO: pass `path` to ai_manager / logic_manager here

    # --- Option 4: Historical database query ---
    elif choice == "4":
        import data_manager as db
        from config import DB_PATH
        
        def format_result(r):
            # Shorten timestamp (e.g. 2026-10-01T09:26:45.923... -> 2026-10-01 09:26)
            dt = str(r.get("created_at", ""))[:16].replace("T", " ")
            
            # Format preview (40 characters)
            val = str(r.get("input_value", "")).replace("\n", " ").strip()
            preview = (val[:40] + "...") if len(val) > 40 else val
            
            # Color risk
            risk = str(r.get("risk_category", "Unknown")).lower()
            if risk == "high":
                colored_risk = f"{RED}{risk}{RESET}"
            elif risk in ("moderate", "medium"):
                colored_risk = f"{YELLOW}{risk}{RESET}"
            else:
                colored_risk = f"{GREEN}{risk}{RESET}"
                
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

    # --- Option 6: Exit ---
    elif choice == "6":
        confirm = input("Are you sure you want to exit? (y/n): > ").strip().lower()
        if confirm == "y":
            print(f"{BLUE}[I/O Manager]{RESET} 🛠️  Session terminated by user. Goodbye ~")
            sys.exit(0)
    print() 