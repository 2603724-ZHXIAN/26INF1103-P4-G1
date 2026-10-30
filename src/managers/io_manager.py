"""Presentation layer: Terminal UI and user interaction manager.

Strict Separation of Concerns:
- Handles CLI formatting, banners, prompts, curses/pick table navigation, and input validation.
- Encapsulates terminal styling properties (_use_color, _banner_width, _theme_colors).
- Does NOT calculate threat scores (delegates to LogicManager and AI layers).
- Does NOT execute raw SQL queries directly (delegates historical & trending queries to DataManager).
"""

import curses
import hashlib
import locale
import os
import sys
from typing import Any, Dict, List, Optional, Tuple, Union

# Handle platform-specific console encoding for Unicode emojis
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

import validators

try:
    from pick import pick
except ImportError:
    pick = None

from ..config import DB_PATH
from ..models.assessment import AssessmentResult
from ..models.submission import Submission

try:
    from .data_manager import DataManager
    default_db = DataManager()
except ImportError:
    default_db = None


DEFAULT_THEME_COLORS: Dict[str, str] = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "cyan": "\033[96m",
    "green": "\033[92m",
    "yellow": "\033[93m",
    "red": "\033[91m",
    "blue": "\033[94m",
    "magenta": "\033[95m",
}


class IOManager:
    """Terminal presentation layer for input collection, validation, and formatted reporting.

    Demonstrates OOP Rubric Principles:
    - Encapsulation: Protected styling properties (_use_color, _banner_width, _theme_colors, _data_manager)
      with validated @property getters and setters.
    - Separation of Concerns: Strictly limits scope to UI formatting and interaction; delegates
      all threat evaluation to LogicManager and all persistence/query operations to DataManager.
    """

    APP_TITLE: str = "CYBER THREAT & SCAM DETECTION ENGINE v1.0"

    INTERACTION_OPTIONS: Dict[str, str] = {
        "1": "viewed_only",
        "2": "clicked_link",
        "3": "entered_information",
        "4": "opened_or_downloaded_file",
        "5": "made_payment_or_shared_banking_details",
        "6": "other",
    }

    INTERACTION_LABELS: Dict[str, str] = {
        "viewed_only": "You viewed the message or item only.",
        "clicked_link": "You clicked the link but did not report entering any information.",
        "entered_information": "You entered personal or login information.",
        "opened_or_downloaded_file": "You opened or downloaded a file.",
        "made_payment_or_shared_banking_details": "You made a payment or shared banking details.",
        "other": "You reported another type of interaction.",
    }

    def __init__(
        self,
        use_color: Optional[bool] = None,
        banner_width: int = 72,
        theme_colors: Optional[Dict[str, str]] = None,
        data_manager: Optional[Any] = None,
        db_path: Optional[str] = None,
    ) -> None:
        """Initialise IOManager styling, dependency references, and terminal settings."""
        self._use_color: bool = sys.stdout.isatty() if use_color is None else bool(use_color)
        self.use_color = self._use_color

        self._banner_width: int = 72
        self.banner_width = banner_width

        self._theme_colors: Dict[str, str] = dict(DEFAULT_THEME_COLORS)
        if theme_colors is not None:
            self.theme_colors = theme_colors

        self._data_manager: Any = data_manager if data_manager is not None else default_db
        self._db_path: str = str(db_path or DB_PATH)

    # -------------------------------------------------------------------------
    # Properties & Encapsulation
    # -------------------------------------------------------------------------

    @property
    def use_color(self) -> bool:
        """Return whether ANSI color formatting is enabled."""
        return self._use_color

    @use_color.setter
    def use_color(self, value: bool) -> None:
        """Set ANSI color toggle with strict type validation."""
        if type(value) is not bool:
            raise TypeError("use_color must be a boolean.")
        self._use_color = value

    @property
    def banner_width(self) -> int:
        """Return the presentation banner width."""
        return self._banner_width

    @banner_width.setter
    def banner_width(self, value: int) -> None:
        """Set presentation banner width with bounds validation."""
        if type(value) is not int:
            raise TypeError("banner_width must be an integer.")
        if not (40 <= value <= 200):
            raise ValueError("banner_width must be between 40 and 200.")
        self._banner_width = value

    @property
    def theme_colors(self) -> Dict[str, str]:
        """Return a copy of the active theme color codes."""
        return dict(self._theme_colors)

    @theme_colors.setter
    def theme_colors(self, value: Dict[str, str]) -> None:
        """Update theme color dictionary with type validation."""
        if not isinstance(value, dict):
            raise TypeError("theme_colors must be a dictionary.")
        self._theme_colors = dict(value)

    @property
    def data_manager(self) -> Any:
        """Return the configured DataManager dependency."""
        return self._data_manager

    @data_manager.setter
    def data_manager(self, value: Any) -> None:
        """Set DataManager dependency."""
        if value is None:
            raise ValueError("data_manager cannot be None.")
        self._data_manager = value

    # -------------------------------------------------------------------------
    # Styling Helpers
    # -------------------------------------------------------------------------

    def _c(self, color_key: str) -> str:
        """Return the ANSI code for a color key if color is enabled, else empty string."""
        if not self._use_color:
            return ""
        return self._theme_colors.get(color_key, "")

    def _tag(self) -> str:
        """Return formatted I/O Manager tag."""
        return f"{self._c('blue')}[I/O Manager]{self._c('reset')}"

    def _print(self, text: str = "") -> None:
        """Print text safely, handling platform-specific terminal encoding."""
        try:
            print(text)
        except UnicodeEncodeError:
            try:
                enc = sys.stdout.encoding or "utf-8"
                print(text.encode(enc, errors="replace").decode(enc))
            except Exception:
                print(ascii(text))

    # -------------------------------------------------------------------------
    # Static & Validation Helpers
    # -------------------------------------------------------------------------

    @staticmethod
    def generate_hash(value: str) -> str:
        """Return the cryptographic SHA-256 hex digest of an input string."""
        return hashlib.sha256(str(value).encode("utf-8")).hexdigest()

    @staticmethod
    def format_label(value: Any, default: str = "unknown") -> str:
        """Convert snake_case or raw strings into readable Title Case labels."""
        if value is None:
            value = default
        return str(value).replace("_", " ").strip().title()

    @staticmethod
    def validate_url_syntax(url: str) -> bool:
        """Validate URL or domain syntax using the validators library."""
        if not isinstance(url, str):
            return False
        clean_url = url.strip()
        if not clean_url or " " in clean_url:
            return False
        return bool(validators.url(clean_url) or validators.domain(clean_url))

    # -------------------------------------------------------------------------
    # Presentation: Main Menu
    # -------------------------------------------------------------------------

    def _render_menu(self) -> str:
        """Construct the formatted CLI main menu string."""
        cyan = self._c("cyan")
        bold = self._c("bold")
        yellow = self._c("yellow")
        dim = self._c("dim")
        reset = self._c("reset")
        width = self._banner_width

        lines = [
            f"{cyan}{'=' * width}{reset}",
            f"{bold}{cyan}{('🛡️  ' + self.APP_TITLE).center(width)}{reset}",
            f"{cyan}{'=' * width}{reset}",
            f"  {yellow}[1]{reset} 📧 Analyze Suspicious Text / Scam Email Message",
            f"  {yellow}[2]{reset} 🔗 Analyze Suspicious URL",
            f"  {yellow}[3]{reset} 📎 Analyze File (Path)",
            f"  {yellow}[4]{reset} 🗄️  Query Historical Incident Database",
            f"  {yellow}[5]{reset} 📈 Top Trending Attacks / Scams",
            f"  {yellow}[6]{reset} 🌐 Emerging Threat & Scam Radar (Live Web Grounding)",
            f"  {yellow}[7]{reset} 🚪 Exit",
            f"{dim}{'-' * width}{reset}",
        ]
        return "\n".join(lines)

    def render_menu(self) -> str:
        """Public alias for _render_menu() per UML class design."""
        return self._render_menu()

    # -------------------------------------------------------------------------
    # Interaction & Input Collection
    # -------------------------------------------------------------------------

    def collect_interaction_details(self) -> Tuple[str, Optional[str]]:
        """Prompt user for their exposure level and return (interaction_type, interaction_description)."""
        yellow = self._c("yellow")
        bold = self._c("bold")
        reset = self._c("reset")

        self._print(f"\n{bold}WHAT ACTIONS HAVE YOU ALREADY TAKEN?{reset}")
        self._print(f"  {yellow}[1]{reset} Only viewed the message or item; took no further action")
        self._print(f"  {yellow}[2]{reset} Clicked a link")
        self._print(f"  {yellow}[3]{reset} Entered personal information, login details, or an OTP")
        self._print(f"  {yellow}[4]{reset} Opened or downloaded a file")
        self._print(f"  {yellow}[5]{reset} Made a payment or shared banking details")
        self._print(f"  {yellow}[6]{reset} Other, or more than one of these actions")

        while True:
            choice = input("Select an option (1-6): > ").strip()
            if choice in self.INTERACTION_OPTIONS:
                break
            self._print("Invalid choice. Please enter a number between 1 and 6.")

        interaction_type = self.INTERACTION_OPTIONS[choice]
        interaction_description = None

        if interaction_type == "other":
            self._print(
                "\nDescribe every action you took. "
                "Do not include passwords, OTPs, or account numbers."
            )
            while True:
                desc = input("> ").strip()
                if desc:
                    interaction_description = desc
                    break
                self._print("Please describe what happened.")

        return interaction_type, interaction_description

    def collect_user_interaction(self) -> Tuple[str, Optional[str]]:
        """Public alias for backward compatibility."""
        return self.collect_interaction_details()

    def collect_user_request(self) -> dict:
        """Display main menu options (1-7) and return validated request dict."""
        red = self._c("red")
        reset = self._c("reset")

        while True:
            self._print(self._render_menu())
            choice = input("Select an option (1-7): > ").strip()

            while choice not in {"1", "2", "3", "4", "5", "6", "7"}:
                self._print(f"  {red}❌ Invalid choice. Please enter a number between 1 and 7.{reset}")
                choice = input("Select an option (1-7): > ").strip()

            self._print(f"{self._tag()} 🛠️  Option [{choice}] has been selected.")

            if choice == "1":
                req = self._collect_text_request()
                if req is not None:
                    return req
            elif choice == "2":
                return self._collect_url_request()
            elif choice == "3":
                req = self._collect_file_request()
                if req is not None:
                    return req
            elif choice == "4":
                res = self._handle_history_query()
                if res is not None:
                    return res
            elif choice == "5":
                res = self._handle_trending_threats()
                if res is not None:
                    return res
            elif choice == "6":
                return self._collect_radar_request()
            elif choice == "7":
                confirm = input("Are you sure you want to exit? (y/n): > ").strip().lower()
                if confirm in ("y", "yes"):
                    return {"action": "exit"}

            self._print()

    def _collect_text_request(self) -> Optional[dict]:
        """Collect and validate raw text or email submission."""
        yellow = self._c("yellow")
        reset = self._c("reset")

        self._print("\n📧 -- Analyze Suspicious Text / Scam Email Message --")
        self._print("Paste the message below. Type END on a new line when finished.\n")

        lines: List[str] = []
        while True:
            line = input("> ")
            if line.strip().upper() == "END":
                break
            lines.append(line)
        text = "\n".join(lines).strip()

        while not text:
            self._print(
                f"  {yellow}⚠️  No text was entered. Type NO to exit, "
                f"or type your message to continue.{reset}"
            )
            text = input("> ").strip()
            if text.upper() == "NO":
                return None

        interaction_type, interaction_description = self.collect_interaction_details()

        self._print(f"\n{self._tag()} Captured text input ({len(text)} characters).")
        self._print(f"{self._tag()} Submission of text is being processed, please wait...")

        return {
            "action": "analyze_submission",
            "input_type": "text",
            "input_value": text,
            "input_hash": self.generate_hash(text),
            "interaction_type": interaction_type,
            "interaction_description": interaction_description,
        }

    def _collect_url_request(self) -> dict:
        """Collect and validate URL using the validators package."""
        yellow = self._c("yellow")
        green = self._c("green")
        reset = self._c("reset")

        self._print("\n🔗 -- Analyze Suspicious URL --")
        while True:
            url = input("Enter the suspicious URL or domain: > ").strip()
            if not url:
                self._print(f"  {yellow}⚠️  URL cannot be empty.{reset}")
                continue

            if self.validate_url_syntax(url):
                self._print(f"  {green}✅ URL '{url}' accepted for analysis.{reset}")
                break

            self._print(
                f"  {yellow}⚠️  That doesn't look like a valid URL/domain "
                f"(e.g. example.com or https://example.com/path). Try again.{reset}"
            )

        interaction_type, interaction_description = self.collect_interaction_details()
        self._print(f"{self._tag()} 🛠️  Submission of URL website is being analyzed...")

        return {
            "action": "analyze_submission",
            "input_type": "url",
            "input_value": url,
            "input_hash": self.generate_hash(url),
            "interaction_type": interaction_type,
            "interaction_description": interaction_description,
        }

    def _collect_file_request(self) -> Optional[dict]:
        """Collect and validate local file existence."""
        yellow = self._c("yellow")
        green = self._c("green")
        red = self._c("red")
        reset = self._c("reset")

        self._print("\n📎 -- Analyze File (Path) --")
        while True:
            path = input("Enter the full file path, or BACK for the menu: > ").strip().strip('"')

            if path.upper() == "BACK":
                self._print(f"{self._tag()} 🛠️  Returning to main menu.")
                return None

            if not path:
                self._print(f"  {yellow}⚠️  File path cannot be empty.{reset}")
                continue

            if not os.path.isfile(path):
                self._print(f"  {red}❌ No file found at '{path}'.{reset}")
                retry = input("    Try a different path? (y/n): > ").strip().lower()
                if retry in ("y", "yes"):
                    continue
                self._print(f"{self._tag()} 🛠️  Submission cancelled. Returning to main menu.")
                return None

            filename = os.path.basename(path)
            self._print(f"\n{green}✅ File '{filename}' accepted for analysis.{reset}\n")

            interaction_type, interaction_description = self.collect_interaction_details()
            self._print(f"{self._tag()} 🛠️  Submission of file '{filename}' is being handed off for analysis...")

            return {
                "action": "analyze_submission",
                "input_type": "file",
                "input_value": filename,
                "file_path": path,
                "input_hash": self.generate_hash(path),
                "interaction_type": interaction_type,
                "interaction_description": interaction_description,
            }

    def _collect_radar_request(self) -> dict:
        """Collect topic for Google Search grounded Threat Radar."""
        bold = self._c("bold")
        cyan = self._c("cyan")
        reset = self._c("reset")

        self._print(f"\n{bold}{cyan}🌐 -- Emerging Threat & Scam Radar (Live AI Web Grounding) --{reset}")
        self._print("Enter a specific topic or keyword (e.g. 'Telegram investment', 'CPF SMS', 'Invoice fraud'),")
        self._print("or press ENTER to scan all top emerging threats right now:\n")
        topic = input("> ").strip()

        return {
            "action": "emerging_threat_radar",
            "topic": topic if topic else None,
        }

    # -------------------------------------------------------------------------
    # Separation of Concerns: Delegation to DataManager
    # -------------------------------------------------------------------------

    def _handle_history_query(self) -> dict:
        """Prompt user for query criteria and delegate query execution to DataManager."""
        yellow = self._c("yellow")
        reset = self._c("reset")

        self._print("\n🗄️  -- Query Historical Incident Database --")
        self._print("  [1] Search by keyword")
        self._print("  [2] Filter by risk level (Low / Moderate / High)")
        self._print("  [3] Back to main menu")

        while True:
            sub_choice = input("Select an option (1-3): > ").strip()
            if sub_choice in {"1", "2", "3"}:
                break
            self._print(f"  {yellow}⚠️  Invalid choice. Please enter 1, 2, or 3.{reset}")

        results: List[dict] = []

        if sub_choice == "1":
            keyword = input("Enter search keyword: > ").strip()
            self._print(f"{self._tag()} 🛠️  Querying records for keyword '{keyword}' via DataManager...")

            if self._data_manager is not None:
                if hasattr(self._data_manager, "search_records"):
                    try:
                        results = self._data_manager.search_records(self._db_path, keyword)
                    except TypeError:
                        results = self._data_manager.search_records(keyword)
                elif hasattr(self._data_manager, "search_by_keyword"):
                    results = self._data_manager.search_by_keyword(keyword)

            if not results:
                self._print(f"  {yellow}⚠️  No records found for '{keyword}'.{reset}")

        elif sub_choice == "2":
            levels = {"1": "low", "2": "moderate", "3": "high"}
            self._print("  [1] Low  [2] Moderate  [3] High")

            while True:
                lvl_choice = input("Select risk level (1-3): > ").strip()
                if lvl_choice in levels:
                    break
                self._print(f"  {yellow}⚠️  Invalid risk level.{reset}")

            selected_level = levels[lvl_choice]
            self._print(f"{self._tag()} 🛠️  Querying records at risk level '{selected_level}' via DataManager...")

            if self._data_manager is not None:
                if hasattr(self._data_manager, "get_records_by_risk_level"):
                    try:
                        results = self._data_manager.get_records_by_risk_level(self._db_path, selected_level)
                    except TypeError:
                        results = self._data_manager.get_records_by_risk_level(selected_level)
                elif hasattr(self._data_manager, "query_by_risk"):
                    results = self._data_manager.query_by_risk(selected_level)
                elif hasattr(self._data_manager, "search_records"):
                    results = self._data_manager.search_records(self._db_path, selected_level)

            if not results:
                self._print(f"  {yellow}⚠️  No records found for risk '{selected_level}'.{reset}")

        elif sub_choice == "3":
            self._print(f"{self._tag()} 🛠️  Returning to main menu.")
            return {
                "action": "history_query",
                "status": "cancelled",
                "records_found": 0,
            }

        if results:
            while True:
                idx = self.browse_historical_records(results)
                if idx is None:
                    break
                selected_r = results[idx]
                sub_id = selected_r.get("submission_id") if isinstance(selected_r, dict) else getattr(selected_r, "submission_id", None)
                report = None

                if self._data_manager is not None and sub_id is not None:
                    if hasattr(self._data_manager, "get_submission_report"):
                        try:
                            report = self._data_manager.get_submission_report(self._db_path, sub_id)
                        except TypeError:
                            report = self._data_manager.get_submission_report(sub_id)
                    elif hasattr(self._data_manager, "get_submission_by_id"):
                        sub_obj = self._data_manager.get_submission_by_id(sub_id)
                        report = sub_obj.to_dict() if sub_obj else None

                if report:
                    self.display_incident_report(report)
                else:
                    self._print(f"  {yellow}⚠️  No report found for ID #{sub_id}.{reset}")
                    try:
                        input("\nPress Enter to continue...")
                    except (EOFError, KeyboardInterrupt):
                        break

        return {
            "action": "history_query",
            "status": "completed",
            "records_found": len(results),
        }

    def _handle_trending_threats(self) -> dict:
        """Fetch and display top trending threats via DataManager."""
        bold = self._c("bold")
        cyan = self._c("cyan")
        yellow = self._c("yellow")
        reset = self._c("reset")
        width = self._banner_width

        self._print(f"{self._tag()} 🛠️  Fetching top trending attacks/scams via DataManager...")

        threats: List[dict] = []
        counts: List[dict] = []

        if self._data_manager is not None:
            if hasattr(self._data_manager, "get_top_threat_types"):
                try:
                    threats = self._data_manager.get_top_threat_types(self._db_path)
                except TypeError:
                    threats = self._data_manager.get_top_threat_types()
            if hasattr(self._data_manager, "get_risk_category_counts"):
                try:
                    counts = self._data_manager.get_risk_category_counts(self._db_path)
                except TypeError:
                    counts = self._data_manager.get_risk_category_counts()

        self._print(f"\n{bold}{cyan}📈 Top Trending Attacks / Scams{reset}")
        self._print("-" * width)
        if not threats:
            self._print("  No threat data available.")
        else:
            for i, t in enumerate(threats, start=1):
                threat_type = t.get("primary_threat_type", "Unknown")
                total = t.get("total", 0)
                self._print(f"  {yellow}{i}.{reset} {threat_type} ({total} incidents)")

        self._print(f"\n{bold}{cyan}📊 Risk Category Breakdown{reset}")
        self._print("-" * width)
        if not counts:
            self._print("  No risk category data available.")
        else:
            for c in counts:
                risk = str(c.get("risk_category", "Unknown")).capitalize()
                total = c.get("total", 0)
                self._print(f"  - {risk}: {total} incidents")

        if threats:
            self._print("\nSelect a threat type to view its latest incidents.")
            self._print("Enter 0 to return to the main menu.")

            while True:
                sel = input(f"Select an option (0-{len(threats)}): > ").strip()
                if sel == "0":
                    break
                if not sel.isdigit() or not (1 <= int(sel) <= len(threats)):
                    self._print(f"  {yellow}⚠️  Please select one of the listed numbers.{reset}")
                    continue

                selected_threat = threats[int(sel) - 1].get("primary_threat_type")
                incidents: List[dict] = []

                if self._data_manager is not None and hasattr(self._data_manager, "get_incidents_by_threat_type"):
                    try:
                        incidents = self._data_manager.get_incidents_by_threat_type(self._db_path, selected_threat)
                    except TypeError:
                        incidents = self._data_manager.get_incidents_by_threat_type(selected_threat)

                if not incidents:
                    self._print(f"  {yellow}⚠️  No incidents found for '{selected_threat}'.{reset}")
                    break

                while True:
                    idx = self.browse_historical_records(incidents)
                    if idx is None:
                        break
                    selected_inc = incidents[idx]
                    sub_id = selected_inc.get("submission_id") if isinstance(selected_inc, dict) else getattr(selected_inc, "submission_id", None)
                    report = None

                    if self._data_manager is not None and hasattr(self._data_manager, "get_submission_report"):
                        try:
                            report = self._data_manager.get_submission_report(self._db_path, sub_id)
                        except TypeError:
                            report = self._data_manager.get_submission_report(sub_id)

                    if report:
                        self.display_incident_report(report)
                    else:
                        break
                break

        self._print()
        return {
            "action": "view_trending_threats",
            "status": "completed",
        }

    # -------------------------------------------------------------------------
    # Presentation: Assessment & Incident Reporting
    # -------------------------------------------------------------------------

    def display_assessment(
        self,
        assessment_or_submission: Union[Submission, AssessmentResult, dict],
    ) -> None:
        """Print a user-friendly security report showing risk level, threat status, why flagged, and numbered recovery steps."""
        resource_type = "Resource"
        overall_risk = "UNKNOWN"
        threat_status = "UNKNOWN"
        primary_threat = "None Detected"
        what_it_is = ""
        reported_action = ""
        recovery_steps: List[str] = []
        flags: List[str] = []
        report_url: Optional[str] = None

        if isinstance(assessment_or_submission, Submission):
            sub = assessment_or_submission
            resource_type = self.format_label(sub.input_type)
            reported_action = self.INTERACTION_LABELS.get(sub.interaction_type, sub.interaction_description or "")
            if sub.assessment:
                ar = sub.assessment
                overall_risk = ar.overall_risk.upper()
                threat_status = "MALICIOUS" if ar.is_scam else "NOT A SCAM"
                what_it_is = ar.what_it_is or ar.threat_summary
                reported_action = ar.exposure_reason or reported_action
                recovery_steps = ar.recovery_steps
                flags = ar.risk_reasons or ar.flags
            else:
                threat_status = sub.processing_status.upper()

        elif isinstance(assessment_or_submission, AssessmentResult):
            ar = assessment_or_submission
            overall_risk = ar.overall_risk.upper()
            threat_status = "MALICIOUS" if ar.is_scam else "NOT A SCAM"
            what_it_is = ar.what_it_is or ar.threat_summary
            reported_action = ar.exposure_reason
            recovery_steps = ar.recovery_steps
            flags = ar.risk_reasons or ar.flags

        elif isinstance(assessment_or_submission, dict):
            data = assessment_or_submission
            risk_res = data.get("risk_assessment", {})
            education = data.get("education", {})
            gemini_res = data.get("gemini_analysis", {})
            vt_res = data.get("virustotal_analysis", {})

            overall_risk = str(
                risk_res.get("overall_risk", risk_res.get("risk_category", "UNKNOWN"))
            ).upper()

            is_malicious = bool(risk_res.get("is_malicious", risk_res.get("is_scam", False)))
            tech_risk = str(risk_res.get("technical_risk", "")).lower()

            if is_malicious:
                threat_status = "MALICIOUS"
            elif tech_risk == "medium":
                threat_status = "SUSPICIOUS"
            elif tech_risk == "low":
                threat_status = "NO MALICIOUS DETECTIONS"
            elif overall_risk == "LOW":
                threat_status = "NOT A SCAM"
            else:
                threat_status = "EVALUATED"

            pt = (
                gemini_res.get("primary_threat_type")
                or (vt_res.get("threat_names") or [None])[0]
                or "No Specific Threat Identified"
            )
            primary_threat = self.format_label(pt)
            what_it_is = education.get("what_it_is") or education.get("threat_summary", "No threat explanation is available.")
            reported_action = risk_res.get("exposure_reason") or data.get("reported_action", "No reported action was available.")
            recovery_steps = education.get("recovery_steps") or [
                risk_res.get("recommended_action", "Verify through official channels.")
            ]
            flags = risk_res.get("risk_reasons") or risk_res.get("flags") or risk_res.get("active_indicators") or []
            report_url = data.get("report_url")
            resource_type = self.format_label(data.get("resource_type", "Submission"))

        width = self._banner_width
        cyan = self._c("cyan")
        bold = self._c("bold")
        reset = self._c("reset")

        risk_color = self._c("green")
        if overall_risk in {"HIGH", "CRITICAL"} or threat_status == "MALICIOUS":
            risk_color = self._c("red")
        elif overall_risk in {"MODERATE", "MEDIUM"} or threat_status == "SUSPICIOUS":
            risk_color = self._c("yellow")

        self._print(f"\n{cyan}{'=' * width}{reset}")
        self._print(f"{bold}{cyan}SECURITY ASSESSMENT REPORT: {resource_type.upper()}{reset}")
        self._print(f"{cyan}{'=' * width}{reset}")
        self._print(f"Threat Status   : {risk_color}{threat_status}{reset}")
        self._print(f"Risk Level      : {risk_color}{overall_risk}{reset}")
        if primary_threat and primary_threat != "None Detected":
            self._print(f"Primary Threat  : {primary_threat}")

        self._print(f"\n{bold}WHAT THIS RESULT MEANS{reset}")
        self._print("-" * width)
        self._print(what_it_is or "No specific threat explanation available.")

        if reported_action:
            self._print(f"\n{bold}YOUR REPORTED ACTION{reset}")
            self._print("-" * width)
            self._print(reported_action)

        if flags:
            self._print(f"\n{bold}WHY IT WAS FLAGGED{reset}")
            self._print("-" * width)
            for flag in flags:
                self._print(f"  • {flag}")

        self._print(f"\n{bold}RECOMMENDED RECOVERY ACTIONS{reset}")
        self._print("-" * width)
        if recovery_steps:
            for idx, step in enumerate(recovery_steps, start=1):
                clean_step = step.lstrip("0123456789. ")
                self._print(f"  {idx}. {clean_step}")
        else:
            self._print("  1. No immediate recovery actions required. Remain vigilant.")

        if report_url:
            self._print(f"\nVirusTotal Telemetry Report:\n{report_url}")

        self._print(f"{cyan}{'=' * width}{reset}\n")

    def display_threat_radar(self, radar_data: dict, topic: Optional[str] = None) -> None:
        """Print the Google Search-grounded threat radar."""
        width = self._banner_width
        cyan = self._c("cyan")
        bold = self._c("bold")
        reset = self._c("reset")

        scope = f"'{topic}'" if topic else "Top Emerging Threats (Current Active Trends)"
        model_name = radar_data.get("model_name", "Gemini AI")

        self._print(f"\n{cyan}{'=' * width}{reset}")
        self._print(f"{bold}{cyan}🌐 EMERGING THREAT & SCAM RADAR: LIVE WEB GROUNDING{reset}")
        self._print(f"{cyan}{'=' * width}{reset}")
        self._print(f"Target Scope   : {scope}")
        self._print(f"AI Engine      : {model_name} + Google Search Grounding")
        self._print(f"{cyan}{'=' * width}{reset}")

        content = str(radar_data.get("content", "")).strip()
        if content:
            self._print(f"\n{content}\n")
        else:
            self._print("\nNo threat intelligence content was returned.")

        sources = radar_data.get("sources", [])
        if sources:
            self._print(f"{cyan}{'-' * width}{reset}")
            self._print(f"{bold}🔗 VERIFIED GROUNDING SOURCES{reset}")
            self._print(f"{cyan}{'-' * width}{reset}")
            for idx, src in enumerate(sources[:8], start=1):
                title = src.get("title") or "Security Advisory"
                url = src.get("url", "")
                self._print(f"[{idx}] {title}")
                if url:
                    self._print(f"    {url}")

        queries = radar_data.get("search_queries", [])
        if queries:
            self._print(f"\n{bold}🔍 Live Search Queries Grounded:{reset}")
            for q in queries:
                self._print(f"  • {q}")

        self._print(f"{cyan}{'=' * width}{reset}")
        try:
            input("\nPress Enter to return to the main menu...")
        except (EOFError, KeyboardInterrupt):
            pass

    def display_incident_report(self, report: dict) -> None:
        """Display a full incident report retrieved from DataManager."""
        cyan = self._c("cyan")
        bold = self._c("bold")
        reset = self._c("reset")
        width = self._banner_width

        sub_id = report.get("submission_id", "Unknown")
        self._print(f"\n{cyan}{'=' * width}{reset}")
        self._print(f"{bold}FULL INCIDENT REPORT (ID: {sub_id}){reset}")
        self._print(f"{cyan}{'=' * width}{reset}")

        for k, v in report.items():
            if v is not None and v != "":
                label = str(k).replace("_", " ").title()
                self._print(f"{bold}{label}:{reset} {v}")

        self._print(f"{cyan}{'=' * width}{reset}")
        try:
            input("\nPress Enter to return to results list...")
        except (EOFError, KeyboardInterrupt):
            pass

    # -------------------------------------------------------------------------
    # Presentation: Interactive Table Navigation (Curses / Pick)
    # -------------------------------------------------------------------------

    def browse_historical_records(self, records: list) -> Optional[int]:
        """Display an interactive curses/pick scrollable table for historical incidents.

        Returns index of selected record, or None if user exits/cancels.
        """
        if not records:
            return None

        # Check whether interactive curses terminal is supported
        if sys.stdin.isatty() and sys.stdout.isatty():
            try:
                return self._browse_curses(records, title="HISTORICAL INCIDENT RESULTS")
            except Exception:
                return self._browse_fallback(records)
        else:
            return self._browse_fallback(records)

    def browse_historical_table(self, records: list) -> Optional[int]:
        """Public alias for browse_historical_records() per UML class design."""
        return self.browse_historical_records(records)

    def _browse_fallback(self, records: list) -> Optional[int]:
        """Fallback menu navigation when curses cannot run (e.g., automated tests or non-tty)."""
        width = self._banner_width
        cyan = self._c("cyan")
        bold = self._c("bold")
        yellow = self._c("yellow")
        reset = self._c("reset")

        self._print(f"\n{cyan}{'=' * width}{reset}")
        self._print(f"{bold}{cyan}HISTORICAL INCIDENT DATABASE (Selection Mode){reset}")
        self._print(f"{cyan}{'=' * width}{reset}")

        for idx, r in enumerate(records, start=1):
            if isinstance(r, dict):
                val = str(r.get("input_value", "")).replace("\n", " ").strip()
                risk = str(r.get("risk_category", "Unknown")).upper()
                sub_id = r.get("submission_id", "?")
                itype = r.get("input_type", "unknown")
            else:
                val = str(getattr(r, "input_value", "")).replace("\n", " ").strip()
                risk = str(getattr(r.assessment, "overall_risk", "Unknown") if hasattr(r, "assessment") and r.assessment else "Unknown").upper()
                sub_id = getattr(r, "submission_id", "?")
                itype = getattr(r, "input_type", "unknown")

            preview = (val[:40] + "...") if len(val) > 40 else val
            self._print(
                f"  [{yellow}{idx}{reset}] ID: {sub_id:<4} | {itype:<5} | {risk:<8} | \"{preview}\""
            )

        self._print(f"  [{yellow}0{reset}] Return / Cancel")
        self._print(f"{cyan}{'-' * width}{reset}")

        while True:
            choice = input(f"Select an incident to open (0-{len(records)}): > ").strip()
            if choice == "0":
                return None
            if choice.isdigit():
                num = int(choice)
                if 1 <= num <= len(records):
                    return num - 1
            self._print(f"  {yellow}⚠️  Please enter a valid number between 0 and {len(records)}.{reset}")

    def _browse_curses(self, records: list, title: str = "HISTORICAL INCIDENT RESULTS") -> Optional[int]:
        """Interactive scrollable curses table implementation."""
        try:
            locale.setlocale(locale.LC_ALL, "")
        except locale.Error:
            pass
        os.environ.setdefault("ESCDELAY", "25")

        def run(stdscr: Any) -> Optional[int]:
            curses.curs_set(0)
            curses.use_default_colors()
            for i, c in enumerate(
                (curses.COLOR_CYAN, curses.COLOR_GREEN, curses.COLOR_YELLOW, curses.COLOR_RED), 1
            ):
                curses.init_pair(i, c, -1)
            cyan_pair, green_pair, yellow_pair, red_pair = (curses.color_pair(i) for i in (1, 2, 3, 4))
            risk_colors = {
                "high": red_pair,
                "moderate": yellow_pair,
                "medium": yellow_pair,
                "low": green_pair,
            }

            def put(y: int, x: int, text: str, attr: int = 0) -> None:
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

                put(0, 0, title.center(w - 1), cyan_pair | curses.A_BOLD)
                put(1, 0, "═" * (w - 1), cyan_pair)
                put(2, 0, f"  {'ID':<5}│ {'Type':<5}│ {'Risk':<9}│ Preview", curses.A_BOLD)
                put(3, 0, "─" * (w - 1), cyan_pair)

                if pos < top:
                    top = pos
                elif pos >= top + visible:
                    top = pos - visible + 1

                for row, r in enumerate(records[top : top + visible]):
                    i = top + row
                    if isinstance(r, dict):
                        val = str(r.get("input_value", "")).replace("\n", " ").strip()
                        risk = str(r.get("risk_category", "Unknown")).lower()
                        sub_id = r.get("submission_id", "?")
                        itype = r.get("input_type", "?")
                    else:
                        val = str(getattr(r, "input_value", "")).replace("\n", " ").strip()
                        risk = str(getattr(r.assessment, "overall_risk", "Unknown") if hasattr(r, "assessment") and r.assessment else "Unknown").lower()
                        sub_id = getattr(r, "submission_id", "?")
                        itype = getattr(r, "input_type", "?")

                    preview = val if len(val) <= preview_w else val[: preview_w - 3] + "..."
                    line_a = f"{str(sub_id):<5}│ {str(itype):<5}│ "
                    y = 4 + row

                    if i == pos:
                        attr = green_pair | curses.A_BOLD
                        put(y, 0, "▶ " + line_a + f"{risk.upper():<9}│ {preview}", attr)
                    else:
                        put(y, 0, "  " + line_a)
                        put(y, 2 + len(line_a), f"{risk.upper():<9}", risk_colors.get(risk, 0) | curses.A_BOLD)
                        put(y, 2 + len(line_a) + 9, f"│ {preview}")

                put(h - 2, 0, "─" * (w - 1), cyan_pair)
                put(h - 1, 0, f" ↑↓ move   Enter open   q/Esc back   [{pos + 1}/{len(records)}]", curses.A_DIM)
                stdscr.refresh()

                key = stdscr.getch()
                if key in (curses.KEY_UP, ord("k")):
                    pos = max(0, pos - 1)
                elif key in (curses.KEY_DOWN, ord("j")):
                    pos = min(len(records) - 1, pos + 1)
                elif key == curses.KEY_PPAGE:
                    pos = max(0, pos - visible)
                elif key == curses.KEY_NPAGE:
                    pos = min(len(records) - 1, pos + visible)
                elif key == curses.KEY_HOME:
                    pos = 0
                elif key == curses.KEY_END:
                    pos = len(records) - 1
                elif key in (10, 13, curses.KEY_ENTER):
                    return pos
                elif key in (ord("q"), ord("Q"), 27):
                    return None

        return curses.wrapper(run)
