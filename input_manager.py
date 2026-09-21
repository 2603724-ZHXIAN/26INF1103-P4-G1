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
