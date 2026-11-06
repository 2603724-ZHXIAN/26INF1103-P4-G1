# Cyber Threat & Scam Detection Engine (Phase 2 OOP)

[![CI](https://github.com/2603724-ZHXIAN/26INF1103-P4-G1/actions/workflows/ci.yml/badge.svg)](https://github.com/2603724-ZHXIAN/26INF1103-P4-G1/actions/workflows/ci.yml)

An educational, multi-layered threat detection engine that analyzes suspicious messages (SMS/email phishing), URLs, and file attachments using Google Gemini AI, Groq Cloud failover, VirusTotal v3 telemetry, and deterministic cybersecurity logic rules.

---

## 1. Prerequisites & Installation

Clone or open the repository in your terminal and install dependencies:

```bash
pip install -r requirements.txt
```

---

## 2. Environment Configuration (.env)

The application uses an environment file `.env` to configure API credentials. An environment template has been provided in [`.env.example`](.env.example).

### Step 1: Copy the template
```bash
# Windows Command Prompt or PowerShell:
copy .env.example .env

# macOS / Linux:
cp .env.example .env
```

### Step 2: Add your API keys to `.env`
Open `.env` in any text editor and fill in your keys:

```dotenv
# --- Google Gemini API (Primary LLM Client) ---
# Obtain from Google AI Studio: https://aistudio.google.com/
GEMINI_API_KEY=your_gemini_api_key_here
GEMINI_MODEL=gemini-2.5-flash

# --- Groq Cloud API (Automated Failover LLM Client) ---
# Obtain from Groq Console: https://console.groq.com/
GROQ_API_KEY=your_groq_api_key_here
GROQ_MODEL=openai/gpt-oss-120b

# --- VirusTotal API (Threat Scanner Service) ---
# Obtain from VirusTotal: https://www.virustotal.com/
VT_API_KEY=your_virustotal_api_key_here
```

> **Note on Graceful Fallback**: If an API key is missing or quota-limited, the application does not crash. `AIManager` automatically fails over between Gemini and Groq, and offline unit tests run without requiring any live keys.

---

## 3. Seed Sample Database (Optional)

A newly initialized SQLite database (`data/database.db`) starts empty. To immediately populate sample historical incidents for testing options `[6]` (Query Historical Incident Database) and `[7]` (Top Trending Attacks / Scams), run the synthetic loader:

```bash
python load_synthetic_data.py data/database.db
```

This populates 40 sample cases across various threat categories (phishing, impersonation, advance fee scams, and malicious URLs).

---

## 4. Running the Application and Tests

All commands should be executed from the root project folder:

### Start the Application CLI
```bash
python -m src.main
```

| Menu option | What it does |
|---|---|
| `[1]` Analyze Suspicious Text / Scam Email Message | Paste a message; the AI extracts warning indicators and `LogicManager` decides the risk |
| `[2]` Analyze Suspicious URL | VirusTotal scan + AI assessment of the result |
| `[3]` Analyze File (Path) | VirusTotal file-hash lookup + AI assessment |
| `[4]` Batch Input Analysis | Import many `.eml` emails at once and analyse them concurrently (see section 6) |
| `[5]` Previous Batch Records | Reopen a saved batch, search its emails or export its Word report |
| `[6]` Query Historical Incident Database | Search saved incidents by keyword or risk level and open full reports |
| `[7]` Top Trending Attacks / Scams | Most common threat types across text, URL and file scans |
| `[8]` Emerging Threat & Scam Radar | Live, web-grounded briefing on current scams |
| `[9]` Exit | Close the application |

### Run All Automated Tests (Offline)
One command runs the whole suite (398 tests) and prints a pass/fail summary per component:
```bash
python run_tests.py
```

| Command | What it does |
|---|---|
| `python run_tests.py` | Run every test, then show a summary table per component |
| `python run_tests.py -v` | Same, but also list every individual test by name |
| `python run_tests.py logic ai` | Run only the test files whose name contains `logic` or `ai` |
| `python -m unittest discover tests` | Standard unittest alternative (no summary table) |

The command exits with code `0` when all tests pass and `1` otherwise. **No API keys or internet connection are needed**: AI and VirusTotal responses are replaced by mocks, and every test uses a temporary or in-memory database, so your real `data/database.db` is never modified.

| Test file | Component verified | Key behaviour covered |
|---|---|---|
| `tests/test_models.py` | Domain models | Encapsulation and validation, composition of `ThreatEvidence` and `AssessmentResult` inside `Submission`, `to_dict`/`from_dict` round trips |
| `tests/test_services.py` | Services | `BaseLLMClient` cannot be instantiated (abstract), Gemini/Groq inheritance and polymorphism, VirusTotal hashing and error results |
| `tests/test_ai_manager.py` | AI Manager | Prompt sandboxing, JSON schema validation, rejection of malformed AI output (e.g. confidence 150), Gemini to Groq failover |
| `tests/test_oop_logic_manager.py` | Logic Manager | Multi-condition scam rules, exposure routing, VirusTotal thresholds, the VirusTotal + AI rule table and its boundaries |
| `tests/test_data_manager.py` | Data Manager | Save/load across separate runs, upserts without duplicates, transaction rollback, corrupt or unavailable database file, corrupt stored JSON |
| `tests/test_io_manager.py` | IO Manager | Encapsulated settings, URL and menu input validation, history/trending queries, result display |
| `tests/test_coordinator.py` | Engine Coordinator | Full text and URL/file pipelines, AI running before the risk decision, AI/scanner failures marking a record as failed, table-driven menu dispatch, threaded and sequential batches saving identical results |
| `tests/test_ai_configuration.py` | Start-up without API keys | Clear "no AI provider" messages instead of a crash; history and records still work |
| `tests/test_main_startup.py` | Start-up with a damaged database | Clear fix steps and exit code 1 instead of a traceback |
| `tests/test_ai_logic_contract.py` | AI Manager ↔ Logic Manager | The AI's JSON format matches what the business rules read |
| `tests/test_trending_threats.py` | Trending | Text, URL and file threats are all counted |
| `tests/test_concurrency_engine.py` | Threading (advanced feature) | `BatchItem` states, `RateLimiter` waits (mocked clock), workers really run in parallel, one failed email does not stop the batch, Ctrl+C cancels waiting emails |
| `tests/test_email_ingestion_service.py`, `test_eml_parser.py`, `test_html_email_parser.py`, `test_ingested_email.py` | Email import | `.eml` parsing, HTML text and link extraction, duplicates, invalid files, size limits |
| `tests/test_batch_report.py`, `test_batch_report_service.py`, `test_campaign_detector.py`, `test_word_report_writer.py` | Batch reports | Statistics and rankings, similar-email campaign grouping, Word `.docx` export |
| `tests/test_batch_database_integration.py`, `test_batch_export_coordinator.py` | Batch storage and export | Batches saved and reloaded from SQLite, report export and export failures |

---

## 5. How a Risk Decision Is Made

Every record passes through the AI before the deterministic rules in `LogicManager` make the final decision. The AI never decides on its own.

**Text messages:** the AI extracts warning indicators (e.g. `credential_request`, `suspicious_link`). Multi-condition rules then combine two or more indicators, for example *credential request + suspicious link = possible credential phishing (high)*.

**URLs and files:** VirusTotal scans the resource, the AI assesses the scan result (`is_malicious`, `scam_confidence` 0-100, `threat_type`, `reasoning`), and `LogicManager` combines both:

| VirusTotal malicious engines | AI says malicious with confidence > 80%? | Result |
|---|---|---|
| 5 or more | Yes | **High risk, Urgent priority, `critical_threat` flag** |
| 5 or more | No | High |
| 1-4 | Yes | Raised to High |
| 1-4 | No | Medium |
| 0 | Yes | Raised to Medium |
| 0 | No | Low |

A confident AI can raise the risk by one level but never lowers a VirusTotal verdict. If the AI is unavailable or returns invalid output, the record is marked **failed** instead of being assessed without AI.

---

## 6. Batch Email Analysis (New Feature) and Threading (Advanced Feature)

**Problem it solves:** checking a mailbox one message at a time is slow. Batch analysis imports many suspicious emails at once, analyses them all, and produces a report that groups similar scams together.

**How to use it:**
1. Choose `[4] Batch Input Analysis`, then `1` (pick several `.eml` files) or `2` (a whole folder). Try the samples in `test_files/email_batch_demo/` or `test_files/campaign_demo_emails/`.
2. A progress bar is shown while the emails are analysed. The batch summary then lists each email's risk, plus duplicates and files that could not be imported.
3. From **Batch Options**, view all emails, search them, show high-risk emails only, or choose `4. Download Batch Report (.docx)`. The Word report is saved in `reports/`.
4. Every batch is stored in the database, so `[5] Previous Batch Records` can reopen it and export the report again in a later session.

**How it works (threading):** `BatchProcessor` uses a `ThreadPoolExecutor` with 5 worker threads, so several emails are sent to the AI at the same time instead of one after another. A shared, thread-safe `RateLimiter` (15 calls per 60 seconds) keeps the API under its quota. Workers only call the AI; every result is then saved and assessed on the main thread through the same pipeline as a single message, so threading never changes the risk decision. Pressing Ctrl+C during a batch cancels the emails that have not started yet.

| Class | Role |
|---|---|
| `EmailIngestionService` | Reads `.eml` files, enforces size limits and detects duplicates |
| `EmlParser`, `HtmlEmailParser` | Extract sender, subject, body text, links and attachment details |
| `IngestedEmail` | One imported email |
| `BatchItem` | One email's processing state while it moves between threads |
| `BatchProcessor` | Worker pool that analyses emails concurrently |
| `RateLimiter` | Thread-safe limit on API calls |
| `BatchReportService`, `BatchReport` | Build statistics and risk rankings from the saved records |
| `CampaignDetector` | Groups emails with similar text into potential scam campaigns |
| `WordReportWriter` | Exports the batch report as a Word `.docx` file |

**Tests:** see the email import, batch report and threading rows in the table in section 4.

---

## 7. Project Structure & Architecture

```text
26INF1103-P4-G1/
├── src/
│   ├── main.py                     # Bootstrap & dependency injection runner
│   ├── coordinator.py              # EngineCoordinator (orchestrates 4 managers)
│   ├── config.py                   # Central paths and constants
│   ├── interfaces/                 # Abstract Base Classes (Contracts)
│   │   ├── __init__.py
│   │   └── llm_client.py           # BaseLLMClient (ABC for LLM providers)
│   ├── services/                   # External API adapters and email import
│   │   ├── __init__.py
│   │   ├── gemini_client.py        # GeminiClient (inherits BaseLLMClient)
│   │   ├── groq_client.py          # GroqClient (inherits BaseLLMClient)
│   │   ├── virustotal_scanner.py   # VirusTotalScanner (standalone concrete service)
│   │   ├── email_ingestion_service.py  # EmailIngestionService (imports .eml files)
│   │   ├── eml_parser.py           # EmlParser
│   │   └── html_email_parser.py    # HtmlEmailParser (inherits HTMLParser)
│   ├── models/                     # Domain Entities (Encapsulation & Composition)
│   │   ├── __init__.py
│   │   ├── submission.py           # Submission (Aggregate Root)
│   │   ├── assessment.py           # AssessmentResult
│   │   ├── evidence.py             # ThreatEvidence
│   │   └── email_ingestion.py      # IngestedEmail
│   ├── batch/                      # Batch analysis, threading and Word reports
│   │   ├── batch_item.py           # BatchItem
│   │   ├── batch_processor.py      # BatchProcessor (worker thread pool)
│   │   ├── rate_limiter.py         # RateLimiter (thread-safe API limit)
│   │   ├── batch_report.py         # BatchReport
│   │   ├── batch_report_service.py # BatchReportService
│   │   ├── campaign_detector.py    # CampaignDetector
│   │   └── word_report_writer.py   # WordReportWriter (.docx export)
│   └── managers/                   # Engine Managers
│       ├── __init__.py
│       ├── ai_manager.py           # AIManager (prompt sandboxing, LLM failover)
│       ├── logic_manager.py        # LogicManager (pure deterministic business rules)
│       ├── data_manager.py         # DataManager (SQLite repository & reports)
│       └── io_manager.py           # IOManager (terminal UI, formatting, menus)
├── tests/                          # Automated offline test suite (398 tests)
├── .github/workflows/ci.yml        # GitHub Actions CI pipeline
├── run_tests.py                    # Runs the whole test suite with a summary
├── data/                           # SQLite database & synthetic dataset fixtures
├── docs/                           # Documentation, rubric details & architecture flowcharts
├── test_files/                     # Sample files and .eml emails for manual testing
├── reports/                        # Exported Word batch reports (created at runtime, not committed)
├── load_synthetic_data.py          # Synthetic dataset loader script
├── requirements.txt                # Python package dependencies
├── Dockerfile                      # Container build definition
└── .env.example                    # Template environment file
```

---

## 8. Running with Docker

Start Docker Desktop and run these commands from the main project folder. The tests need no `.env` file; the application needs one to call the live APIs.

### 1. Build the Docker image
```bash
docker build -t cyber-threat-engine:latest .
```

### 2. Run the automated tests in Docker
```bash
docker run --rm cyber-threat-engine:latest python run_tests.py
```

### 3. Prepare the folders
The container is deleted when the app closes (`--rm`), so the database and Word reports must be saved **outside** it.
The run commands below connect these folders on your computer to the container:

| Folder on your computer | Inside the container | Purpose |
|---|---|---|
| `data/` | `/app/data` | SQLite database (records, history and batches are kept between runs) |
| `reports/` | `/app/reports` | Word batch reports, ready to open on your computer |
| `test_files/` | `/files` (read-only) | Files and `.eml` emails you want to analyse |

```powershell
# Windows PowerShell
New-Item -ItemType Directory -Force data, reports, test_files
```
```bash
# macOS / Linux
mkdir -p data reports test_files
```

### 4. Start the application container
Ensure your `.env` file exists in the root project folder.

**Windows PowerShell:**
```powershell
docker run --rm -it `
  --mount "type=bind,source=$($PWD.Path)\.env,target=/app/.env,readonly" `
  --mount "type=bind,source=$($PWD.Path)\test_files,target=/files,readonly" `
  -v "$($PWD.Path)\data:/app/data" `
  -v "$($PWD.Path)\reports:/app/reports" `
  cyber-threat-engine:latest
```

**macOS / Linux:**
```bash
docker run --rm -it \
  --mount "type=bind,source=$(pwd)/.env,target=/app/.env,readonly" \
  --mount "type=bind,source=$(pwd)/test_files,target=/files,readonly" \
  -v "$(pwd)/data:/app/data" \
  -v "$(pwd)/reports:/app/reports" \
  cyber-threat-engine:latest
```

### 5. Analyse files and emails in Docker
Use the container paths under `/files`:
```text
Option [3] Analyze File                    -> /files/safe_test_file.txt
Option [4] Batch Input Analysis (folder)   -> /files/email_batch_demo
```
Word reports exported from the batch menu (option `4. Download Batch Report (.docx)`) appear in your `reports/` folder,
and all saved records remain in `data/database.db` the next time you start the container.

---

## 9. Continuous Integration (CI)

The GitHub Actions workflow [`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs automatically on every push to any branch, on every pull request into `main`, and on demand from the **Actions** tab. It has two jobs:

| Job | Steps |
|---|---|
| **Unit tests (Python 3.11)** | Check out the code, install `requirements.txt`, run `python run_tests.py -v` |
| **Docker build + tests in container** | Runs only if the first job passes: builds the image from the `Dockerfile` and runs `python run_tests.py -v` inside the container |

No secrets are required because every external API is mocked in the tests. The badge at the top of this README shows the latest result on `main`; individual runs and logs are on the repository's **Actions** tab.
