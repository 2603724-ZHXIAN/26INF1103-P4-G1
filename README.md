# Cyber Threat & Scam Detection Engine (Phase 2 OOP)

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

A newly initialized SQLite database (`data/database.db`) starts empty. To immediately populate sample historical incidents for testing options `[4]` (Database Query) and `[5]` (Top Trending Attacks), run the synthetic loader:

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

### Run All Automated Unit Tests (Offline)
Runs all 173 tests verifying domain models, managers, coordinator routing, failover logic, and services without live API calls:
```bash
python -m unittest discover tests
```

---

## 5. Project Structure & Architecture

```text
26INF1103-P4-G1/
├── src/
│   ├── main.py                     # Bootstrap & dependency injection runner
│   ├── coordinator.py              # EngineCoordinator (orchestrates 4 managers)
│   ├── config.py                   # Central paths and constants
│   ├── interfaces/                 # Abstract Base Classes (Contracts)
│   │   ├── __init__.py
│   │   └── llm_client.py           # BaseLLMClient (ABC for LLM providers)
│   ├── services/                   # External API Adapters
│   │   ├── __init__.py
│   │   ├── gemini_client.py        # GeminiClient (inherits BaseLLMClient)
│   │   ├── groq_client.py          # GroqClient (inherits BaseLLMClient)
│   │   └── virustotal_scanner.py   # VirusTotalScanner (standalone concrete service)
│   ├── models/                     # Domain Entities (Encapsulation & Composition)
│   │   ├── __init__.py
│   │   ├── submission.py           # Submission (Aggregate Root)
│   │   ├── assessment.py           # AssessmentResult
│   │   └── evidence.py             # ThreatEvidence
│   └── managers/                   # Engine Managers
│       ├── __init__.py
│       ├── ai_manager.py           # AIManager (prompt sandboxing, LLM failover)
│       ├── logic_manager.py        # LogicManager (pure deterministic business rules)
│       ├── data_manager.py         # DataManager (SQLite repository & reports)
│       └── io_manager.py           # IOManager (terminal UI, formatting, menus)
├── tests/                          # Automated offline unit test suite (173 tests)
├── data/                           # SQLite database & synthetic dataset fixtures
├── docs/                           # Documentation, rubric details & architecture flowcharts
├── load_synthetic_data.py          # Synthetic dataset loader script
├── requirements.txt                # Python package dependencies
├── dockerfile                      # Container build definition
└── .env.example                    # Template environment file
```

---

## 6. Running with Docker

These commands are for Windows PowerShell. Start Docker Desktop and run them from the main project folder.

### 1. Prepare files for analysis
Create a folder named `test_files` in the root folder:
```powershell
New-Item -ItemType Directory -Force test_files
```
Place any files you want to analyze inside this folder.

### 2. Build the Docker image
```powershell
docker build -f dockerfile -t cyber-threat-engine:latest .
```

### 3. Start the application container
Ensure your `.env` file exists in the root project folder:
```powershell
docker run --rm -it `
  --mount "type=bind,source=$($PWD.Path)\.env,target=/app/.env,readonly" `
  --mount "type=bind,source=$($PWD.Path)\test_files,target=/files,readonly" `
  cyber-threat-engine:latest
```

### 4. Analyze a file in Docker
Select option `[3]` in the menu and enter the container path:
```text
/files/your_file.txt
```

### 5. Run automated tests in Docker
```powershell
docker run --rm cyber-threat-engine:latest python -m unittest discover tests
```
