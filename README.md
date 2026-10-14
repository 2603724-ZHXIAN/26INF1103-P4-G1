Guide on Usage
===============================================================

Perform
`pip install -r requirements.txt`

===============================================================

Create `.env` file to be filled with own API Keys

# GEMINI_API_KEY=your_gemini_api_key_here
# GEMINI_MODEL=gemini-3.8-flash
# VT_API_KEY=your_virustotal_api_key_here
# GROQ_API_KEY=your_groq_api_key_here
# GROQ_MODEL=openai/gpt-oss-120b

===============================================================

Since a newly created `database.db` will start empty, options [4] and [5] won't return anything until data is stored. 
Fortunately, this project includes a script and dataset to pre-load sample historical incidents:

1. `load_synthetic_data.py`
2. `data/synthetic_data.json`

```bash
python load_synthetic_data.py data/database.db
## Running the application and tests

Run these commands from the main project folder.

Start the application:

```bash
python -m src.main
```

Run the offline logic tests:

```bash
python -m tests.test_logic_manager
```

## Project folders

- `src/`: Python application modules.
- `data/`: Database and sample dataset.
- `tests/`: Offline tests.
- `docs/`: Project documentation and flowchart.

Keep your local `.env` file in the main project folder.

## Running with Docker

These commands are for Windows PowerShell. Start Docker Desktop and run them from the main project folder.

### 1. Prepare files for analysis

Create a folder named `test_files` in the main project folder:

```powershell
New-Item -ItemType Directory -Force test_files
```

Place any files you want to analyse inside this folder.

### 2. Build the image

```powershell
docker build -f dockerfile -t cyber-threat-engine:organisation .
```

### 3. Start the application

Ensure your `.env` file is in the main project folder.

```powershell
docker run --rm -it `
  --mount "type=bind,source=$($PWD.Path)\.env,target=/app/.env,readonly" `
  --mount "type=bind,source=$($PWD.Path)\test_files,target=/files,readonly" `
  cyber-threat-engine:organisation
```

Each backtick must be the last character on its line, with no trailing spaces.

The `.env` file supplies your API keys. It stays on your computer and is excluded from the image. No additional `--env-file` flag is needed.

### 4. Analyse a file using option [3]

Select option [3] and enter the container file path, for example:

```text
/files/safe_test_file.txt
```

Replace `safe_test_file.txt` with the name of a file inside `test_files`.

When running in Docker, use `/files/...` instead of a Windows path such as `C:\Users\...\Downloads\...`.

### 5. Run the offline tests

```powershell
docker run --rm cyber-threat-engine:organisation python -m tests.test_logic_manager
```

Database changes inside these temporary containers are discarded when the containers exit.
