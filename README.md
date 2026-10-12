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
# GROQ_MODEL="openai/gpt-oss-120b"

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
