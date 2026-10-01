Guide on Usage
===============================================================

Perform
`pip install -r requirements.txt`

===============================================================

Create `.env` file to be filled with own API Keys

# GEMINI_API_KEY=your_gemini_api_key_here
# GEMINI_MODEL=gemini-3.8-flash
# VT_API_KEY=your_virustotal_api_key_here

===============================================================

Since a newly created `database.db` will start empty, options [4] and [5] won't return anything until data is stored. 
Fortunately, this project includes a script and dataset to pre-load sample historical incidents:

1. `load_synthetic_data.py`
2. `synthetic_data.json`

```bash
python load_synthetic_data.py database.db