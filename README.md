Guide on Usage
===============================================================

Perform
`pip install -r requirements.txt`

===============================================================

`.env` file to be filled with own API

===============================================================

Since a newly created `database.db` will start empty, options [4] and [5] won't return anything until data is stored. 
Fortunately, this project includes a script and dataset to pre-load sample historical incidents:

1. `load_synthetic_data.py`
2. `synthetic_data.json`

```bash
python load_synthetic_data.py database.db