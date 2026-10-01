===============================================================================================
Perform: 
"pip install -r requirements.txt"
===============================================================================================
.env: 
file to be filled with own API\
===============================================================================================
Since a newly created database.db will start empty, options [4] and [5] won't return anything until data is stored.
Fortunately, This project includes a script 
1. (load_synthetic_data.py) and 
2. dataset (synthetic_data.json) 
to pre-load sample historical incidents.

python load_synthetic_data.py database.db