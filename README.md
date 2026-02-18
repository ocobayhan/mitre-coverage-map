SOC Coverage Manager (Flask + SQLite)

Run

1) python -m venv .venv
2) .\.venv\Scripts\Activate.ps1
3) pip install -r requirements.txt
4) python app.py
5) open http://localhost:8000

MITRE data

- Place the Enterprise ATT&CK JSON as data/mitre.json
- If you want manual updates, replace that file and restart the server

Data storage

- SQLite database is soc.db in the project root
- Rules and mitigation notes are stored persistently

Admin reset

- POST /api/admin/reset { confirm: 'RESET', reseed: true }
- Reseed uses data/rules_seed.json if present, otherwise SOC.html

