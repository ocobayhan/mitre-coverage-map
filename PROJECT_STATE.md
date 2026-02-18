# PROJECT STATE - MITRE Coverage Map

Last updated: 2026-02-18

## Purpose
Lightweight, server-based SOC coverage manager with MITRE ATT&CK mapping, mitigations tracking, and persistent storage.

## Current Status
- Backend: Flask + SQLite
- Frontend: Single HTML + JS + CSS served by Flask
- MITRE data: loaded from `data/mitre.json` (manual updates)
- Rules: stored in `soc.db`
- Mitigation notes: stored in `soc.db`
- Reset/reseed: available via `/api/admin/reset`

## How To Run (Windows)
1. `python -m venv .venv`
2. `\.venv\Scripts\Activate.ps1`
3. `pip install -r requirements.txt`
4. `python app.py`
5. Open `http://localhost:8000`

If PowerShell execution policy blocks activation:
- `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`

## Data Files
- MITRE JSON: `data/mitre.json`
- Seed rules: `data/rules_seed.json`
- DB: `soc.db` (excluded from git)

## Key Endpoints
- `GET /api/mitre`
- `GET/POST /api/rules`
- `DELETE /api/rules/<id>`
- `GET/POST /api/mitigation-notes`
- `POST /api/admin/reset` with `{ "confirm": "RESET", "reseed": true }`

## Admin Reset Behavior
- Clears `rules` and `mitigation_notes`
- Reseeds from `data/rules_seed.json`
- If seed missing, fallback to parsing `SOC.html` (legacy)

## Known Issues
- None currently. If MITRE JSON missing, UI shows `Veri Hatasý`.

## Next Suggested Improvements
- Add MITRE update admin action (upload or replace `data/mitre.json` in UI)
- Add role-based access / simple auth if public deployment
- Add search/filter for techniques and rules
- Add export functions (CSV/JSON)

## Repo Hygiene
- `.gitignore` excludes: `.venv/`, `soc.db`, `__pycache__/`, `.env`

## Commit Tracking
- Latest commit on `main`: "Initial commit"
- For future changes, commit after each feature/fix with concise message

