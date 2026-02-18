# PROJECT STATE - MITRE Coverage Map

Last updated: 2026-02-18

## Purpose
Lightweight, server-based SOC coverage manager with MITRE ATT&CK mapping, mitigations tracking, product-based coverage, and persistent storage.

## Current Status
- Backend: Flask + SQLite
- Frontend: Single HTML + JS + CSS served by Flask
- MITRE data: loaded from `data/mitre.json` (manual updates)
- Rules: stored in `soc.db`
- Mitigation notes: stored in `soc.db`
- Products: stored in `soc.db` (name + color)
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
- `POST /api/rules/bulk` (CSV import)
- `GET/POST /api/mitigation-notes`
- `GET/POST /api/products`
- `PUT /api/products/<id>`
- `DELETE /api/products/<id>`
- `POST /api/admin/reset` with `{ "confirm": "RESET", "reseed": true }`

## Admin Reset Behavior
- Clears `rules` and `mitigation_notes`
- Reseeds from `data/rules_seed.json`
- If seed missing, fallback to parsing `SOC.html` (legacy)

## UI Features Implemented
- MITRE matrix layout (horizontal tactics)
- Technique card color gradient based on coverage score
- Sub-techniques expand inline under technique card
- Technique modal: rules + mitigations + notes
- Mitigation info popover + checkbox + comment
- Left sidebar with Matrix / Bilgilendirme / Ayarlar
- Product legend and multi-color stripe on technique cards
- Product management in Settings (add/delete/update color)
- CSV bulk upload in Settings
- Search bar on Matrix (ID or name)
- Product filtering via legend toggle (click product name to hide/show)

## Filters & Validation
- Search: only matching techniques remain visible
- Product filter: legend items toggle inclusion
- Technique validation on add: checks `Txxxx` or `Txxxx.xxx` and existence in MITRE map

## Known Issues / Notes
- Turkish encoding has been problematic before; files now written as UTF-8 with escapes in `index.html`.
- If UI shows ? characters, hard refresh and ensure server restarts.

## Git / Repo Hygiene
- `.gitignore` excludes: `.venv/`, `soc.db`, `__pycache__/`, `.env`
- Untracked files often include `Error.jpg`, `Mitre.jpg` (do not commit)

## Recent Work (High Level)
- Added products table + CRUD endpoints
- Implemented product color editing and persistence
- Implemented CSV bulk import
- Added search + product filter behavior
- Fixed sidebar markup issues

## Open Roadmap (Agreed)
Milestone 1 (in progress):
- Search + product filtering + validation (nearly done)

Milestone 2:
- Export: CSV and PDF (should respect active filters)

Milestone 3:
- MITRE Navigator Layer JSON export (score-based)

Milestone 4:
- Performance: backend cached/minified MITRE API

Deferred:
- Audit log (later after user system)

## Commit Tracking
- Latest commit: update after filters/legend toggle fixes (pending in working tree)
- User pushes to private GitHub repo manually
