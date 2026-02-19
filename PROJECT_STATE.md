# PROJECT STATE - MITRE Coverage Map

Last updated: 2026-02-20

## Purpose
Lightweight, server-based SOC coverage manager with MITRE ATT&CK mapping, mitigations tracking, product-based coverage, and persistent storage.

## Current Status
- Backend: Flask + SQLite
- Frontend: Single HTML + JS + CSS served by Flask
- MITRE data: loaded from `data/mitre.json` (manual updates)
- Rules: stored in `soc.db`
- Mitigation notes: stored in `soc.db` (includes `team` field)
- Mitigation entries: stored in `soc.db` (per mitigation, multiple teams/comments)
- Products: stored in `soc.db` (name + color)
- Reset/reseed: available via `/api/admin/reset`
- MITRE minified endpoint is cached in-memory on backend

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
- `GET /api/mitre-min`
- `GET/POST /api/rules`
- `DELETE /api/rules/<id>`
- `POST /api/rules/bulk` (CSV import)
- `GET/POST /api/mitigation-notes`
- `GET/POST /api/mitigation-entries`
- `DELETE /api/mitigation-entries/<id>`
- `GET/POST /api/products`
- `PUT /api/products/<id>`
- `DELETE /api/products/<id>`
- `POST /api/admin/reset` with `{ "confirm": "RESET", "reseed": true }`

## Admin Reset Behavior
- Clears `rules` and `mitigation_notes`
- Clears `mitigation_global` and `mitigation_entries`
- Reseeds from `data/rules_seed.json`
- If seed missing, fallback to parsing `SOC.html` (legacy)

## UI Features Implemented
- MITRE matrix layout (horizontal tactics)
- Technique card color gradient based on coverage score
- Sub-techniques expand inline under technique card
- Technique modal: rules + mitigations + notes
- Mitigation info popover + checkbox + entries list (team + comment) + "Onayla" (checkbox save + closes modal)
- Mitigations are global across techniques (same entries appear everywhere)
- Modal has tabs: Mitigations / Kurallar
- New panel: Mitigation Listesi (mitigation -> techniques list)
- Mitigation Listesi now includes global team/comment entries with add/remove actions
- Technique IDs in Mitigation Listesi are interactive chips (hover state + click popover with full technique name)
- Left sidebar with Matrix / Bilgilendirme / Ayarlar
- Product legend and multi-color stripe on technique cards
- Product management in Settings (add/delete/update color)
- CSV bulk upload in Settings
- Search bar on Matrix (ID or name)
- Product filtering via legend toggle (click product name to hide/show)
- Matrix now fills the remaining page height (no resizer or bottom form)

## Filters & Validation
- Search: only matching techniques remain visible
- Product filter: legend items toggle inclusion
- Technique validation on add: checks `Txxxx` or `Txxxx.xxx` and existence in MITRE map

## Known Issues / Notes
- Turkish encoding has been problematic before; `templates/index.html` and `static/app.js` were rewritten to clean UTF-8. If "?" appears, hard refresh and restart server.
- If UI shows ? characters, hard refresh and ensure server restarts.

## Git / Repo Hygiene
- `.gitignore` excludes: `.venv/`, `soc.db`, `__pycache__/`, `.env`
- Untracked files often include `Error.jpg`, `Mitre.jpg` (do not commit)

## Recent Work (High Level)
- Removed bottom "Yeni Kural" form and draggable resizer (matrix is full-height now)
- Removed slide-in rule panel (kept modal + existing add flow)
- Modal "Onayla" now saves mitigations and closes modal
- Fixed navigation switching between Matrix / Bilgilendirme / Ayarlar
- Cleaned Turkish characters in templates and UI strings
- Added MITRE minified API + in-memory cache (performance)
- Added `team` field to mitigation notes (DB + API)
- Mitigation popover text shortened and labeled (summary + detail toggle)
- UI polish pass: hover elevation, button transitions, modal typography
- Color palette updated and all text forced to light colors (no black on dark)
- Mitigation entries now global per mitigation (same entry appears across all techniques)
- Mitigation modal now uses tabs (Mitigations / Kurallar)
- Added `mitigation_global` backend storage and migration/seed logic for global mitigation state
- Added `mitigation_entries` API + persistence for multi-team implementation notes per mitigation
- Synced Matrix modal and Mitigation Listesi page so add/remove entries reflect both views
- Reworked Mitigation Listesi layout: wider Ekip/Yorum column, compact technique chips, toggle for full list
- Added technique chip hover/tooltip popover with full `Txxxx - name` text

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
- Latest commit: UI polish + contrast fixes + mitigation popover improvements (see git log)
- User pushes to private GitHub repo manually


## New Context Quick Start
1. Read `PROJECT_STATE.md` (this file) for current state and roadmap.
2. Check `git status -sb` for pending changes.
3. Run app: `python app.py` and open `http://localhost:8000` for UI verification.

## Last Verified Flows
- Matrix renders with horizontal tactics
- Legend click toggles product filter
- Search input filters techniques by ID/name
- Add rule validates technique ID/name
- Product CRUD + color update applies to legend/stripe
- CSV bulk import works and refreshes matrix
- Mitigation entries added in Matrix are visible in Mitigation Listesi
- Mitigation entries added/removed in Mitigation Listesi are visible in Matrix
- Shared mitigation checkbox/comment/team state is global by mitigation ID

## Action Checklist
- [x] Matrix + Mitigation Listesi global mitigation senkronu
- [x] Mitigation ekip/yorum ekle-sil (iki tarafta da)
- [x] Teknik chip hover + tıklama popover (tam teknik adı)
- [x] Mitigation Listesi genişlik/UI düzeni
- [x] Modal sekmeler (Mitigations / Kurallar)

- [ ] RBAC altyapısı (`users` tablosu + `viewer/editor/admin`)
- [ ] Login/logout ve session yönetimi
- [ ] Endpoint bazlı yetki kontrolü (role guard)
- [ ] UI role bazlı buton görünürlüğü/kısıtlama
- [ ] Admin kullanıcı yönetimi ekranı
- [ ] Basit audit log (kim-ne-zaman-ne yaptı)

- [ ] Türkçe karakter/encoding temizliği (`templates/index.html`, `static/app.js`)
- [ ] CSS çakışma/sadeleştirme (tekrarlı kuralların temizlenmesi)
- [ ] Mitigation Listesi responsive düzen (dar ekran)
- [ ] UX final polish (spacing, tipografi, tutarlılık)

## Suggested Order
1. RBAC backend (tablo + login + endpoint guard)
2. RBAC frontend (role bazlı görünürlük/kısıtlama)
3. Audit log (kritik işlemler)
4. Encoding + CSS refactor
5. Responsive/UX polish


## RBAC & Audit Update (2026-02-20)
- RBAC guards are now active across API endpoints.
- Login/session endpoints active: `/login`, `/api/login`, `/api/logout`, `/api/me`.
- Admin user management added:
  - `GET/POST /api/users`
  - `PUT /api/users/<id>`
- Audit logging added:
  - DB table: `audit_logs`
  - API: `GET /api/audit-logs` (admin)
  - Logged actions include login/logout and key create/update/delete/reset actions.
- Settings page now includes Admin-only `Kullanici Yonetimi` and `Audit Log` sections.
