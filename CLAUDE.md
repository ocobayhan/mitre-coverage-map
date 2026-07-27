# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Running the App

```bash
# First-time setup
python -m venv .venv
.venv\Scripts\Activate.ps1   # Windows PowerShell
pip install -r requirements.txt

# Start server (port 8000, debug mode)
python app.py
# Visit http://localhost:8000
```

Environment overrides: `SOC_SECRET_KEY`, `SOC_HOST`, `SOC_PORT`.

Default credentials created on first run: `admin/Admin123!`, `editor/Editor123!`, `viewer/Viewer123!`.

## Architecture Overview

Single-file Flask backend (`app.py`) serving a single-page application. No build step — all frontend code is plain HTML/CSS/JS.

```
app.py              — Flask app, all API routes, DB schema, migrations
templates/
  index.html        — Main SPA: 4 nav sections (Harita/Envanter/Boşluklar/Ayarlar),
                      each with sub-tabs. All panels are in the DOM at all times;
                      SECTIONS + showPanel() in app.js toggle them.
  docs.html         — Standalone wiki served at /docs (was half of index.html)
  login.html        — Login page
  report.html       — Executive report served at /report
static/
  app.js            — All frontend logic; bump ?v= query param on each change
  styles.css        — All styling; bump ?v= query param on each change
data/
  mitre.json        — MITRE ATT&CK Enterprise JSON (STIX 2.x format, not committed)
  rules_seed.json   — Seed data for rules (optional)
soc.db              — SQLite database (auto-created on first run, not committed)
```

## Frontend Files

`static/app.js` and `templates/index.html` together form the SPA frontend. Both files can be freely edited. When modifying `app.js`, bump the `?v=` version in the `<script>` tag in `index.html` to bust the browser cache. The DOM selectors that `app.js` depends on (IDs, classes) must stay in sync with `index.html`.

## Database

SQLite at `soc.db`. Schema is created and migrated entirely inside `init_db()` in `app.py`. Migrations are idempotent (use `IF NOT EXISTS`, check for columns via `PRAGMA table_info`, check for index via `PRAGMA index_list`).

Key tables:
- `rules` — detection rules with `(name, source)` UNIQUE constraint.
  `origin` distinguishes evidence strength: `named` (a real, named detection —
  fills the "Tespit" bucket) vs `product_claim` (product-level bulk claim from
  an import's `product_coverage[]` — scores but never fills the bucket).
- `rule_techniques` — many-to-many: one rule → many MITRE technique IDs
- `products` — security products (name, color)
- `mitigation_entries` — who mitigates what, with which product (`product_id` → `products.id`, nullable).
  A mitigation counts as "applied" iff it has at least one row here — there is no separate
  `checked` flag. The old `mitigation_global` / `mitigation_notes` tables were dropped in Faz 4d.
- `technique_config` — per-technique detection target (`rule_threshold`, default 2) + MITRE signals
- `users` — local auth with roles: `viewer`, `editor`, `admin`
- `audit_logs` — append-only log of all write actions

## API Routes

All data endpoints are under `/api/`. Role enforcement via decorators:
- `@login_required` — any authenticated user
- `@role_required("viewer"|"editor"|"admin")` — minimum role check

Key patterns:
- `GET /api/rules` returns rules with `techniques[]` array (from `rule_techniques` join)
- `POST /api/rules` requires `name` + `source`; `tactic`/`tech` are optional
- `GET /api/mitre-min` returns minified MITRE data (attack-patterns, courses-of-action, mitigates relationships only) — cached in memory, invalidated by file mtime
- `POST /api/admin/reset` requires `{ confirm: "RESET" }` — deletes all rules/mitigations, optionally reseeds from `data/rules_seed.json`
- Coverage import is two-phase: `POST /api/import/coverage/preview` returns a
  plan and writes nothing; `…/apply` executes that same plan. Both go through
  `_plan_coverage_import()`. Schema + the LLM prompt live in
  `docs/mitre_mapping_prompt.md`, served to the UI via
  `GET /api/import/mapping-prompt` — never duplicate the prompt in code.

## MITRE Data Setup

Place the MITRE ATT&CK Enterprise JSON (downloadable from MITRE) at `data/mitre.json`. The server minifies and caches it at runtime. The `technique_config` table is auto-populated from this file on first run (idempotent).

## Cache Busting

When modifying `styles.css` or `app.js`, bump the corresponding `?v=` version number in `index.html` to force browser cache invalidation. Current versions are tracked in `MEMORY.md`.

## Role System

`ROLE_LEVELS = { viewer: 1, editor: 2, admin: 3 }` — numeric comparison used throughout. Roles gate: read-only (viewer), write rules/mitigations (editor), manage users/products/config (admin).

Project Instructions

### CRITICAL REMINDERS

#### Key Design Documents
- *Audit Logging:* docs/audit_logging.md — How to add audit logging to routes (patterns, constants, sanitization, checklist)
- *RBAC:* docs/rbac.md — User roles, permission matrix, backend permission groups, frontend checks
- *Docker/Backup:* docs/backup_restore.md — Container layout, why backups use a host bind mount instead of the data named volume, scheduling, restore steps

There is no in-app job scheduler (no `JobScheduler`/`ScheduledJob` in `app.py`) — the only scheduled process is the external `scripts/sync_connectors.py`, intended to run via Windows Task Scheduler (see README's QRadar Connector section). If an in-app scheduler is ever built, add its design doc here.

#### Development Environment
Single machine: Windows 11, everything (dev, test, run) happens locally via `.venv\Scripts\python.exe`. There is no separate Ubuntu test server or SSH deployment target for this project — do not assume one exists.

#### Workflow
1. *Start by reading* `PROJECT_STATE.md` (progress/status) and `README.md` (setup/usage/requirements) before non-trivial changes.
2. *End by updating* `PROJECT_STATE.md` if functionality, data status, or KPI numbers changed; update `README.md` if setup/usage/API surface changed.
3. Run tests locally: `.venv\Scripts\python.exe -m unittest discover -s tests -v` and, for UI changes, `scripts\browser_smoke.py`. Never skip tests or modify them without user approval.
4. Commit after every functional phase (only when the user asks for a commit).
5. For multi-step tasks, use TaskCreate/TODO tracking; for larger tasks, keep fine-grained state in a tracked plan.
6. Enter plan mode often — especially if user mentions "plan."

#### Core Principles
* *Simplicity first.* Always ask: is there a simpler way? But never at the cost of security or functionality.
* *Minimal impact.* Touch only what's necessary. Before changing code, evaluate all dependencies and side effects — fixing one thing must not break another.
* *No shortcuts.* Find root causes. No temporary fixes. Senior developer standards.

#### Subagent Strategy
* Use subagents mainly to keep main context window clean.
* Use subagents to also have a fresh eye look at the issue at hand.
* Offload research, exploration, and parallel analysis to subagents
* One task per subagent for focused execution.

#### Verification Before Done
* Never mark a task complete without proving it works
* Run tests, include visual checks, check logs
* Ask yourself: "Would a staff engineer approve this?"

#### Versioning
- Frontend and backend can iterate at different rates (independent versioning).
- `templates/index.html` pins `static/styles.css?v=N` and `static/app.js?v=N` — bump the relevant `v` whenever that file changes, so browsers don't serve a stale cached copy.
- Suggest a version/changelog note in `PROJECT_STATE.md` when a considerable amount of change has accumulated.
