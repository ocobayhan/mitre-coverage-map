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
  index.html        — Main SPA (all panels rendered on load, toggled by JS)
  login.html        — Login page
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
- `rules` — detection rules with `(name, source)` UNIQUE constraint
- `rule_techniques` — many-to-many: one rule → many MITRE technique IDs
- `products` — security products (name, color)
- `mitigation_global` — per-mitigation checkbox/comment state (global, not per-user)
- `mitigation_notes` — legacy per-technique mitigation notes (kept for migration)
- `technique_config` — per-technique importance score and rule threshold (auto-computed from mitre.json)
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
- *Scheduler:* docs/PLAN_SCHEDULER_REDESIGN.md — JobScheduler engine, ScheduledJob dataclass, how to register new jobs

#### Development Environment
- *Dev machine (Windows 11):* Where Claude runs (bash shell via Claude Code)
- *Test server (Ubuntu):* ssh claude@ip
- *Backend:* http://ip:port
- *Frontend:* http://ip:port

#### SSH Session Management
- *Prefer persistent SSH sessions* over repeated one-liner connect/disconnect
- *ALWAYS logout/exit SSH sessions* when done with a dev run
- Don't leave orphaned sessions on the server (ip)

#### Workflow
1. *Start by reading* docs/PROGRESS.md, docs/REQUIREMENTS.md, and any relevant DESIGN documents.
2. *End by updating* those same docs — including submodule docs under docs/<submodule_name>/. If functionality changed, update REQUIREMENTS.md.
3. Run tests on Ubuntu VM, not locally. Never skip tests or modify them without user approval. Include user-facing visual tests.
4. Commit after every functional phase.
5. For multi-step tasks, create a TODO checklist. For larger/complex tasks, use a TODO.md with checkboxes and maintain fine-grained state there.
6. Enter plan mode often — especially if user mentions "plan."
7. Write every relevant progress to docs/PROGRESS.md

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
- Frontend and backend can iterate at different rates (independent versioning)
- Suggest updates when there are considerable amount of changes implemented.
- Version files: ..., ....
