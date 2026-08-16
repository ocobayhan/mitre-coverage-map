# SOC Coverage Map

A self-hosted Flask + SQLite application for tracking detection coverage against the MITRE ATT&CK Enterprise matrix. It answers one question for a security operations team: **for a given environment, which ATT&CK techniques can we actually detect — and where are the blind spots?**

## Why this exists

Most ATT&CK coverage tracking lives in spreadsheets or the standalone Navigator tool, neither of which models the same technique differently per detection source, per environment, or over time. This project ties detection rules, threat-intel product claims, mitigations, and environment-specific monitoring into one scored, filterable matrix — with an audit trail and role-based access, so it can serve as a team's living source of truth rather than a one-off snapshot.

## Key features

- **Navigator-style coverage matrix** — a dense, color-coded grid of every ATT&CK technique and sub-technique, scored 0–100%.
- **Evidence-aware scoring** — a named, verified detection rule counts differently than a bulk "this product covers 300 techniques" import claim; sub-technique coverage rolls up to the parent technique without double-counting shared rules. Full methodology: [docs/scoring_methodology.md](docs/scoring_methodology.md).
- **Environment-scoped coverage** — the same detection rule may or may not apply in a given environment, depending on whether the product that generates it actually monitors that environment. Coverage percentages, gaps, and reports can all be filtered per environment.
- **Mitigation tracking**, kept separate from detection scoring — who owns each MITRE mitigation, with which product, and how.
- **LLM-assisted coverage import** — paste a vendor's technique-coverage claim and get a structured preview/apply flow instead of hand-entering hundreds of rows (schema + prompt documented in [docs/mitre_mapping_prompt.md](docs/mitre_mapping_prompt.md)).
- **Executive PDF report** — a print-ready `/report` view with an executive summary, the full coverage map, a tactic breakdown, and an action-item list.
- **Role-based access** (`viewer` / `editor` / `admin`) and an append-only, hash-chained audit log for every write.
- **QRadar connector** — pulls the Use Case Manager mapping inventory read-only and reconciles it against existing rules.

## Quick start

### Local

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:SOC_PORT='8888'
python app.py
```

App: `http://127.0.0.1:8888`

Three accounts are created for local use on first run:

- `admin / Admin123!`
- `editor / Editor123!`
- `viewer / Viewer123!`

**Change these immediately in any shared or production environment.**

### Production

Production runs on Waitress instead of Flask's dev server and requires a strong, persistent session secret — generate a fresh one per deployment, never reuse a key across environments:

```powershell
$env:SOC_SECRET_KEY='<32+ random bytes, e.g. openssl rand -hex 32>'
$env:SOC_HOST='0.0.0.0'
$env:SOC_PORT='8000'
$env:SOC_COOKIE_SECURE='1'
.\.venv\Scripts\python.exe serve.py
```

Put a reverse proxy in front for TLS termination. Only set `SOC_COOKIE_SECURE=1` when actually serving over HTTPS.

### Docker

```powershell
copy .env.example .env
# fill in SOC_SECRET_KEY inside .env
docker compose up -d --build
```

Live data (`soc.db`) lives in a Docker-managed named volume (`soc_data`); backups go to a plain host folder (`./backups`) that Docker never touches, so `docker compose down -v` or `docker system prune --volumes` can't take your backups with them. See [docs/backup_restore.md](docs/backup_restore.md) for the backup architecture, and [docs/kurulum_rehberi.md](docs/kurulum_rehberi.md) for a from-scratch setup + restore walkthrough (Turkish).

## Data

- MITRE Enterprise ATT&CK dataset: `data/mitre.json`
- Seed detections: `data/rules_seed.json`
- SQLite database: `soc.db` (not committed)

Restart the app after replacing the MITRE dataset. The Data Quality screen checks technique-ID, product, tactic, and mapping consistency.

### Updating the MITRE dataset

`data/mitre.json` comes from MITRE's official STIX repository (committed to this repo despite its size — 50MB+):

```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json" -OutFile "data\mitre.json"
```

On restart, `build_technique_config()` automatically adds any newly introduced techniques (existing admin overrides are never touched — `INSERT OR IGNORE` on the technique-ID primary key). **MITRE occasionally renames or splits a whole tactic** (e.g. in 2026-07, "Defense Evasion" split into "Stealth" and "Defense Impairment") — when that happens, `_TACTIC_LABEL_MAP` / `_TACTIC_ORDER` in `app.py` and the matching dictionaries in `static/app.js` need a manual update (`grep -rn "defense-evasion"` finds the pattern to follow). After updating:

1. Confirm tactic count and names match the live ATT&CK site.
2. Confirm the `technique_config` row count grew and admin overrides (`source='admin'`) survived.
3. Confirm the matrix renders with zero console errors and the correct column order.
4. Run the test suite and `scripts/browser_smoke.py`.

## Scoring

Every technique gets a single coverage score that also drives its matrix cell color:

```
score = min(effective detections / technique target, 1)
```

**Effective detections** is the product of two independent weights:

```
effective weight = coverage level (low 0.25 | half 0.50 | good 0.75 | full 1.00)
                  × environment monitoring weight (full 1.00 | partial %/100 | none/unknown 0)
```

Coverage level is a 4-tier simplification of DeTT&CT's Visibility Score; monitoring weight is a separate concept — how much of an *environment* a given product actually observes (see "Environment-scoped coverage" below).

**Technique target** (`technique_config.rule_threshold`) starts from a 3-tier bucket based on how many threat groups (`group_count`, from `mitre.json`) are known to use that technique (low prevalence → 1, medium → 2, high → 3). An admin can override it per technique, either from the technique detail modal or from the dedicated **Technique Targets** list view under Inventory (admin-only, deliberately kept off the map itself). Raising a technique's target immediately turns its cell red if coverage hasn't kept up.

**A parent technique's target is the sum of its sub-techniques' unmet gaps** (`Σ max(0, sub.target − sub.effective)`) — it grows with how many sub-techniques are genuinely still open, not with how many sub-techniques merely exist. Full rationale and formula history: [docs/scoring_methodology.md](docs/scoring_methodology.md).

**Mitigations don't affect the score.** Color answers one question — *can we detect this?* — mitigation status shows up separately, as a line in the hover tooltip. Product diversity doesn't affect the score either; the dots on each card already show that.

> This score is a maturity signal, not proof that a detection actually fires in production.

### Reading a matrix cell

The map is a dense grid close to MITRE Navigator's own layout — one column per tactic, one equal-height cell per technique. Only the name and ID show on the card face; numeric detail (detection ratio, mitigation, environment) appears in a tooltip on hover, so color alone is never the only signal.

- **Fill color** reflects score only: no detections → dark gray, below target → amber, at or above target → green.
- **Clicking a cell** opens the technique detail modal; **hovering** a cell that has sub-techniques expands them underneath (no click needed — it closes when the mouse leaves). Sub-techniques get their own color but don't count toward the parent's denominator.
- Hovering shows detections/target, products, mitigation status, environment, and how many threat groups use the technique.
- The small gradient legend above the map summarizes what each color means.

### What counts as "covered"?

Two mutually exclusive buckets, which sum to the total technique count:

| Metric | Meaning |
|---|---|
| **Detected** | At least one *named* detection is mapped to the technique — we can see it |
| **Undetected** | No named detection exists — the actual action list |

`Mitigated` is tracked separately and is informational only — it overlaps both buckets.

**The Detected bucket requires hard evidence.** A bulk product-coverage claim from an import (*"this product covers these 300 techniques"*) contributes to the score but never fills the Detected bucket (`rules.origin = 'product_claim'`) — a single blanket claim shouldn't make 120 techniques look detected when the map's whole purpose is answering "can we actually see this." These techniques are marked on the map with a dashed amber border: scored, but without hard evidence behind them.

**The denominator is parent techniques only.** Sub-techniques don't count toward it — almost all rules map to the parent, and a rule written against a sub-technique already counts for its parent. Sub-techniques still render on the map with their own color and are reported separately as informational; a low value there just means sub-technique mapping hasn't been done yet.

The same definition is used in the matrix, in `GET /api/gap-analysis` (`detected_techniques` / `uncovered_techniques` / `mitigated_techniques`), and in the executive report.

### Prioritization

There's no "importance" score anymore — it used to be an opaque 0.3–1.0 value derived from `mitre.json` that nobody could tune. Instead, undetected techniques are ranked by **how many threat groups are known to use that technique** (`technique_config.group_count`) — objective MITRE data, not a setting.

## Mitigation records

`Inventory > Mitigations` records, per MITRE mitigation, **who** provides it, **with which product**, and **how**:

| Field | Required | Note |
|---|---|---|
| Team | yes | picked from the `teams` catalog |
| Product | no | picked from the `products` catalog; empty means "covered by process/training/policy" |
| Description | yes | free text describing how it's actually provided |

A mitigation counts as "applied" based on exactly one thing: having at least one record. There's no separate checkbox — an earlier design kept a parallel `checked` flag that was never actually filled in and created two sources of truth, so it was removed.

Mitigation status doesn't affect the coverage score; it shows up as a separate line in a technique card's hover tooltip.

## Environment-scoped coverage

Not every product is deployed everywhere: an EDR might cover both client machines and corporate servers while missing a second site's servers entirely; a SIEM might ingest logs from every server but not from any client. In that case, a SIEM-based rule simply **doesn't apply** in the client environment.

The weighting is:

```
effective weight = coverage-level weight × monitoring weight
    monitoring:  full → 1.00 | partial → coverage_percent/100 | none, unknown → 0
```

> **Note:** the environment selector was removed from the live matrix screen — the matrix panel now always runs in *all environments (merged)* mode, a deliberate simplification. Environment-scoped coverage is still available on the **Gap Analysis** screen and in the executive report (`/report?environment_id=<id>`); monitoring status is entered per environment under `Coverage Inventory > Environment > Product Monitoring`.

Server-side: `GET /api/gap-analysis?environment_id=<id>` powers both the Gap Analysis screen and the environment-scoped report.

## Product categories

`products.category` takes three values, each with a different effect on the map:

| Category | Example | Effect |
|---|---|---|
| `detection_source` (default) | SIEM, EDR, identity protection, email security, XDR | Colors the map; only these count toward the product-diversity indicator |
| `preventive_control` | Firewall, antivirus, patch management, MFA | Doesn't generate detections; doesn't count toward coverage |
| `enrichment` | Threat-intel feeds | Feeds prioritization, not coverage |

Existing installs migrate every product to `detection_source` by default (so nobody's coverage count silently changes); reclassify from `Settings > Product Management`.

There's no foreign key between `products.id` and `rules.source` — the two are linked only by name equality. A rule source that doesn't match a catalog entry can't be attached to any environment, so rule creation rejects it outright; existing mismatches are flagged as **critical** on the Data Quality screen.

## QRadar connector

The connector pulls the QRadar Use Case Manager mapping inventory read-only. The SEC token is never stored in the database — only the name of the environment variable it should be read from is kept in the connector config.

```powershell
$env:QRADAR_SEC_TOKEN='<read-only-authorized-service-token>'
```

An admin can register multiple QRadar instances, test connectivity, and trigger a sync from `Settings > Connectors`. Reconciliation first matches on native rule ID; if exactly one existing record shares the same product and name, it links to that record instead. New records are created as `untested` with low confidence. Manual ATT&CK mappings and validation evidence are never deleted by the connector.

For scheduled syncs, run this as a service account carrying the same environment variables:

```powershell
.\.venv\Scripts\python.exe scripts\sync_connectors.py
# a single connector only:
.\.venv\Scripts\python.exe scripts\sync_connectors.py --connector-id 1
```

Every 6 hours is a reasonable interval for Windows Task Scheduler. Concurrent syncs of the same connector are blocked; a run stalled for over 15 minutes is treated as timed out and closed. Native records missing from three consecutive syncs aren't deleted — they're marked `stale`.

## Coverage inventory

`Coverage Inventory` manages the measurement boundary through `Environment > Product Monitoring`. An admin defines environments and platform/asset-type groups; an editor records each product's monitoring status (`unknown`, `none`, `partial`, `full`), method, percentage, owner, and notes. A QRadar connector can only link to a monitoring record tagged with the same product.

This record is evidence of product *presence*, not MITRE detection coverage directly. Technique mapping and validation evidence for native detections pulled from a connector are tracked separately. Every coverage and survey change is written to the audit chain with before/after values.

## Audit log

Audit entries record request ID, user, IP, user agent, before/after values, and a SHA-256 hash chain. Database triggers block updates or deletes on audit rows. Admins can filter, inspect, verify chain integrity, and export CSV from the Audit screen. An **Evidence Package** export bundles the filtered records plus a manifest with full chain status, prior/current hashes, and an independently verifiable package hash, as JSON.

## Testing

```powershell
pip install -r requirements-dev.txt
python -m unittest discover -s tests -v
python scripts\browser_smoke.py
```

The browser test connects to a running instance and writes screenshots to the system temp folder.

## Backup

Copy `soc.db` while the app is stopped. To restore, stop the running process and replace the current file with a verified backup. An audit export is not a substitute for a database backup.
