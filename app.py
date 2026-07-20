from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import re
import sqlite3
import threading
import time
import uuid
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from flask import Flask, Response, jsonify, request, render_template, g, session, redirect, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from qradar_connector import QRadarClient, QRadarConnectorError

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = BASE_DIR / "soc.db"
MITRE_PATH = DATA_DIR / "mitre.json"
SEED_RULES_PATH = DATA_DIR / "rules_seed.json"
LEGACY_SOC_HTML = BASE_DIR / "SOC.html"

app = Flask(__name__)
app.config["JSON_AS_ASCII"] = False
app.config["JSONIFY_MIMETYPE"] = "application/json; charset=utf-8"
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("SOC_COOKIE_SECURE", "0") == "1"
app.secret_key = os.environ.get("SOC_SECRET_KEY", "change-this-in-production")


MITRE_CACHE = {"mtime": None, "data": None}
THREAT_ACTOR_CACHE: dict[str, Any] = {"mtime": None, "data": None}
TTP_LIST_CACHE: dict[str, Any] = {"data": None, "dirty": True}
LOGIN_ATTEMPTS: dict[str, deque[float]] = defaultdict(deque)
LOGIN_ATTEMPTS_LOCK = threading.Lock()
LOGIN_WINDOW_SECONDS = 300
LOGIN_MAX_FAILURES = 5
ROLE_LEVELS = {"viewer": 1, "editor": 2, "admin": 3}
TECHNIQUE_NAME_ALIASES = {
    "data from cloud storage object": "T1530",
    "remote access software": "T1219",
}
AUDIT_COLUMNS = {
    "request_id": "TEXT NOT NULL DEFAULT ''",
    "ip_address": "TEXT NOT NULL DEFAULT ''",
    "user_agent": "TEXT NOT NULL DEFAULT ''",
    "before_json": "TEXT NOT NULL DEFAULT ''",
    "after_json": "TEXT NOT NULL DEFAULT ''",
    "prev_hash": "TEXT NOT NULL DEFAULT ''",
    "entry_hash": "TEXT NOT NULL DEFAULT ''",
}

_TACTIC_LABEL_MAP: dict[str, str] = {
    "reconnaissance": "Reconnaissance",
    "resource-development": "Resource Development",
    "initial-access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege-escalation": "Privilege Escalation",
    "defense-evasion": "Defense Evasion",
    "credential-access": "Credential Access",
    "discovery": "Discovery",
    "lateral-movement": "Lateral Movement",
    "collection": "Collection",
    "command-and-control": "Command and Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
}


@app.before_request
def assign_request_id() -> None:
    supplied = request.headers.get("X-Request-ID", "").strip()
    g.request_id = supplied[:128] if supplied else uuid.uuid4().hex


@app.after_request
def add_security_headers(response: Response) -> Response:
    response.headers["X-Request-ID"] = getattr(g, "request_id", "")
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cache-Control"] = "no-store" if request.path.startswith("/api/") else response.headers.get("Cache-Control", "no-cache")
    return response


def _login_attempt_key(username: str) -> str:
    return f"{request.remote_addr or '-'}|{username.casefold()}"


def _login_is_limited(key: str) -> bool:
    cutoff = time.monotonic() - LOGIN_WINDOW_SECONDS
    with LOGIN_ATTEMPTS_LOCK:
        attempts = LOGIN_ATTEMPTS[key]
        while attempts and attempts[0] < cutoff:
            attempts.popleft()
        return len(attempts) >= LOGIN_MAX_FAILURES


def _record_login_failure(key: str) -> None:
    with LOGIN_ATTEMPTS_LOCK:
        LOGIN_ATTEMPTS[key].append(time.monotonic())


def _clear_login_failures(key: str) -> None:
    with LOGIN_ATTEMPTS_LOCK:
        LOGIN_ATTEMPTS.pop(key, None)



def get_db() -> sqlite3.Connection:
    if "db" not in g:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(_: Exception | None) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def ensure_mitigation_team_column(db: sqlite3.Connection) -> None:
    cols = [r[1] for r in db.execute("PRAGMA table_info(mitigation_notes)").fetchall()]
    if "team" not in cols:
        db.execute("ALTER TABLE mitigation_notes ADD COLUMN team TEXT NOT NULL DEFAULT ''")
        db.commit()


def ensure_mitigation_global_table(db: sqlite3.Connection) -> None:
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS mitigation_global (
            mitigation_id TEXT PRIMARY KEY,
            checked INTEGER NOT NULL DEFAULT 0,
            comment TEXT NOT NULL DEFAULT "",
            team TEXT NOT NULL DEFAULT ""
        )
        """
    )
    db.commit()


def ensure_action_items_table(db: sqlite3.Connection) -> None:
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS action_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tech_id TEXT NOT NULL DEFAULT '',
            title TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            priority INTEGER NOT NULL DEFAULT 2
                CHECK(priority IN (1, 2, 3, 4)),
            status TEXT NOT NULL DEFAULT 'open'
                CHECK(status IN ('open','in_progress','done','cancelled')),
            assigned_team_id INTEGER,
            due_date TEXT,
            created_by_username TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    db.commit()


def ensure_teams_table(db: sqlite3.Connection) -> None:
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS teams (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    db.commit()


def ensure_mitigation_global_seed(db: sqlite3.Connection) -> None:
    existing = db.execute("SELECT COUNT(*) AS cnt FROM mitigation_global").fetchone()[0]
    if existing:
        return
    rows = db.execute(
        "SELECT mitigation_id, checked, comment, team FROM mitigation_notes"
    ).fetchall()
    if not rows:
        return
    merged: dict[str, dict[str, Any]] = {}
    for r in rows:
        mid = r["mitigation_id"]
        checked = 1 if r["checked"] else 0
        comment = r["comment"] or ""
        team = r["team"] or ""
        if mid not in merged:
            merged[mid] = {"checked": checked, "comment": comment, "team": team}
            continue
        # prefer checked if any row checked
        merged[mid]["checked"] = max(merged[mid]["checked"], checked)
        # prefer longer comment/team if present
        if len(comment) > len(merged[mid]["comment"]):
            merged[mid]["comment"] = comment
        if len(team) > len(merged[mid]["team"]):
            merged[mid]["team"] = team
    db.executemany(
        "INSERT INTO mitigation_global (mitigation_id, checked, comment, team) VALUES (?, ?, ?, ?)",
        [(k, v["checked"], v["comment"], v["team"]) for k, v in merged.items()],
    )
    db.commit()


# ── Migration: Kural Birleştirme ─────────────────────────────────────────────
# CSV import veya bulk add sırasında aynı (name, source) çiftine sahip birden
# fazla satır oluşabilir. Bu fonksiyon ilk çalıştığında:
#   1. Aynı (name, source) olan satırları tespit eder.
#   2. En küçük id'yi "canonical" kural olarak tutar; diğerlerini siler.
#   3. Silinen kuralların rule_techniques kayıtlarını canonical kurala taşır.
#   4. idx_rules_name_source UNIQUE index ekler → gelecekte çift kural oluşmaz.
# Idempotent: index zaten varsa hiçbir şey yapmaz.
def migrate_consolidate_rules(db: sqlite3.Connection) -> None:
    """Merge duplicate (name, source) rules into one row, combining techniques."""
    indexes = [r[1] for r in db.execute("PRAGMA index_list(rules)").fetchall()]
    if "idx_rules_name_source" in indexes:
        return
    groups = db.execute(
        "SELECT name, source FROM rules GROUP BY name, source HAVING COUNT(*) > 1"
    ).fetchall()
    for g in groups:
        rows = db.execute(
            "SELECT id, tech FROM rules WHERE name=? AND source=? ORDER BY id ASC",
            (g["name"], g["source"])
        ).fetchall()
        keep_id = rows[0]["id"]
        for dup in rows[1:]:
            if dup["tech"]:
                db.execute(
                    "INSERT OR IGNORE INTO rule_techniques (rule_id, tech_id) VALUES (?,?)",
                    (keep_id, dup["tech"])
                )
            for t in db.execute(
                "SELECT tech_id FROM rule_techniques WHERE rule_id=?", (dup["id"],)
            ).fetchall():
                db.execute(
                    "INSERT OR IGNORE INTO rule_techniques (rule_id, tech_id) VALUES (?,?)",
                    (keep_id, t["tech_id"])
                )
            db.execute("DELETE FROM rule_techniques WHERE rule_id=?", (dup["id"],))
            db.execute("DELETE FROM rules WHERE id=?", (dup["id"],))
    db.commit()
    db.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_rules_name_source ON rules(name, source)"
    )
    db.commit()


# ── Migration: rules.tech → rule_techniques ──────────────────────────────────
# Eski şema rules.tech TEXT sütunuyla tek teknik tutuyordu. Bu migration
# mevcut rules satırlarından rule_techniques join tablosuna veri kopyalar.
# Idempotent: tabloda kayıt varsa atlanır.
def migrate_rule_techniques(db: sqlite3.Connection) -> None:
    existing = db.execute("SELECT rule_id FROM rule_techniques LIMIT 1").fetchone()
    if existing:
        return  # already migrated
    rows = db.execute("SELECT id, tech FROM rules").fetchall()
    for r in rows:
        db.execute(
            "INSERT OR IGNORE INTO rule_techniques (rule_id, tech_id) VALUES (?, ?)",
            (r["id"], r["tech"])
        )
    db.commit()


def build_technique_config(db: sqlite3.Connection) -> None:
    """Parse mitre.json to compute per-technique importance and rule_threshold.

    Importance is derived from how many threat groups (intrusion-sets) and
    tools/malware use each technique (via 'uses' relationships).
      importance = clamp(0.3 + 0.7 * (group_count*2 + tool_count) / 60, 0.3, 1.0)
      rule_threshold = clamp(1 + group_count // 8, 1, 5)

    Idempotent: skips if any 'auto' rows already exist.
    """
    if db.execute("SELECT 1 FROM technique_config WHERE source='auto' LIMIT 1").fetchone():
        return  # already built
    if not MITRE_PATH.exists():
        return  # no mitre data available yet

    data = json.loads(MITRE_PATH.read_text(encoding="utf-8"))
    objects = data.get("objects", [])

    # Map STIX id → T-code for non-deprecated attack-patterns
    tech_stix: dict[str, str] = {}
    group_stix: set[str] = set()
    tool_stix: set[str] = set()

    for obj in objects:
        t = obj.get("type", "")
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        if t == "attack-pattern":
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    eid = ref.get("external_id", "")
                    if eid.startswith("T"):
                        tech_stix[obj["id"]] = eid
        elif t == "intrusion-set":
            group_stix.add(obj["id"])
        elif t in ("malware", "tool"):
            tool_stix.add(obj["id"])

    # Count "uses" relationships per technique
    group_counts: dict[str, set[str]] = {}
    tool_counts: dict[str, set[str]] = {}

    for obj in objects:
        if obj.get("type") != "relationship":
            continue
        if obj.get("relationship_type") != "uses":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        src = obj.get("source_ref", "")
        tgt = obj.get("target_ref", "")
        tid = tech_stix.get(tgt)
        if not tid:
            continue
        if src in group_stix:
            group_counts.setdefault(tid, set()).add(src)
        elif src in tool_stix:
            tool_counts.setdefault(tid, set()).add(src)

    # Compute importance and rule_threshold for each technique
    rows = []
    for _stix_id, tid in tech_stix.items():
        g = len(group_counts.get(tid, set()))
        t = len(tool_counts.get(tid, set()))
        raw = g * 2 + t
        importance = round(min(0.3 + 0.7 * (raw / 60.0), 1.0), 3)
        rule_threshold = max(1, min(5, 1 + g // 8))
        rows.append((tid, importance, rule_threshold, "auto", g, t))

    db.executemany(
        "INSERT OR IGNORE INTO technique_config "
        "(tech_id, importance, rule_threshold, source, group_count, tool_count) VALUES (?,?,?,?,?,?)",
        rows,
    )
    db.commit()


def ensure_soc_cmm_schema(db: sqlite3.Connection) -> None:
    """Create the governed SOC-CMM KPI model without changing legacy scores."""
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS soc_profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            scope TEXT NOT NULL DEFAULT 'Kurum geneli',
            attack_version TEXT NOT NULL DEFAULT '',
            version INTEGER NOT NULL DEFAULT 1,
            status TEXT NOT NULL DEFAULT 'draft'
                CHECK(status IN ('draft','approved','retired')),
            is_active INTEGER NOT NULL DEFAULT 0,
            approved_by TEXT NOT NULL DEFAULT '',
            approved_at TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS soc_profile_techniques (
            profile_id INTEGER NOT NULL,
            tech_id TEXT NOT NULL,
            included INTEGER NOT NULL DEFAULT 1,
            weight INTEGER NOT NULL DEFAULT 3 CHECK(weight BETWEEN 1 AND 5),
            rationale TEXT NOT NULL DEFAULT '',
            PRIMARY KEY (profile_id, tech_id),
            FOREIGN KEY (profile_id) REFERENCES soc_profiles(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS detection_assessments (
            rule_id INTEGER PRIMARY KEY,
            lifecycle_status TEXT NOT NULL DEFAULT 'active'
                CHECK(lifecycle_status IN ('draft','active','disabled')),
            validation_status TEXT NOT NULL DEFAULT 'untested'
                CHECK(validation_status IN ('untested','validated','failed','expired')),
            detection_score INTEGER NOT NULL DEFAULT 0 CHECK(detection_score BETWEEN -1 AND 5),
            applicable_scope TEXT NOT NULL DEFAULT 'Kurum geneli',
            owner TEXT NOT NULL DEFAULT '',
            validation_method TEXT NOT NULL DEFAULT '',
            evidence_ref TEXT NOT NULL DEFAULT '',
            data_dependencies TEXT NOT NULL DEFAULT '',
            last_validated_at TEXT,
            expires_at TEXT,
            updated_by TEXT NOT NULL DEFAULT '',
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (rule_id) REFERENCES rules(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS telemetry_sources (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            producer TEXT NOT NULL DEFAULT '',
            destination TEXT NOT NULL DEFAULT '',
            scope TEXT NOT NULL DEFAULT 'Kurum geneli',
            owner TEXT NOT NULL DEFAULT '',
            connected_at TEXT,
            last_event_at TEXT,
            active INTEGER NOT NULL DEFAULT 1,
            analytics_ready INTEGER NOT NULL DEFAULT 0,
            device_completeness INTEGER NOT NULL DEFAULT 0 CHECK(device_completeness BETWEEN 0 AND 5),
            field_completeness INTEGER NOT NULL DEFAULT 0 CHECK(field_completeness BETWEEN 0 AND 5),
            timeliness INTEGER NOT NULL DEFAULT 0 CHECK(timeliness BETWEEN 0 AND 5),
            consistency INTEGER NOT NULL DEFAULT 0 CHECK(consistency BETWEEN 0 AND 5),
            retention INTEGER NOT NULL DEFAULT 0 CHECK(retention BETWEEN 0 AND 5),
            notes TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS telemetry_components (
            source_id INTEGER NOT NULL,
            component_id TEXT NOT NULL,
            required_fields TEXT NOT NULL DEFAULT '',
            PRIMARY KEY (source_id, component_id),
            FOREIGN KEY (source_id) REFERENCES telemetry_sources(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS visibility_overrides (
            profile_id INTEGER NOT NULL,
            tech_id TEXT NOT NULL,
            score INTEGER NOT NULL CHECK(score BETWEEN 0 AND 4),
            reason TEXT NOT NULL,
            approved_by TEXT NOT NULL DEFAULT '',
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (profile_id, tech_id),
            FOREIGN KEY (profile_id) REFERENCES soc_profiles(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS kpi_snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            profile_id INTEGER NOT NULL,
            profile_version INTEGER NOT NULL,
            formula_version TEXT NOT NULL,
            attack_version TEXT NOT NULL DEFAULT '',
            scope TEXT NOT NULL,
            mapped_coverage REAL NOT NULL,
            validated_coverage REAL NOT NULL,
            weighted_detection REAL NOT NULL,
            visibility REAL NOT NULL,
            visible_threshold_coverage REAL NOT NULL,
            numerator_json TEXT NOT NULL,
            denominator INTEGER NOT NULL,
            payload_json TEXT NOT NULL,
            payload_hash TEXT NOT NULL,
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (profile_id) REFERENCES soc_profiles(id)
        );

        CREATE INDEX IF NOT EXISTS idx_profile_techniques_profile ON soc_profile_techniques(profile_id);
        CREATE INDEX IF NOT EXISTS idx_telemetry_components_component ON telemetry_components(component_id);
        CREATE INDEX IF NOT EXISTS idx_kpi_snapshots_profile_date ON kpi_snapshots(profile_id, created_at);
        CREATE TRIGGER IF NOT EXISTS kpi_snapshots_no_update
        BEFORE UPDATE ON kpi_snapshots BEGIN
            SELECT RAISE(ABORT, 'KPI snapshots are append-only');
        END;
        CREATE TRIGGER IF NOT EXISTS kpi_snapshots_no_delete
        BEFORE DELETE ON kpi_snapshots BEGIN
            SELECT RAISE(ABORT, 'KPI snapshots are append-only');
        END;
        """
    )
    db.execute(
        """
        INSERT OR IGNORE INTO detection_assessments (rule_id)
        SELECT id FROM rules
        """
    )
    db.commit()


def ensure_connector_schema(db: sqlite3.Connection) -> None:
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS connectors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            kind TEXT NOT NULL CHECK(kind IN ('qradar')),
            name TEXT NOT NULL UNIQUE,
            base_url TEXT NOT NULL,
            secret_env TEXT NOT NULL,
            product_name TEXT NOT NULL DEFAULT 'QRadar',
            mappings_path TEXT NOT NULL DEFAULT '/console/plugins/app_proxy:UseCaseManager_Service/api/mappings',
            verify_tls INTEGER NOT NULL DEFAULT 1,
            ca_bundle TEXT NOT NULL DEFAULT '',
            enabled INTEGER NOT NULL DEFAULT 1,
            import_new_rules INTEGER NOT NULL DEFAULT 1,
            last_status TEXT NOT NULL DEFAULT 'never',
            last_sync_at TEXT,
            last_error TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS connector_sync_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            connector_id INTEGER NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('running','success','failed')),
            triggered_by TEXT NOT NULL DEFAULT '',
            started_at TEXT NOT NULL,
            finished_at TEXT,
            received INTEGER NOT NULL DEFAULT 0,
            created INTEGER NOT NULL DEFAULT 0,
            updated INTEGER NOT NULL DEFAULT 0,
            unchanged INTEGER NOT NULL DEFAULT 0,
            linked_existing INTEGER NOT NULL DEFAULT 0,
            rules_created INTEGER NOT NULL DEFAULT 0,
            stale INTEGER NOT NULL DEFAULT 0,
            mapping_count INTEGER NOT NULL DEFAULT 0,
            payload_hash TEXT NOT NULL DEFAULT '',
            error TEXT NOT NULL DEFAULT '',
            FOREIGN KEY (connector_id) REFERENCES connectors(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS external_detections (
            connector_id INTEGER NOT NULL,
            native_id TEXT NOT NULL,
            name TEXT NOT NULL,
            origin TEXT NOT NULL DEFAULT 'unknown',
            enabled INTEGER NOT NULL DEFAULT 1,
            rule_type TEXT NOT NULL DEFAULT 'rule',
            severity TEXT NOT NULL DEFAULT '',
            offense_count INTEGER NOT NULL DEFAULT 0,
            last_offense_at TEXT NOT NULL DEFAULT '',
            payload_hash TEXT NOT NULL,
            first_seen_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            missing_sync_count INTEGER NOT NULL DEFAULT 0,
            stale INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (connector_id, native_id),
            FOREIGN KEY (connector_id) REFERENCES connectors(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS external_detection_techniques (
            connector_id INTEGER NOT NULL,
            native_id TEXT NOT NULL,
            tech_id TEXT NOT NULL,
            mapping_source TEXT NOT NULL DEFAULT 'qradar',
            PRIMARY KEY (connector_id, native_id, tech_id),
            FOREIGN KEY (connector_id, native_id)
                REFERENCES external_detections(connector_id, native_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS rule_external_refs (
            rule_id INTEGER NOT NULL,
            connector_id INTEGER NOT NULL,
            native_id TEXT NOT NULL,
            match_method TEXT NOT NULL,
            linked_at TEXT NOT NULL,
            PRIMARY KEY (connector_id, native_id),
            FOREIGN KEY (rule_id) REFERENCES rules(id) ON DELETE CASCADE,
            FOREIGN KEY (connector_id, native_id)
                REFERENCES external_detections(connector_id, native_id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_connector_runs_connector ON connector_sync_runs(connector_id, id DESC);
        CREATE INDEX IF NOT EXISTS idx_external_detections_state ON external_detections(connector_id, stale, enabled);
        CREATE INDEX IF NOT EXISTS idx_rule_external_refs_rule ON rule_external_refs(rule_id);
        """
    )
    db.commit()


def ensure_scope_registry_schema(db: sqlite3.Connection) -> None:
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS environments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            code TEXT NOT NULL UNIQUE,
            description TEXT NOT NULL DEFAULT '',
            criticality INTEGER NOT NULL DEFAULT 3 CHECK(criticality BETWEEN 1 AND 5),
            owner TEXT NOT NULL DEFAULT '',
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS asset_groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            environment_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            platform TEXT NOT NULL DEFAULT 'Other',
            asset_type TEXT NOT NULL DEFAULT 'Other',
            asset_count INTEGER NOT NULL DEFAULT 0 CHECK(asset_count >= 0),
            criticality INTEGER NOT NULL DEFAULT 3 CHECK(criticality BETWEEN 1 AND 5),
            owner TEXT NOT NULL DEFAULT '',
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(environment_id, name),
            FOREIGN KEY (environment_id) REFERENCES environments(id)
        );

        CREATE TABLE IF NOT EXISTS product_deployments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_group_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            connector_id INTEGER,
            monitoring_status TEXT NOT NULL DEFAULT 'unknown'
                CHECK(monitoring_status IN ('unknown','none','partial','full')),
            coverage_percent INTEGER NOT NULL DEFAULT 0 CHECK(coverage_percent BETWEEN 0 AND 100),
            monitoring_mode TEXT NOT NULL DEFAULT 'other'
                CHECK(monitoring_mode IN ('agent','log_forwarding','api','network','hybrid','other')),
            owner TEXT NOT NULL DEFAULT '',
            notes TEXT NOT NULL DEFAULT '',
            reviewed_by TEXT NOT NULL DEFAULT '',
            reviewed_at TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(asset_group_id, product_id),
            FOREIGN KEY (asset_group_id) REFERENCES asset_groups(id) ON DELETE CASCADE,
            FOREIGN KEY (product_id) REFERENCES products(id),
            FOREIGN KEY (connector_id) REFERENCES connectors(id)
        );

        CREATE INDEX IF NOT EXISTS idx_asset_groups_environment ON asset_groups(environment_id, active);
        CREATE INDEX IF NOT EXISTS idx_product_deployments_group ON product_deployments(asset_group_id);
        CREATE INDEX IF NOT EXISTS idx_product_deployments_connector ON product_deployments(connector_id);
        """
    )
    db.commit()


def _attack_catalog() -> dict[str, Any]:
    """Return the ATT&CK techniques, data components and v18 detection links."""
    if not MITRE_PATH.exists():
        return {"techniques": {}, "components": {}, "tech_components": {}, "version": ""}
    raw = json.loads(MITRE_PATH.read_text(encoding="utf-8"))
    objects = [
        obj for obj in raw.get("objects", [])
        if not obj.get("revoked") and not obj.get("x_mitre_deprecated")
    ]
    by_id = {obj.get("id"): obj for obj in objects if obj.get("id")}

    def external_id(obj: dict[str, Any], prefix: str) -> str:
        return next((
            ref.get("external_id", "")
            for ref in obj.get("external_references", [])
            if ref.get("source_name") == "mitre-attack"
            and ref.get("external_id", "").startswith(prefix)
        ), "")

    techniques: dict[str, Any] = {}
    components: dict[str, Any] = {}
    analytic_components: dict[str, set[str]] = {}
    strategy_components: dict[str, set[str]] = {}
    versions: list[str] = []
    attack_version = ""
    for obj in objects:
        obj_type = obj.get("type")
        if obj_type == "attack-pattern":
            tech_id = external_id(obj, "T")
            if tech_id:
                techniques[tech_id] = {
                    "id": tech_id,
                    "name": obj.get("name", ""),
                    "platforms": obj.get("x_mitre_platforms", []),
                    "tactics": [
                        phase.get("phase_name", "")
                        for phase in obj.get("kill_chain_phases", [])
                        if phase.get("kill_chain_name") == "mitre-attack"
                    ],
                    "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique")),
                    "stix_id": obj.get("id", ""),
                }
                if obj.get("x_mitre_attack_spec_version"):
                    versions.append(str(obj["x_mitre_attack_spec_version"]))
        elif obj_type == "x-mitre-data-component":
            component_id = external_id(obj, "DC")
            if component_id:
                components[component_id] = {
                    "id": component_id,
                    "name": obj.get("name", ""),
                    "description": obj.get("description", ""),
                    "log_sources": obj.get("x_mitre_log_sources", []),
                    "stix_id": obj.get("id", ""),
                }
        elif obj_type == "x-mitre-analytic":
            analytic_components[obj.get("id", "")] = {
                ref.get("x_mitre_data_component_ref", "")
                for ref in obj.get("x_mitre_log_source_references", [])
                if ref.get("x_mitre_data_component_ref")
            }
        elif obj_type == "x-mitre-collection" and obj.get("name") == "Enterprise ATT&CK":
            attack_version = str(obj.get("x_mitre_version", ""))

    for obj in objects:
        if obj.get("type") == "x-mitre-detection-strategy":
            refs: set[str] = set()
            for analytic_ref in obj.get("x_mitre_analytic_refs", []):
                refs |= analytic_components.get(analytic_ref, set())
            strategy_components[obj.get("id", "")] = refs

    component_by_stix = {value["stix_id"]: key for key, value in components.items()}
    technique_by_stix = {value["stix_id"]: key for key, value in techniques.items()}
    tech_components: dict[str, set[str]] = defaultdict(set)
    for obj in objects:
        if obj.get("type") != "relationship" or obj.get("relationship_type") != "detects":
            continue
        tech_id = technique_by_stix.get(obj.get("target_ref", ""))
        if not tech_id:
            continue
        for component_ref in strategy_components.get(obj.get("source_ref", ""), set()):
            component_id = component_by_stix.get(component_ref)
            if component_id:
                tech_components[tech_id].add(component_id)

    return {
        "techniques": techniques,
        "components": components,
        "tech_components": {key: sorted(value) for key, value in tech_components.items()},
        "version": attack_version or max(versions, default=""),
    }


def ensure_default_soc_profile(db: sqlite3.Connection) -> None:
    catalog = _attack_catalog()
    if db.execute("SELECT COUNT(*) FROM soc_profiles").fetchone()[0]:
        if catalog["version"]:
            db.execute(
                "UPDATE soc_profiles SET attack_version=? WHERE status='draft' AND (attack_version='' OR attack_version LIKE '3.%')",
                (catalog["version"],),
            )
            db.commit()
        return
    cursor = db.execute(
        """
        INSERT INTO soc_profiles (name, description, scope, attack_version, is_active)
        VALUES (?, ?, ?, ?, 1)
        """,
        (
            "Kurumsal ATT&CK Profili",
            "İlk envanter. Kapsam, ağırlıklar ve gerekçeler onay öncesinde gözden geçirilmelidir.",
            "Kurum geneli",
            catalog["version"],
        ),
    )
    profile_id = cursor.lastrowid
    db.executemany(
        "INSERT INTO soc_profile_techniques (profile_id, tech_id) VALUES (?, ?)",
        [(profile_id, tech_id) for tech_id in catalog["techniques"]],
    )
    db.commit()


def _json_text(value: Any) -> str:
    if value is None:
        return ""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _audit_entry_hash(row: dict[str, Any], prev_hash: str) -> str:
    payload = {
        "user_id": row.get("user_id"),
        "username": row.get("username", ""),
        "action": row.get("action", ""),
        "target_type": row.get("target_type", ""),
        "target_id": row.get("target_id", ""),
        "detail": row.get("detail", ""),
        "request_id": row.get("request_id", ""),
        "ip_address": row.get("ip_address", ""),
        "user_agent": row.get("user_agent", ""),
        "before_json": row.get("before_json", ""),
        "after_json": row.get("after_json", ""),
        "created_at": row.get("created_at", ""),
    }
    canonical = _json_text(payload)
    return hashlib.sha256(f"{prev_hash}|{canonical}".encode("utf-8")).hexdigest()


def ensure_audit_integrity(db: sqlite3.Connection) -> None:
    """Upgrade legacy audit rows and make the log append-only."""
    existing = {r[1] for r in db.execute("PRAGMA table_info(audit_logs)").fetchall()}
    added_columns = False
    for name, definition in AUDIT_COLUMNS.items():
        if name not in existing:
            db.execute(f"ALTER TABLE audit_logs ADD COLUMN {name} {definition}")
            added_columns = True

    if added_columns:
        prev_hash = ""
        rows = db.execute("SELECT * FROM audit_logs ORDER BY id ASC").fetchall()
        for row in rows:
            values = dict(row)
            entry_hash = _audit_entry_hash(values, prev_hash)
            db.execute(
                "UPDATE audit_logs SET prev_hash=?, entry_hash=? WHERE id=?",
                (prev_hash, entry_hash, row["id"]),
            )
            prev_hash = entry_hash

    db.executescript(
        """
        CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_logs(created_at);
        CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_logs(username);
        CREATE INDEX IF NOT EXISTS idx_audit_target ON audit_logs(target_type, target_id);
        CREATE TRIGGER IF NOT EXISTS audit_logs_no_update
        BEFORE UPDATE ON audit_logs
        BEGIN
            SELECT RAISE(ABORT, 'audit logs are append-only');
        END;
        CREATE TRIGGER IF NOT EXISTS audit_logs_no_delete
        BEFORE DELETE ON audit_logs
        BEGIN
            SELECT RAISE(ABORT, 'audit logs are append-only');
        END;
        """
    )
    db.commit()


def verify_audit_chain(db: sqlite3.Connection) -> dict[str, Any]:
    prev_hash = ""
    checked = 0
    for row in db.execute("SELECT * FROM audit_logs ORDER BY id ASC").fetchall():
        values = dict(row)
        expected = _audit_entry_hash(values, prev_hash)
        if values.get("prev_hash", "") != prev_hash or values.get("entry_hash", "") != expected:
            return {"valid": False, "checked": checked, "broken_at_id": row["id"]}
        prev_hash = expected
        checked += 1
    return {"valid": True, "checked": checked, "broken_at_id": None, "head_hash": prev_hash}


def init_db() -> None:
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    try:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                tactic TEXT NOT NULL,
                tech TEXT NOT NULL,
                source TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS mitigation_notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                technique_id TEXT NOT NULL,
                mitigation_id TEXT NOT NULL,
                checked INTEGER NOT NULL DEFAULT 0,
                comment TEXT NOT NULL DEFAULT "",
                team TEXT NOT NULL DEFAULT "",
                UNIQUE(technique_id, mitigation_id)
            );

            CREATE TABLE IF NOT EXISTS products (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                color TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS mitigation_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mitigation_id TEXT NOT NULL,
                team TEXT NOT NULL DEFAULT "",
                comment TEXT NOT NULL DEFAULT ""
            );

            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('viewer','editor','admin')),
                is_active INTEGER NOT NULL DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                username TEXT NOT NULL DEFAULT '',
                action TEXT NOT NULL,
                target_type TEXT NOT NULL,
                target_id TEXT NOT NULL DEFAULT '',
                detail TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            -- rule_techniques: bir kural birden fazla MITRE tekniğine bağlanabilir.
            -- tech_id alanı T1059 veya teknik adı (eski seed) olabilir; frontend
            -- her ikisini de nameToIdMap ile çözümler.
            CREATE TABLE IF NOT EXISTS rule_techniques (
                rule_id INTEGER NOT NULL,
                tech_id TEXT NOT NULL,
                PRIMARY KEY (rule_id, tech_id)
            );

            -- technique_config: her MITRE tekniği için data-driven önem skoru ve kural eşiği.
            -- importance (0.3–1.0): tehdit grubu/araç kullanım sıklığından hesaplanır.
            -- rule_threshold (1–10): "yeterli kapsama" sayılacak minimum kural sayısı.
            -- source: 'auto' (mitre.json parse) | 'admin' (el ile override).
            CREATE TABLE IF NOT EXISTS technique_config (
                tech_id          TEXT PRIMARY KEY,
                importance       REAL NOT NULL DEFAULT 0.5,
                rule_threshold   INTEGER NOT NULL DEFAULT 3,
                source           TEXT NOT NULL DEFAULT 'auto',
                group_count      INTEGER NOT NULL DEFAULT 0,
                tool_count       INTEGER NOT NULL DEFAULT 0
            );
            """
        )
        db.commit()
        ensure_mitigation_team_column(db)
        ensure_mitigation_global_table(db)
        ensure_mitigation_global_seed(db)
        ensure_teams_table(db)
        ensure_action_items_table(db)
        ensure_products(db)
        ensure_users(db)
        ensure_audit_integrity(db)
        ensure_connector_schema(db)
        ensure_scope_registry_schema(db)
        migrate_rule_techniques(db)
        migrate_consolidate_rules(db)
        build_technique_config(db)
        ensure_rule_coverage_level(db)
        ensure_soc_cmm_schema(db)
        ensure_default_soc_profile(db)
    finally:
        db.close()


def ensure_rule_coverage_level(db: sqlite3.Connection) -> None:
    cols = {r[1] for r in db.execute("PRAGMA table_info(rules)").fetchall()}
    if "coverage_level" not in cols:
        db.execute(
            "ALTER TABLE rules ADD COLUMN coverage_level TEXT NOT NULL DEFAULT 'full'"
        )
        db.commit()


def ensure_products(db: sqlite3.Connection) -> None:
    existing = db.execute("SELECT COUNT(*) AS cnt FROM products").fetchone()[0]
    if existing:
        return
    defaults = [
        ("QRadar", "#2e7d32"),
        ("DFE", "#1565c0"),
        ("DefO365", "#ef6c00"),
        ("DefIdentity", "#6a1b9a"),
        ("Other", "#546e7a"),
    ]
    db.executemany("INSERT INTO products (name, color) VALUES (?, ?)", defaults)
    db.commit()


def ensure_users(db: sqlite3.Connection) -> None:
    existing = db.execute("SELECT COUNT(*) AS cnt FROM users").fetchone()[0]
    if existing:
        return
    defaults = [
        ("admin", generate_password_hash("Admin123!"), "admin", 1),
        ("editor", generate_password_hash("Editor123!"), "editor", 1),
        ("viewer", generate_password_hash("Viewer123!"), "viewer", 1),
    ]
    db.executemany(
        "INSERT INTO users (username, password_hash, role, is_active) VALUES (?, ?, ?, ?)",
        defaults,
    )
    db.commit()


def get_current_user() -> dict[str, Any] | None:
    user_id = session.get("user_id")
    if not user_id:
        return None
    db = get_db()
    row = db.execute(
        "SELECT id, username, role, is_active FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()
    if not row or not row["is_active"]:
        session.clear()
        return None
    return dict(row)


def write_audit_log(
    db: sqlite3.Connection,
    action: str,
    target_type: str,
    target_id: str = "",
    detail: str = "",
    user: dict[str, Any] | None = None,
    before: Any = None,
    after: Any = None,
) -> None:
    actor = user or getattr(g, "current_user", None)
    user_id = actor.get("id") if actor else None
    username = actor.get("username", "") if actor else ""
    request_id = getattr(g, "request_id", "")
    ip_address = request.remote_addr or ""
    user_agent = request.user_agent.string[:500]
    before_json = _json_text(before)
    after_json = _json_text(after)
    created_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    previous = db.execute(
        "SELECT entry_hash FROM audit_logs ORDER BY id DESC LIMIT 1"
    ).fetchone()
    prev_hash = previous["entry_hash"] if previous else ""
    values = {
        "user_id": user_id,
        "username": username,
        "action": action,
        "target_type": target_type,
        "target_id": target_id,
        "detail": detail[:4000],
        "request_id": request_id,
        "ip_address": ip_address,
        "user_agent": user_agent,
        "before_json": before_json,
        "after_json": after_json,
        "created_at": created_at,
    }
    entry_hash = _audit_entry_hash(values, prev_hash)
    db.execute(
        """
        INSERT INTO audit_logs (
            user_id, username, action, target_type, target_id, detail,
            request_id, ip_address, user_agent, before_json, after_json,
            prev_hash, entry_hash, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            user_id, username, action, target_type, target_id, detail[:4000],
            request_id, ip_address, user_agent, before_json, after_json,
            prev_hash, entry_hash, created_at,
        ),
    )


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = get_current_user()
        if not user:
            if request.path.startswith("/api/"):
                return jsonify({"error": "Authentication required"}), 401
            return redirect(url_for("login_page"))
        g.current_user = user
        return fn(*args, **kwargs)

    return wrapper


def role_required(min_role: str):
    min_level = ROLE_LEVELS[min_role]

    def decorator(fn):
        @wraps(fn)
        @login_required
        def wrapper(*args, **kwargs):
            user = g.current_user
            level = ROLE_LEVELS.get(user["role"], 0)
            if level < min_level:
                return jsonify({"error": "Forbidden"}), 403
            return fn(*args, **kwargs)

        return wrapper

    return decorator




def _compute_gap_analysis(mitre_data: dict, db: sqlite3.Connection) -> dict:
    """Shared logic for /api/gap-analysis and /report.
    Returns dict with overview, by_tactic, critical_gaps."""
    tech_by_stix: dict[str, dict] = {}
    mitigation_stix_to_ext: dict[str, str] = {}
    tech_to_mitigations: dict[str, set] = {}

    for obj in mitre_data["objects"]:
        t = obj.get("type")
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        if t == "attack-pattern":
            ext_id = next(
                (
                    ref["external_id"]
                    for ref in obj.get("external_references", [])
                    if ref.get("source_name") == "mitre-attack"
                    and ref.get("external_id", "").startswith("T")
                ),
                None,
            )
            if not ext_id:
                continue
            tactics = [
                ph["phase_name"]
                for ph in obj.get("kill_chain_phases", [])
                if ph.get("kill_chain_name") == "mitre-attack"
            ]
            tech_by_stix[obj["id"]] = {
                "external_id": ext_id,
                "name": obj.get("name", ""),
                "is_subtechnique": obj.get("x_mitre_is_subtechnique", False),
                "tactics": tactics,
            }
        elif t == "course-of-action":
            ext_id = next(
                (
                    ref["external_id"]
                    for ref in obj.get("external_references", [])
                    if ref.get("source_name") == "mitre-attack"
                    and ref.get("external_id", "").startswith("M")
                ),
                None,
            )
            if ext_id:
                mitigation_stix_to_ext[obj["id"]] = ext_id
        elif t == "relationship" and obj.get("relationship_type") == "mitigates":
            mit_ext = mitigation_stix_to_ext.get(obj.get("source_ref", ""))
            tech_info = tech_by_stix.get(obj.get("target_ref", ""))
            if mit_ext and tech_info:
                tech_to_mitigations.setdefault(tech_info["external_id"], set()).add(mit_ext)

    rule_stats_by_tech = {
        r["tech_id"]: dict(r)
        for r in db.execute(
            """
            SELECT rt.tech_id,
                   COUNT(DISTINCT r.id) AS rule_count,
                   SUM(CASE r.coverage_level
                         WHEN 'low' THEN 0.25
                         WHEN 'partial' THEN 0.60
                         ELSE 1.00 END) AS effective_rule_count,
                   COUNT(DISTINCT r.source) AS product_count
            FROM rule_techniques rt
            JOIN rules r ON r.id = rt.rule_id
            GROUP BY rt.tech_id
            """
        ).fetchall()
    }

    covered_mits: set = set(
        r["mitigation_id"]
        for r in db.execute(
            "SELECT DISTINCT mitigation_id FROM mitigation_entries"
        ).fetchall()
    )
    covered_mits |= set(
        r["mitigation_id"]
        for r in db.execute(
            "SELECT mitigation_id FROM mitigation_global WHERE checked=1"
        ).fetchall()
    )

    tech_config = {
        r["tech_id"]: {"importance": r["importance"], "rule_threshold": r["rule_threshold"]}
        for r in db.execute(
            "SELECT tech_id, importance, rule_threshold FROM technique_config"
        ).fetchall()
    }

    all_techs = []
    for _stix_id, info in tech_by_stix.items():
        teid = info["external_id"]
        rule_stats = rule_stats_by_tech.get(teid, {})
        rule_count = int(rule_stats.get("rule_count", 0))
        effective_rule_count = float(rule_stats.get("effective_rule_count", 0.0))
        product_count = int(rule_stats.get("product_count", 0))
        mits_for_tech = tech_to_mitigations.get(teid, set())
        covered_mitigation_count = len(mits_for_tech & covered_mits)
        mitigation_checked = covered_mitigation_count > 0
        tc = tech_config.get(teid, {})
        importance = tc.get("importance", 0.5)
        rule_threshold = max(1, int(tc.get("rule_threshold", 3)))
        rule_score = min(effective_rule_count / rule_threshold, 1.0)
        mitigation_score = (
            min(covered_mitigation_count / len(mits_for_tech), 1.0)
            if mits_for_tech else 0.0
        )
        diversity_score = min(product_count / 2, 1.0)
        coverage_score = min(
            rule_score * 0.50 + mitigation_score * 0.30 + diversity_score * 0.20,
            1.0,
        )
        detected = rule_count > 0
        mature = coverage_score >= 0.70
        imp_level = _importance_to_level(importance)
        all_techs.append({
            "tech_id": teid,
            "name": info["name"],
            "is_subtechnique": info["is_subtechnique"],
            "tactics": info["tactics"],
            "rule_count": rule_count,
            "effective_rule_count": round(effective_rule_count, 2),
            "rule_threshold": rule_threshold,
            "product_count": product_count,
            "mitigation_checked": mitigation_checked,
            "mitigation_count": covered_mitigation_count,
            "coverage_score": round(coverage_score, 3),
            "covered": detected,
            "mature": mature,
            "importance": importance,
            "importance_level": imp_level,
        })

    parents = [t for t in all_techs if not t["is_subtechnique"]]
    subs = [t for t in all_techs if t["is_subtechnique"]]
    # Kapsama yüzdesine alt teknikler de dahil
    total_all = len(all_techs)
    covered_all = sum(1 for t in all_techs if t["covered"])
    total_techniques = len(parents)
    covered_techniques = sum(1 for t in parents if t["covered"])
    total_subtechniques = len(subs)
    covered_subtechniques = sum(1 for t in subs if t["covered"])
    mature_all = sum(1 for t in all_techs if t["mature"])
    average_score = round(
        sum(t["coverage_score"] for t in all_techs) / max(total_all, 1) * 100, 1
    )
    # Kritik boşluklar: yüksek öneme rağmen olgunluk skoru %35'in altında.
    critical_gaps_list = [
        t for t in all_techs
        if t["importance_level"] >= 4 and t["coverage_score"] < 0.35
    ]
    # Genel kapsama % — tüm teknikler (parent + alt)
    coverage_pct = round(covered_all / total_all * 100, 1) if total_all else 0.0

    # Taktik bazlı: parent + alt teknikler birlikte
    by_tactic_map: dict[str, dict] = {}
    for t in all_techs:
        for tactic in t["tactics"]:
            entry = by_tactic_map.setdefault(
                tactic, {"total": 0, "covered": 0, "mature": 0, "score_total": 0.0}
            )
            entry["total"] += 1
            entry["score_total"] += t["coverage_score"]
            if t["covered"]:
                entry["covered"] += 1
            if t["mature"]:
                entry["mature"] += 1

    by_tactic = []
    for tactic in _TACTIC_ORDER:
        if tactic in by_tactic_map:
            entry = by_tactic_map[tactic]
            pct = round(entry["covered"] / entry["total"] * 100, 1) if entry["total"] else 0.0
            by_tactic.append({
                "tactic": tactic,
                "label": _TACTIC_LABEL_MAP.get(tactic, tactic),
                "total": entry["total"],
                "covered": entry["covered"],
                "pct": pct,
                "mature": entry["mature"],
                "maturity_pct": round(entry["mature"] / entry["total"] * 100, 1),
                "average_score_pct": round(entry["score_total"] / entry["total"] * 100, 1),
            })
    for tactic, entry in by_tactic_map.items():
        if tactic not in _TACTIC_ORDER:
            pct = round(entry["covered"] / entry["total"] * 100, 1) if entry["total"] else 0.0
            by_tactic.append({
                "tactic": tactic,
                "label": _TACTIC_LABEL_MAP.get(tactic, tactic),
                "total": entry["total"],
                "covered": entry["covered"],
                "pct": pct,
                "mature": entry["mature"],
                "maturity_pct": round(entry["mature"] / entry["total"] * 100, 1),
                "average_score_pct": round(entry["score_total"] / entry["total"] * 100, 1),
            })

    critical_gaps_sorted = sorted(
        critical_gaps_list, key=lambda x: (-x["importance"], x["name"])
    )[:50]
    critical_gaps_out = [
        {
            "tech_id": t["tech_id"],
            "name": t["name"],
            "tactic": t["tactics"][0] if t["tactics"] else "",
            "importance_level": t["importance_level"],
            "importance": t["importance"],
            "rule_count": t["rule_count"],
            "effective_rule_count": t["effective_rule_count"],
            "rule_threshold": t["rule_threshold"],
            "product_count": t["product_count"],
            "coverage_score": t["coverage_score"],
            "mitigation_checked": t["mitigation_checked"],
        }
        for t in critical_gaps_sorted
    ]

    return {
        "overview": {
            # Genel (parent + alt) sayılar — coverage_pct buna göre
            "total_techniques": total_all,
            "covered_techniques": covered_all,
            "coverage_pct": coverage_pct,
            "mature_techniques": mature_all,
            "maturity_pct": round(mature_all / total_all * 100, 1) if total_all else 0.0,
            "average_score_pct": average_score,
            # Sadece parent / sadece alt — UI'da detay göstermek için
            "parent_total": total_techniques,
            "parent_covered": covered_techniques,
            "total_subtechniques": total_subtechniques,
            "covered_subtechniques": covered_subtechniques,
            "critical_gap_count": len(critical_gaps_list),
        },
        "by_tactic": by_tactic,
        "critical_gaps": critical_gaps_out,
    }


def _get_threat_actors() -> list:
    """Parse mitre.json for intrusion-sets and their technique usage. Cached."""
    if not MITRE_PATH.exists():
        return []
    mtime = MITRE_PATH.stat().st_mtime
    if THREAT_ACTOR_CACHE["data"] is not None and THREAT_ACTOR_CACHE["mtime"] == mtime:
        return THREAT_ACTOR_CACHE["data"]  # type: ignore[return-value]

    data = json.loads(MITRE_PATH.read_text(encoding="utf-8"))
    objects = data.get("objects", [])

    tech_stix_to_ext: dict[str, str] = {}
    actors: dict[str, dict] = {}

    for obj in objects:
        t = obj.get("type", "")
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        if t == "attack-pattern":
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack" and ref.get("external_id", "").startswith("T"):
                    tech_stix_to_ext[obj["id"]] = ref["external_id"]
                    break
        elif t == "intrusion-set":
            stix_id = obj["id"]
            name = obj.get("name", "")
            aliases = obj.get("aliases", [name])
            g_id = ""
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack" and ref.get("external_id", "").startswith("G"):
                    g_id = ref["external_id"]
                    break
            actors[stix_id] = {
                "id": g_id,
                "stix_id": stix_id,
                "name": name,
                "aliases": aliases,
                "technique_ids": set(),
            }

    for obj in objects:
        if obj.get("type") != "relationship":
            continue
        if obj.get("relationship_type") != "uses":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        src = obj.get("source_ref", "")
        tgt = obj.get("target_ref", "")
        if src in actors:
            t_ext = tech_stix_to_ext.get(tgt)
            if t_ext:
                actors[src]["technique_ids"].add(t_ext)

    result = [
        {
            "id": a["id"],
            "stix_id": a["stix_id"],
            "name": a["name"],
            "aliases": a["aliases"],
            "technique_ids": sorted(a["technique_ids"]),
        }
        for a in actors.values()
    ]
    result.sort(key=lambda x: x["name"])

    THREAT_ACTOR_CACHE["mtime"] = mtime
    THREAT_ACTOR_CACHE["data"] = result
    return result


def _minify_mitre(raw: dict) -> dict:
    objects = raw.get("objects", [])
    out = {"objects": []}
    for obj in objects:
        t = obj.get("type")
        if t == "attack-pattern":
            out["objects"].append({
                "type": "attack-pattern",
                "id": obj.get("id"),
                "name": obj.get("name"),
                "description": obj.get("description"),
                "kill_chain_phases": obj.get("kill_chain_phases", []),
                "x_mitre_is_subtechnique": obj.get("x_mitre_is_subtechnique", False),
                "x_mitre_platforms": obj.get("x_mitre_platforms", []),
                "external_references": obj.get("external_references", []),
                "revoked": obj.get("revoked", False),
                "x_mitre_deprecated": obj.get("x_mitre_deprecated", False),
            })
        elif t == "course-of-action":
            out["objects"].append({
                "type": "course-of-action",
                "id": obj.get("id"),
                "name": obj.get("name"),
                "description": obj.get("description"),
                "external_references": obj.get("external_references", []),
                "revoked": obj.get("revoked", False),
                "x_mitre_deprecated": obj.get("x_mitre_deprecated", False),
            })
        elif t == "relationship" and obj.get("relationship_type") == "mitigates":
            out["objects"].append({
                "type": "relationship",
                "relationship_type": "mitigates",
                "source_ref": obj.get("source_ref"),
                "target_ref": obj.get("target_ref"),
            })
    return out


def get_minified_mitre() -> dict:
    if not MITRE_PATH.exists():
        raise FileNotFoundError("MITRE data not found")
    mtime = MITRE_PATH.stat().st_mtime
    if MITRE_CACHE["data"] is None or MITRE_CACHE["mtime"] != mtime:
        raw = json.loads(MITRE_PATH.read_text(encoding="utf-8"))
        MITRE_CACHE["data"] = _minify_mitre(raw)
        MITRE_CACHE["mtime"] = mtime
    return MITRE_CACHE["data"]


def _load_seed_rules() -> list[dict[str, Any]]:
    if SEED_RULES_PATH.exists():
        try:
            return json.loads(SEED_RULES_PATH.read_text(encoding="utf-8"))
        except Exception:
            return []

    if LEGACY_SOC_HTML.exists():
        try:
            text = LEGACY_SOC_HTML.read_text(encoding="utf-8", errors="ignore")
            match = None
            import re
            match = re.search(r"let\s+userRules\s*=\s*(\[.*?\]);", text, re.S)
            if not match:
                return []
            return json.loads(match.group(1))
        except Exception:
            return []

    return []


def _reseed_rules(db: sqlite3.Connection) -> int:
    rules = _load_seed_rules()
    inserted = 0
    for r in rules:
        name = (r.get("name") or "").strip()
        tactic = (r.get("tactic") or "").strip()
        tech = (r.get("tech") or "").strip()
        source = (r.get("source") or "").strip() or "Other"
        if not name or not tactic or not tech:
            continue
        db.execute(
            "INSERT INTO rules (name, tactic, tech, source) VALUES (?, ?, ?, ?)",
            (name, tactic, tech, source)
        )
        inserted += 1
    db.commit()
    return inserted


@app.route("/")
@login_required
def index() -> str:
    return render_template("index.html")


@app.route("/login")
def login_page() -> str:
    user = get_current_user()
    if user:
        return redirect(url_for("index"))
    return render_template("login.html")


@app.route("/api/login", methods=["POST"])
def login_api():
    payload = request.get_json(silent=True) or {}
    username = (payload.get("username") or "").strip()
    password = (payload.get("password") or "").strip()
    if not username or not password:
        return jsonify({"error": "Missing fields: username, password"}), 400
    db = get_db()
    attempt_key = _login_attempt_key(username)
    if _login_is_limited(attempt_key):
        write_audit_log(
            db,
            action="login_blocked",
            target_type="session",
            detail="Too many failed login attempts",
            user={"id": None, "username": username},
        )
        db.commit()
        response = jsonify({"error": "Too many failed attempts. Try again later."})
        response.headers["Retry-After"] = str(LOGIN_WINDOW_SECONDS)
        return response, 429
    row = db.execute(
        "SELECT id, username, password_hash, role, is_active FROM users WHERE username = ?",
        (username,),
    ).fetchone()
    if not row or not row["is_active"] or not check_password_hash(row["password_hash"], password):
        _record_login_failure(attempt_key)
        write_audit_log(
            db,
            action="login_failed",
            target_type="session",
            detail="Invalid credentials or inactive account",
            user={"id": row["id"] if row else None, "username": username},
        )
        db.commit()
        return jsonify({"error": "Invalid credentials"}), 401
    _clear_login_failures(attempt_key)
    session.clear()
    session["user_id"] = row["id"]
    write_audit_log(
        db,
        action="login",
        target_type="session",
        target_id=str(row["id"]),
        detail="Login successful",
        user={"id": row["id"], "username": row["username"]},
        after={"role": row["role"]},
    )
    db.commit()
    return jsonify({"ok": True, "user": {"id": row["id"], "username": row["username"], "role": row["role"]}})


@app.route("/api/logout", methods=["POST"])
@login_required
def logout_api():
    db = get_db()
    write_audit_log(db, action="logout", target_type="session", detail="Logout")
    db.commit()
    session.clear()
    return jsonify({"ok": True})


@app.route("/api/me")
@login_required
def me():
    user = g.current_user
    return jsonify({"id": user["id"], "username": user["username"], "role": user["role"]})




@app.route("/api/mitre-min")
@role_required("viewer")
def mitre_min():
    if not MITRE_PATH.exists():
        return jsonify({"error": "MITRE data not found. Place mitre.json in data/mitre.json."}), 500
    try:
        return jsonify(get_minified_mitre())
    except Exception as exc:
        return jsonify({"error": f"MITRE data load failed: {exc}"}), 500


@app.route("/api/mitre")
@role_required("viewer")
def mitre_json():
    if not MITRE_PATH.exists():
        return jsonify({"error": "MITRE data not found. Place mitre.json in data/mitre.json."}), 500
    try:
        with MITRE_PATH.open("r", encoding="utf-8") as f:
            data = json.load(f)
        return jsonify(data)
    except Exception as exc:
        return jsonify({"error": f"MITRE data load failed: {exc}"}), 500


@app.route("/api/rules", methods=["GET", "POST"])
@role_required("viewer")
def rules():
    db = get_db()
    if request.method == "GET":
        rows = db.execute("""
            SELECT r.id, r.name, r.tactic, r.tech, r.source, r.coverage_level,
                   da.lifecycle_status, da.validation_status, da.detection_score,
                   da.applicable_scope, da.owner, da.validation_method,
                   da.evidence_ref, da.last_validated_at, da.expires_at,
                   GROUP_CONCAT(rt.tech_id) as techs
            FROM rules r
            LEFT JOIN rule_techniques rt ON rt.rule_id = r.id
            LEFT JOIN detection_assessments da ON da.rule_id = r.id
            GROUP BY r.id ORDER BY r.id ASC
        """).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            techs_raw = d.pop("techs", None)
            d["techniques"] = sorted(set(techs_raw.split(","))) if techs_raw else []
            result.append(d)
        return jsonify(result)

    if ROLE_LEVELS[g.current_user["role"]] < ROLE_LEVELS["editor"]:
        return jsonify({"error": "Forbidden"}), 403

    payload = request.get_json(silent=True) or {}
    name = (payload.get("name") or "").strip()
    # tactic ve tech opsiyonel: Kurallar sayfasından tekniksiz kural oluşturulabilir,
    # teknikler sonradan rule_techniques üzerinden eklenir.
    tactic = (payload.get("tactic") or "none").strip() or "none"
    tech = (payload.get("tech") or "").strip()
    source = (payload.get("source") or "").strip()

    if not name or not source:
        return jsonify({"error": "Missing fields: name, source"}), 400

    try:
        cur = db.execute(
            "INSERT INTO rules (name, tactic, tech, source) VALUES (?, ?, ?, ?)",
            (name, tactic, tech or "none", source)
        )
    except sqlite3.IntegrityError:
        # idx_rules_name_source UNIQUE index ihlali → aynı (name, source) zaten var.
        return jsonify({"error": "Bu isim ve kaynak için kural zaten mevcut. Teknik eklemek için mevcut kuralı kullanın."}), 409
    if tech:
        db.execute("INSERT OR IGNORE INTO rule_techniques (rule_id, tech_id) VALUES (?, ?)",
                   (cur.lastrowid, tech))
    db.execute("INSERT OR IGNORE INTO detection_assessments (rule_id) VALUES (?)", (cur.lastrowid,))
    write_audit_log(
        db,
        action="create",
        target_type="rule",
        target_id=str(cur.lastrowid),
        detail=f"name={name};tech={tech or '-'};source={source}",
    )
    _invalidate_ttp_cache()
    db.commit()
    return jsonify({
        "id": cur.lastrowid, "name": name, "tactic": tactic, "tech": tech,
        "source": source, "techniques": [tech] if tech else [],
        "coverage_level": "full", "lifecycle_status": "active",
        "validation_status": "untested", "detection_score": 0,
        "applicable_scope": "Kurum geneli", "owner": "",
        "validation_method": "", "evidence_ref": "",
        "last_validated_at": None, "expires_at": None,
    }), 201




@app.route("/api/rules/bulk", methods=["POST"])
@role_required("editor")
def rules_bulk():
    db = get_db()
    file = request.files.get("file")
    if not file:
        return jsonify({"error": "Missing CSV file"}), 400

    import csv
    try:
        content = file.read().decode("utf-8")
    except Exception:
        return jsonify({"error": "CSV must be UTF-8 encoded"}), 400

    reader = csv.DictReader(content.splitlines())
    required = {"name", "tactic", "tech", "source"}
    if not reader.fieldnames:
        return jsonify({"error": "CSV header must include: name,tactic,tech,source"}), 400

    header_map = {h.strip().lower(): h for h in reader.fieldnames}
    if not required.issubset(set(header_map.keys())):
        return jsonify({"error": "CSV header must include: name,tactic,tech,source"}), 400

    products = {r["name"]: True for r in db.execute("SELECT name FROM products").fetchall()}

    inserted = 0
    errors = []
    for i, row in enumerate(reader, start=2):
        norm = {k.strip().lower(): (v or "") for k, v in row.items()}
        name = norm.get("name", "").strip()
        tactic = norm.get("tactic", "").strip()
        tech = norm.get("tech", "").strip()
        source = norm.get("source", "").strip()
        if not name or not tactic or not tech or not source:
            errors.append(f"Satir {i}: eksik alan")
            continue
        if source not in products:
            errors.append(f"Satir {i}: kaynak bulunamadi ({source})")
            continue
        row_id = db.execute(
            "INSERT INTO rules (name, tactic, tech, source) VALUES (?, ?, ?, ?)",
            (name, tactic, tech, source)
        ).lastrowid
        db.execute("INSERT OR IGNORE INTO rule_techniques (rule_id, tech_id) VALUES (?, ?)",
                   (row_id, tech))
        db.execute("INSERT OR IGNORE INTO detection_assessments (rule_id) VALUES (?)", (row_id,))
        inserted += 1
    write_audit_log(
        db,
        action="bulk_create",
        target_type="rule",
        detail=f"inserted={inserted};errors={len(errors)}",
    )
    _invalidate_ttp_cache()
    db.commit()
    return jsonify({"ok": True, "inserted": inserted, "errors": errors})


@app.route("/api/rules/<int:rule_id>/coverage", methods=["PATCH"])
@role_required("editor")
def update_rule_coverage(rule_id: int):
    payload = request.get_json(silent=True) or {}
    level = (payload.get("coverage_level") or "").strip()
    if level not in ("low", "partial", "full"):
        return jsonify({"error": "Geçersiz değer: low | partial | full"}), 400
    db = get_db()
    row = db.execute("SELECT id, coverage_level FROM rules WHERE id=?", (rule_id,)).fetchone()
    if not row:
        return jsonify({"error": "Rule not found"}), 404
    db.execute("UPDATE rules SET coverage_level=? WHERE id=?", (level, rule_id))
    write_audit_log(db, action="update", target_type="rule", target_id=str(rule_id),
                    detail=f"coverage_level={level}",
                    before={"coverage_level": row["coverage_level"]},
                    after={"coverage_level": level})
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/rules/<int:rule_id>", methods=["DELETE"])
@role_required("editor")
def delete_rule(rule_id: int):
    db = get_db()
    row = db.execute(
        "SELECT id, name, tactic, tech, source, coverage_level FROM rules WHERE id=?",
        (rule_id,),
    ).fetchone()
    if not row:
        return jsonify({"error": "Rule not found"}), 404
    techniques = [
        r["tech_id"] for r in db.execute(
            "SELECT tech_id FROM rule_techniques WHERE rule_id=? ORDER BY tech_id", (rule_id,)
        ).fetchall()
    ]
    db.execute("DELETE FROM rule_techniques WHERE rule_id = ?", (rule_id,))
    db.execute("DELETE FROM detection_assessments WHERE rule_id = ?", (rule_id,))
    db.execute("DELETE FROM rules WHERE id = ?", (rule_id,))
    before = dict(row)
    before["techniques"] = techniques
    write_audit_log(
        db, action="delete", target_type="rule", target_id=str(rule_id), before=before
    )
    _invalidate_ttp_cache()
    db.commit()
    return jsonify({"ok": True})




# ── Kural Teknik Yönetimi ─────────────────────────────────────────────────────
# Bir kurala yeni MITRE tekniği ekler veya mevcut tekniği kaldırır.
# Frontend: Kurallar sayfasında her kural satırındaki + input + × buton.
@app.route("/api/rules/<int:rule_id>/techniques", methods=["POST"])
@role_required("editor")
def add_rule_technique(rule_id: int):
    payload = request.get_json(silent=True) or {}
    tech_id = (payload.get("tech_id") or "").strip().upper()
    if not tech_id:
        return jsonify({"error": "tech_id gerekli"}), 400
    db = get_db()
    db.execute("INSERT OR IGNORE INTO rule_techniques (rule_id, tech_id) VALUES (?, ?)",
               (rule_id, tech_id))
    write_audit_log(db, action="create", target_type="rule_technique",
                    target_id=str(rule_id), detail=f"tech_id={tech_id}")
    _invalidate_ttp_cache()
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/rules/<int:rule_id>/techniques/<tech_id>", methods=["DELETE"])
@role_required("editor")
def delete_rule_technique(rule_id: int, tech_id: str):
    db = get_db()
    db.execute("DELETE FROM rule_techniques WHERE rule_id = ? AND tech_id = ?",
               (rule_id, tech_id.upper()))
    write_audit_log(db, action="delete", target_type="rule_technique",
                    target_id=str(rule_id), detail=f"tech_id={tech_id}")
    _invalidate_ttp_cache()
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/products", methods=["GET", "POST"])
@role_required("viewer")
def products():
    db = get_db()
    if request.method == "GET":
        rows = db.execute("SELECT id, name, color FROM products ORDER BY name ASC").fetchall()
        return jsonify([dict(r) for r in rows])

    if ROLE_LEVELS[g.current_user["role"]] < ROLE_LEVELS["admin"]:
        return jsonify({"error": "Forbidden"}), 403

    payload = request.get_json(silent=True) or {}
    name = (payload.get("name") or "").strip()
    color = (payload.get("color") or "").strip()
    if not name or not color:
        return jsonify({"error": "Missing fields: name, color"}), 400
    try:
        cur = db.execute("INSERT INTO products (name, color) VALUES (?, ?)", (name, color))
        write_audit_log(
            db,
            action="create",
            target_type="product",
            target_id=str(cur.lastrowid),
            detail=f"name={name};color={color}",
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "Product already exists"}), 400
    return jsonify({"id": cur.lastrowid, "name": name, "color": color}), 201


@app.route("/api/products/<int:product_id>", methods=["DELETE"])
@role_required("admin")
def delete_product(product_id: int):
    db = get_db()
    row = db.execute("SELECT id, name, color FROM products WHERE id=?", (product_id,)).fetchone()
    if not row:
        return jsonify({"error": "Product not found"}), 404
    usage_count = db.execute(
        "SELECT COUNT(*) FROM rules WHERE source=?", (row["name"],)
    ).fetchone()[0]
    if usage_count:
        return jsonify({
            "error": "Ürün tespitler tarafından kullanılıyor.",
            "rule_count": usage_count,
        }), 409
    db.execute("DELETE FROM products WHERE id = ?", (product_id,))
    write_audit_log(
        db, action="delete", target_type="product", target_id=str(product_id), before=dict(row)
    )
    db.commit()
    return jsonify({"ok": True})




@app.route("/api/products/<int:product_id>", methods=["PUT"])
@role_required("admin")
def update_product(product_id: int):
    db = get_db()
    payload = request.get_json(silent=True) or {}
    color = (payload.get("color") or "").strip()
    if not color:
        return jsonify({"error": "Missing fields: color"}), 400
    row = db.execute("SELECT id, name, color FROM products WHERE id=?", (product_id,)).fetchone()
    if not row:
        return jsonify({"error": "Product not found"}), 404
    db.execute("UPDATE products SET color = ? WHERE id = ?", (color, product_id))
    write_audit_log(
        db,
        action="update",
        target_type="product",
        target_id=str(product_id),
        detail=f"color={color}", before=dict(row),
        after={"id": product_id, "name": row["name"], "color": color},
    )
    db.commit()
    return jsonify({"ok": True})

@app.route("/api/teams", methods=["GET", "POST"])
@role_required("viewer")
def teams_api():
    db = get_db()
    if request.method == "GET":
        rows = db.execute(
            "SELECT id, name, created_at FROM teams ORDER BY name ASC"
        ).fetchall()
        return jsonify([dict(r) for r in rows])

    if ROLE_LEVELS[g.current_user["role"]] < ROLE_LEVELS["admin"]:
        return jsonify({"error": "Forbidden"}), 403

    payload = request.get_json(silent=True) or {}
    name = (payload.get("name") or "").strip()
    if not name:
        return jsonify({"error": "Missing fields: name"}), 400
    try:
        cur = db.execute("INSERT INTO teams (name) VALUES (?)", (name,))
        write_audit_log(
            db,
            action="create",
            target_type="team",
            target_id=str(cur.lastrowid),
            detail=f"name={name}",
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "Team already exists"}), 400
    return jsonify({"id": cur.lastrowid, "name": name}), 201


@app.route("/api/teams/<int:team_id>", methods=["DELETE"])
@role_required("admin")
def delete_team(team_id: int):
    db = get_db()
    row = db.execute("SELECT id, name, created_at FROM teams WHERE id=?", (team_id,)).fetchone()
    if not row:
        return jsonify({"error": "Team not found"}), 404
    usage_count = db.execute(
        "SELECT COUNT(*) FROM action_items WHERE assigned_team_id=?", (team_id,)
    ).fetchone()[0]
    if usage_count:
        return jsonify({
            "error": "Ekip aksiyon planında kullanılıyor.",
            "action_item_count": usage_count,
        }), 409
    db.execute("DELETE FROM teams WHERE id = ?", (team_id,))
    write_audit_log(
        db, action="delete", target_type="team", target_id=str(team_id), before=dict(row)
    )
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/mitigation-notes", methods=["GET", "POST"])
@role_required("viewer")
def mitigation_notes():
    db = get_db()
    if request.method == "GET":
        ensure_mitigation_global_table(db)
        ensure_mitigation_global_seed(db)
        # Auto-compute checked: any mitigation_id with entries in mitigation_entries is checked
        auto_checked_ids = set(
            r["mitigation_id"]
            for r in db.execute(
                "SELECT DISTINCT mitigation_id FROM mitigation_entries"
            ).fetchall()
        )
        rows = db.execute(
            "SELECT mitigation_id, checked, comment, team FROM mitigation_global"
        ).fetchall()
        result = []
        seen: set[str] = set()
        for r in rows:
            mid = r["mitigation_id"]
            seen.add(mid)
            result.append(
                {
                    "mitigation_id": mid,
                    "checked": bool(r["checked"]) or (mid in auto_checked_ids),
                    "comment": r["comment"],
                    "team": r["team"],
                }
            )
        # Also surface mitigation_ids that have entries but no global row
        for mid in auto_checked_ids:
            if mid not in seen:
                result.append(
                    {"mitigation_id": mid, "checked": True, "comment": "", "team": ""}
                )
        return jsonify(result)

    if ROLE_LEVELS[g.current_user["role"]] < ROLE_LEVELS["editor"]:
        return jsonify({"error": "Forbidden"}), 403

    payload = request.get_json(silent=True) or {}
    mitigation_id = (payload.get("mitigation_id") or "").strip()
    checked = 1 if payload.get("checked") else 0
    comment = (payload.get("comment") or "").strip()
    team = (payload.get("team") or "").strip()

    if not mitigation_id:
        return jsonify({"error": "Missing fields: mitigation_id"}), 400

    ensure_mitigation_global_table(db)
    previous = db.execute(
        "SELECT mitigation_id, checked, comment, team FROM mitigation_global WHERE mitigation_id=?",
        (mitigation_id,),
    ).fetchone()
    db.execute(
        """
        INSERT INTO mitigation_global (mitigation_id, checked, comment, team)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(mitigation_id)
        DO UPDATE SET checked=excluded.checked, comment=excluded.comment, team=excluded.team
        """,
        (mitigation_id, checked, comment, team),
    )
    write_audit_log(
        db,
        action="upsert",
        target_type="mitigation_note",
        target_id=mitigation_id,
        detail=f"checked={checked};team={team}",
        before=dict(previous) if previous else None,
        after={
            "mitigation_id": mitigation_id, "checked": checked,
            "comment": comment, "team": team,
        },
    )
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/mitigation-entries", methods=["GET", "POST"])
@role_required("viewer")
def mitigation_entries():
    db = get_db()
    if request.method == "GET":
        rows = db.execute(
            "SELECT id, mitigation_id, team, comment FROM mitigation_entries ORDER BY id ASC"
        ).fetchall()
        result = []
        for r in rows:
            result.append(
                {
                    "id": r["id"],
                    "mitigation_id": r["mitigation_id"],
                    "team": r["team"],
                    "comment": r["comment"],
                }
            )
        return jsonify(result)

    if ROLE_LEVELS[g.current_user["role"]] < ROLE_LEVELS["editor"]:
        return jsonify({"error": "Forbidden"}), 403

    payload = request.get_json(silent=True) or {}
    mitigation_id = (payload.get("mitigation_id") or "").strip()
    team = (payload.get("team") or "").strip()
    comment = (payload.get("comment") or "").strip()
    if not mitigation_id or not team or not comment:
        return jsonify({"error": "Missing fields: mitigation_id, team, comment"}), 400

    cur = db.execute(
        "INSERT INTO mitigation_entries (mitigation_id, team, comment) VALUES (?, ?, ?)",
        (mitigation_id, team, comment),
    )
    write_audit_log(
        db,
        action="create",
        target_type="mitigation_entry",
        target_id=str(cur.lastrowid),
        detail=f"mitigation_id={mitigation_id};team={team}",
        after={
            "mitigation_id": mitigation_id, "team": team, "comment": comment,
        },
    )
    _invalidate_ttp_cache()
    db.commit()
    return jsonify({"id": cur.lastrowid, "mitigation_id": mitigation_id, "team": team, "comment": comment}), 201


@app.route("/api/mitigation-entries/<int:entry_id>", methods=["DELETE"])
@role_required("editor")
def delete_mitigation_entry(entry_id: int):
    db = get_db()
    row = db.execute(
        "SELECT id, mitigation_id, team, comment FROM mitigation_entries WHERE id=?",
        (entry_id,),
    ).fetchone()
    if not row:
        return jsonify({"error": "Mitigation entry not found"}), 404
    db.execute("DELETE FROM mitigation_entries WHERE id = ?", (entry_id,))
    write_audit_log(
        db,
        action="delete",
        target_type="mitigation_entry",
        target_id=str(entry_id),
        before=dict(row),
    )
    _invalidate_ttp_cache()
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/users", methods=["GET", "POST"])
@role_required("admin")
def users_api():
    db = get_db()
    if request.method == "GET":
        rows = db.execute(
            "SELECT id, username, role, is_active FROM users ORDER BY username ASC"
        ).fetchall()
        return jsonify([dict(r) for r in rows])

    payload = request.get_json(silent=True) or {}
    username = (payload.get("username") or "").strip()
    password = (payload.get("password") or "").strip()
    role = (payload.get("role") or "").strip()
    if not username or not password or role not in ROLE_LEVELS:
        return jsonify({"error": "Missing/invalid fields: username, password, role"}), 400
    if len(password) < 10:
        return jsonify({"error": "Password must be at least 10 characters"}), 400

    try:
        cur = db.execute(
            "INSERT INTO users (username, password_hash, role, is_active) VALUES (?, ?, ?, 1)",
            (username, generate_password_hash(password), role),
        )
        write_audit_log(
            db,
            action="create",
            target_type="user",
            target_id=str(cur.lastrowid),
            detail=f"username={username};role={role}",
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username already exists"}), 400

    return jsonify({"id": cur.lastrowid, "username": username, "role": role, "is_active": 1}), 201


@app.route("/api/users/<int:user_id>", methods=["PUT"])
@role_required("admin")
def users_update_api(user_id: int):
    db = get_db()
    row = db.execute("SELECT id, username, role, is_active FROM users WHERE id = ?", (user_id,)).fetchone()
    if not row:
        return jsonify({"error": "User not found"}), 404

    payload = request.get_json(silent=True) or {}
    next_role = (payload.get("role") or row["role"]).strip()
    is_active = payload.get("is_active")
    new_password = (payload.get("password") or "").strip()

    if next_role not in ROLE_LEVELS:
        return jsonify({"error": "Invalid role"}), 400
    if is_active is None:
        is_active = row["is_active"]
    is_active = 1 if bool(is_active) else 0

    if user_id == g.current_user["id"] and is_active == 0:
        return jsonify({"error": "You cannot deactivate your own account"}), 400
    if new_password and len(new_password) < 10:
        return jsonify({"error": "Password must be at least 10 characters"}), 400
    if row["role"] == "admin" and row["is_active"] and (next_role != "admin" or not is_active):
        active_admins = db.execute(
            "SELECT COUNT(*) FROM users WHERE role='admin' AND is_active=1"
        ).fetchone()[0]
        if active_admins <= 1:
            return jsonify({"error": "The last active admin cannot be demoted or deactivated"}), 409

    db.execute(
        "UPDATE users SET role = ?, is_active = ? WHERE id = ?",
        (next_role, is_active, user_id),
    )
    if new_password:
        db.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (generate_password_hash(new_password), user_id),
        )
    write_audit_log(
        db,
        action="update",
        target_type="user",
        target_id=str(user_id),
        detail=f"role={next_role};is_active={is_active};password_changed={bool(new_password)}",
        before=dict(row),
        after={
            "id": user_id, "username": row["username"], "role": next_role,
            "is_active": is_active, "password_changed": bool(new_password),
        },
    )
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/audit-logs", methods=["GET"])
@role_required("admin")
def audit_logs_api():
    db = get_db()
    page_raw = request.args.get("page", "1")
    per_page_raw = request.args.get("per_page", request.args.get("limit", "50"))
    try:
        page = max(1, int(page_raw))
        per_page = max(10, min(200, int(per_page_raw)))
    except ValueError:
        page, per_page = 1, 50

    where, params = _audit_filters(request.args)
    total = db.execute(f"SELECT COUNT(*) FROM audit_logs {where}", params).fetchone()[0]
    rows = db.execute(
        f"""
        SELECT id, user_id, username, action, target_type, target_id, detail,
               request_id, ip_address, user_agent, before_json, after_json,
               prev_hash, entry_hash, created_at
        FROM audit_logs {where}
        ORDER BY id DESC
        LIMIT ? OFFSET ?
        """,
        [*params, per_page, (page - 1) * per_page],
    ).fetchall()
    action_rows = db.execute(
        "SELECT action, COUNT(*) AS count FROM audit_logs GROUP BY action ORDER BY count DESC"
    ).fetchall()
    target_rows = db.execute(
        "SELECT target_type, COUNT(*) AS count FROM audit_logs GROUP BY target_type ORDER BY count DESC"
    ).fetchall()
    return jsonify({
        "items": [dict(r) for r in rows],
        "pagination": {
            "page": page,
            "per_page": per_page,
            "total": total,
            "pages": max(1, (total + per_page - 1) // per_page),
        },
        "facets": {
            "actions": [dict(r) for r in action_rows],
            "target_types": [dict(r) for r in target_rows],
        },
        "integrity": verify_audit_chain(db),
    })


def _audit_filters(args: Any) -> tuple[str, list[Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    filters = {
        "username": "username = ?",
        "action": "action = ?",
        "target_type": "target_type = ?",
    }
    for key, clause in filters.items():
        value = (args.get(key) or "").strip()
        if value:
            clauses.append(clause)
            params.append(value)
    query = (args.get("q") or "").strip()
    if query:
        like = f"%{query}%"
        clauses.append("(target_id LIKE ? OR detail LIKE ? OR request_id LIKE ?)")
        params.extend([like, like, like])
    date_from = (args.get("date_from") or "").strip()
    date_to = (args.get("date_to") or "").strip()
    if date_from:
        clauses.append("created_at >= ?")
        params.append(date_from)
    if date_to:
        clauses.append("created_at <= ?")
        params.append(f"{date_to}T23:59:59Z" if len(date_to) == 10 else date_to)
    return ("WHERE " + " AND ".join(clauses) if clauses else ""), params


@app.route("/api/audit-logs/export", methods=["GET"])
@role_required("admin")
def audit_logs_export_api():
    db = get_db()
    where, params = _audit_filters(request.args)
    rows = db.execute(
        f"""
        SELECT id, created_at, username, action, target_type, target_id, detail,
               request_id, ip_address, user_agent, before_json, after_json,
               prev_hash, entry_hash
        FROM audit_logs {where} ORDER BY id DESC LIMIT 10000
        """,
        params,
    ).fetchall()
    stream = io.StringIO()
    writer = csv.writer(stream)
    headers = [
        "id", "created_at", "username", "action", "target_type", "target_id",
        "detail", "request_id", "ip_address", "user_agent", "before_json",
        "after_json", "prev_hash", "entry_hash",
    ]
    writer.writerow(headers)
    writer.writerows([[row[h] for h in headers] for row in rows])
    filename = f"audit-export-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.csv"
    return Response(
        "\ufeff" + stream.getvalue(),
        content_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.route("/api/audit-logs/evidence", methods=["POST"])
@role_required("admin")
def audit_evidence_export_api():
    """Create a self-verifiable audit evidence package for external review."""
    db = get_db()
    supplied = request.get_json(silent=True) or {}
    allowed_filters = {
        key: str(supplied.get(key, "")).strip()
        for key in ("q", "username", "action", "target_type", "date_from", "date_to")
        if str(supplied.get(key, "")).strip()
    }
    write_audit_log(
        db,
        action="export",
        target_type="audit_evidence",
        detail=f"filters={_json_text(allowed_filters)}",
        after={"format": "audit-evidence-1.0", "filters": allowed_filters},
    )
    db.commit()

    where, params = _audit_filters(allowed_filters)
    total = db.execute(f"SELECT COUNT(*) FROM audit_logs {where}", params).fetchone()[0]
    rows = db.execute(
        f"""
        SELECT id, user_id, username, action, target_type, target_id, detail,
               request_id, ip_address, user_agent, before_json, after_json,
               prev_hash, entry_hash, created_at
        FROM audit_logs {where} ORDER BY id ASC LIMIT 10000
        """,
        params,
    ).fetchall()
    generated_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    integrity = verify_audit_chain(db)
    manifest = {
        "schema_version": "audit-evidence-1.0",
        "generated_at": generated_at,
        "generated_by": g.current_user["username"],
        "filters": allowed_filters,
        "record_count": len(rows),
        "source_record_count": total,
        "truncated": total > len(rows),
        "hash_algorithm": "SHA-256",
        "audit_chain": integrity,
    }
    package_core = {"manifest": manifest, "records": [dict(row) for row in rows]}
    canonical = json.dumps(package_core, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    package = {**package_core, "export_hash": hashlib.sha256(canonical.encode("utf-8")).hexdigest()}
    body = json.dumps(package, ensure_ascii=False, indent=2)
    filename = f"audit-evidence-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.json"
    return Response(
        body,
        content_type="application/json; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


QRADAR_DEFAULT_MAPPINGS_PATH = "/console/plugins/app_proxy:UseCaseManager_Service/api/mappings"


def _connector_payload(payload: dict[str, Any], existing: sqlite3.Row | None = None) -> dict[str, Any]:
    current = dict(existing) if existing else {}
    data = {
        "kind": "qradar",
        "name": str(payload.get("name", current.get("name", ""))).strip(),
        "base_url": str(payload.get("base_url", current.get("base_url", ""))).strip().rstrip("/"),
        "secret_env": str(payload.get("secret_env", current.get("secret_env", "QRADAR_SEC_TOKEN"))).strip(),
        "product_name": str(payload.get("product_name", current.get("product_name", "QRadar"))).strip(),
        "mappings_path": str(payload.get("mappings_path", current.get("mappings_path", QRADAR_DEFAULT_MAPPINGS_PATH))).strip(),
        "verify_tls": int(bool(payload.get("verify_tls", current.get("verify_tls", 1)))),
        "ca_bundle": str(payload.get("ca_bundle", current.get("ca_bundle", ""))).strip(),
        "enabled": int(bool(payload.get("enabled", current.get("enabled", 1)))),
        "import_new_rules": int(bool(payload.get("import_new_rules", current.get("import_new_rules", 1)))),
    }
    parsed = urlparse(data["base_url"])
    allow_http = app.config.get("TESTING") and parsed.hostname in {"127.0.0.1", "localhost", "::1"}
    if not data["name"] or not parsed.hostname or (parsed.scheme != "https" and not allow_http):
        raise ValueError("QRadar adı ve geçerli bir HTTPS base URL gereklidir")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Base URL kullanıcı bilgisi, query veya fragment içeremez")
    if not re.fullmatch(r"[A-Z][A-Z0-9_]{2,63}", data["secret_env"]):
        raise ValueError("Token ortam değişkeni yalnızca A-Z, 0-9 ve alt çizgi içermelidir")
    if not data["product_name"] or not data["mappings_path"].startswith("/"):
        raise ValueError("Ürün adı ve / ile başlayan mappings path gereklidir")
    if data["ca_bundle"] and not Path(data["ca_bundle"]).is_file():
        raise ValueError("CA bundle dosyası bulunamadı")
    return data


def _connector_view(db: sqlite3.Connection, row: sqlite3.Row) -> dict[str, Any]:
    item = dict(row)
    item["token_configured"] = bool(os.environ.get(row["secret_env"], "").strip())
    item["inventory"] = dict(db.execute(
        """
        SELECT COUNT(*) AS total,
               SUM(CASE WHEN stale=0 AND enabled=1 THEN 1 ELSE 0 END) AS active,
               SUM(CASE WHEN stale=1 THEN 1 ELSE 0 END) AS stale,
               SUM(CASE WHEN origin='custom' THEN 1 ELSE 0 END) AS custom,
               SUM(CASE WHEN origin='vendor_builtin' THEN 1 ELSE 0 END) AS built_in
        FROM external_detections WHERE connector_id=?
        """,
        (row["id"],),
    ).fetchone())
    item["linked_rules"] = db.execute(
        "SELECT COUNT(*) FROM rule_external_refs WHERE connector_id=?", (row["id"],)
    ).fetchone()[0]
    item["recent_runs"] = [dict(run) for run in db.execute(
        "SELECT * FROM connector_sync_runs WHERE connector_id=? ORDER BY id DESC LIMIT 10",
        (row["id"],),
    ).fetchall()]
    return item


def _qradar_client(connector: sqlite3.Row) -> QRadarClient:
    token = os.environ.get(connector["secret_env"], "").strip()
    if not token:
        raise QRadarConnectorError(f"Token ortam değişkeni tanımlı değil: {connector['secret_env']}")
    return QRadarClient(
        connector["base_url"],
        token,
        connector["mappings_path"],
        verify_tls=bool(connector["verify_tls"]),
        ca_bundle=connector["ca_bundle"],
    )


def _run_qradar_sync(db: sqlite3.Connection, connector: sqlite3.Row) -> dict[str, Any]:
    running = db.execute(
        "SELECT id,started_at FROM connector_sync_runs WHERE connector_id=? AND status='running' ORDER BY id DESC LIMIT 1",
        (connector["id"],),
    ).fetchone()
    if running:
        try:
            running_since = datetime.fromisoformat(running["started_at"].replace("Z", "+00:00"))
        except ValueError:
            running_since = datetime.now(timezone.utc)
        if datetime.now(timezone.utc) - running_since < timedelta(minutes=15):
            raise QRadarConnectorError("Bu connector için başka bir senkronizasyon çalışıyor")
        db.execute(
            "UPDATE connector_sync_runs SET status='failed',finished_at=?,error='Senkronizasyon zaman aşımına uğradı' WHERE id=?",
            (datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"), running["id"]),
        )
        db.commit()
    started_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    cursor = db.execute(
        "INSERT INTO connector_sync_runs (connector_id,status,triggered_by,started_at) VALUES (?, 'running', ?, ?)",
        (connector["id"], g.current_user["username"], started_at),
    )
    run_id = cursor.lastrowid
    db.commit()
    try:
        detections = _qradar_client(connector).fetch_detections()
        if not detections:
            raise QRadarConnectorError("QRadar mapping yanıtında kullanılabilir kural bulunamadı")
        now = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        stats = {
            "received": len(detections), "created": 0, "updated": 0, "unchanged": 0,
            "linked_existing": 0, "rules_created": 0, "stale": 0,
            "mapping_count": sum(len(item["techniques"]) for item in detections),
        }
        db.execute("INSERT OR IGNORE INTO products (name,color) VALUES (?, '#2e7d32')", (connector["product_name"],))
        seen: set[str] = set()
        catalog = _attack_catalog()["techniques"]
        for detection in detections:
            native_id = detection["native_id"]
            seen.add(native_id)
            previous = db.execute(
                "SELECT payload_hash FROM external_detections WHERE connector_id=? AND native_id=?",
                (connector["id"], native_id),
            ).fetchone()
            if previous is None:
                stats["created"] += 1
            elif previous["payload_hash"] != detection["payload_hash"]:
                stats["updated"] += 1
            else:
                stats["unchanged"] += 1
            db.execute(
                """
                INSERT INTO external_detections (
                    connector_id,native_id,name,origin,enabled,rule_type,severity,
                    offense_count,last_offense_at,payload_hash,first_seen_at,last_seen_at
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(connector_id,native_id) DO UPDATE SET
                    name=excluded.name, origin=excluded.origin, enabled=excluded.enabled,
                    rule_type=excluded.rule_type, severity=excluded.severity,
                    offense_count=excluded.offense_count, last_offense_at=excluded.last_offense_at,
                    payload_hash=excluded.payload_hash, last_seen_at=excluded.last_seen_at,
                    missing_sync_count=0, stale=0
                """,
                (
                    connector["id"], native_id, detection["name"], detection["origin"],
                    int(detection["enabled"]), detection["rule_type"], detection["severity"],
                    detection["offense_count"], detection["last_offense_at"], detection["payload_hash"], now, now,
                ),
            )
            db.execute(
                "DELETE FROM external_detection_techniques WHERE connector_id=? AND native_id=?",
                (connector["id"], native_id),
            )
            db.executemany(
                "INSERT INTO external_detection_techniques (connector_id,native_id,tech_id) VALUES (?,?,?)",
                [(connector["id"], native_id, tech_id) for tech_id in detection["techniques"]],
            )
            linked = db.execute(
                "SELECT rule_id FROM rule_external_refs WHERE connector_id=? AND native_id=?",
                (connector["id"], native_id),
            ).fetchone()
            if linked:
                continue
            candidates = db.execute(
                "SELECT id FROM rules WHERE source=? AND lower(trim(name))=lower(trim(?)) ORDER BY id",
                (connector["product_name"], detection["name"]),
            ).fetchall()
            if len(candidates) == 1:
                rule_id = candidates[0]["id"]
                match_method = "exact_name"
                stats["linked_existing"] += 1
            elif connector["import_new_rules"]:
                first_tech = detection["techniques"][0] if detection["techniques"] else "none"
                technique = catalog.get(first_tech, {})
                tactics = technique.get("tactics", []) if isinstance(technique, dict) else []
                tactic = tactics[0] if tactics else "none"
                rule_id = db.execute(
                    "INSERT INTO rules (name,tactic,tech,source,coverage_level) VALUES (?,?,?,?,?)",
                    (detection["name"], tactic, first_tech, connector["product_name"], "low"),
                ).lastrowid
                db.execute("INSERT INTO detection_assessments (rule_id) VALUES (?)", (rule_id,))
                db.executemany(
                    "INSERT OR IGNORE INTO rule_techniques (rule_id,tech_id) VALUES (?,?)",
                    [(rule_id, tech_id) for tech_id in detection["techniques"]],
                )
                match_method = "connector_created"
                stats["rules_created"] += 1
            else:
                continue
            db.execute(
                "INSERT INTO rule_external_refs (rule_id,connector_id,native_id,match_method,linked_at) VALUES (?,?,?,?,?)",
                (rule_id, connector["id"], native_id, match_method, now),
            )

        existing_ids = [row["native_id"] for row in db.execute(
            "SELECT native_id FROM external_detections WHERE connector_id=?", (connector["id"],)
        ).fetchall()]
        for native_id in existing_ids:
            if native_id not in seen:
                db.execute(
                    """
                    UPDATE external_detections SET missing_sync_count=missing_sync_count+1,
                        stale=CASE WHEN missing_sync_count+1>=3 THEN 1 ELSE stale END
                    WHERE connector_id=? AND native_id=?
                    """,
                    (connector["id"], native_id),
                )
        stats["stale"] = db.execute(
            "SELECT COUNT(*) FROM external_detections WHERE connector_id=? AND stale=1", (connector["id"],)
        ).fetchone()[0]
        payload_hash = hashlib.sha256("".join(item["payload_hash"] for item in detections).encode("ascii")).hexdigest()
        finished_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        db.execute(
            """
            UPDATE connector_sync_runs SET status='success',finished_at=?,received=?,created=?,updated=?,
                unchanged=?,linked_existing=?,rules_created=?,stale=?,mapping_count=?,payload_hash=? WHERE id=?
            """,
            (
                finished_at, stats["received"], stats["created"], stats["updated"], stats["unchanged"],
                stats["linked_existing"], stats["rules_created"], stats["stale"], stats["mapping_count"], payload_hash, run_id,
            ),
        )
        db.execute(
            "UPDATE connectors SET last_status='success',last_sync_at=?,last_error='',updated_at=CURRENT_TIMESTAMP WHERE id=?",
            (finished_at, connector["id"]),
        )
        write_audit_log(db, "sync", "connector", str(connector["id"]), f"qradar;received={stats['received']};created={stats['created']};updated={stats['updated']};rules_created={stats['rules_created']}", after={**stats, "payload_hash": payload_hash})
        _invalidate_ttp_cache()
        db.commit()
        return {"run_id": run_id, "status": "success", **stats, "payload_hash": payload_hash}
    except Exception as exc:
        error = str(exc)[:1000]
        finished_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        db.rollback()
        db.execute(
            "UPDATE connector_sync_runs SET status='failed',finished_at=?,error=? WHERE id=?",
            (finished_at, error, run_id),
        )
        db.execute(
            "UPDATE connectors SET last_status='failed',last_error=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",
            (error, connector["id"]),
        )
        write_audit_log(db, "sync_failed", "connector", str(connector["id"]), error)
        db.commit()
        raise QRadarConnectorError(error) from exc


@app.route("/api/connectors", methods=["GET", "POST"])
@role_required("admin")
def connectors_api():
    db = get_db()
    if request.method == "GET":
        return jsonify([_connector_view(db, row) for row in db.execute("SELECT * FROM connectors ORDER BY name").fetchall()])
    try:
        data = _connector_payload(request.get_json(silent=True) or {})
        columns = list(data)
        cursor = db.execute(
            f"INSERT INTO connectors ({','.join(columns)}) VALUES ({','.join('?' for _ in columns)})",
            [data[column] for column in columns],
        )
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except sqlite3.IntegrityError:
        return jsonify({"error": "Bu connector adı zaten kullanılıyor"}), 409
    write_audit_log(db, "create", "connector", str(cursor.lastrowid), "kind=qradar", after=data)
    db.commit()
    return jsonify({"id": cursor.lastrowid}), 201


@app.route("/api/connectors/<int:connector_id>", methods=["PUT"])
@role_required("admin")
def connector_api(connector_id: int):
    db = get_db()
    existing = db.execute("SELECT * FROM connectors WHERE id=?", (connector_id,)).fetchone()
    if not existing:
        return jsonify({"error": "Connector bulunamadı"}), 404
    try:
        data = _connector_payload(request.get_json(silent=True) or {}, existing)
        assignments = ",".join(f"{column}=?" for column in data)
        db.execute(
            f"UPDATE connectors SET {assignments},updated_at=CURRENT_TIMESTAMP WHERE id=?",
            [data[column] for column in data] + [connector_id],
        )
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except sqlite3.IntegrityError:
        return jsonify({"error": "Bu connector adı zaten kullanılıyor"}), 409
    write_audit_log(db, "update", "connector", str(connector_id), before=dict(existing), after=data)
    db.commit()
    return jsonify(_connector_view(db, db.execute("SELECT * FROM connectors WHERE id=?", (connector_id,)).fetchone()))


@app.route("/api/connectors/<int:connector_id>/test", methods=["POST"])
@role_required("admin")
def connector_test_api(connector_id: int):
    db = get_db()
    connector = db.execute("SELECT * FROM connectors WHERE id=?", (connector_id,)).fetchone()
    if not connector:
        return jsonify({"error": "Connector bulunamadı"}), 404
    try:
        result = _qradar_client(connector).test()
    except QRadarConnectorError as exc:
        write_audit_log(db, "test_failed", "connector", str(connector_id), str(exc))
        db.commit()
        return jsonify({"error": str(exc)}), 502
    write_audit_log(db, "test", "connector", str(connector_id), f"mapping_records={result['mapping_records']}")
    db.commit()
    return jsonify(result)


@app.route("/api/connectors/<int:connector_id>/sync", methods=["POST"])
@role_required("admin")
def connector_sync_api(connector_id: int):
    db = get_db()
    connector = db.execute("SELECT * FROM connectors WHERE id=?", (connector_id,)).fetchone()
    if not connector:
        return jsonify({"error": "Connector bulunamadı"}), 404
    if not connector["enabled"]:
        return jsonify({"error": "Connector devre dışı"}), 409
    try:
        return jsonify(_run_qradar_sync(db, connector))
    except QRadarConnectorError as exc:
        return jsonify({"error": str(exc)}), 502


ENV_CODE_RE = re.compile(r"[A-Z0-9][A-Z0-9_-]{1,31}")
SCOPE_PLATFORMS = {"Windows", "Linux", "macOS", "Network", "Cloud", "Identity", "SaaS", "Container", "Other"}
SCOPE_ASSET_TYPES = {"Client", "Server", "Network Device", "Identity", "Cloud Workload", "Container", "Application", "Other"}
MONITORING_STATUSES = {"unknown", "none", "partial", "full"}
MONITORING_MODES = {"agent", "log_forwarding", "api", "network", "hybrid", "other"}


def _environment_payload(payload: dict[str, Any], current: sqlite3.Row | None = None) -> dict[str, Any]:
    old = dict(current) if current else {}
    data = {
        "name": str(payload.get("name", old.get("name", ""))).strip(),
        "code": str(payload.get("code", old.get("code", ""))).strip().upper(),
        "description": str(payload.get("description", old.get("description", ""))).strip(),
        "criticality": int(payload.get("criticality", old.get("criticality", 3))),
        "owner": str(payload.get("owner", old.get("owner", ""))).strip(),
        "active": int(bool(payload.get("active", old.get("active", 1)))),
    }
    if not data["name"] or not ENV_CODE_RE.fullmatch(data["code"]):
        raise ValueError("Ortam adı ve 2-32 karakterlik kod gereklidir")
    if not 1 <= data["criticality"] <= 5:
        raise ValueError("Kritiklik 1-5 arasında olmalıdır")
    return data


def _asset_group_payload(payload: dict[str, Any], current: sqlite3.Row | None = None) -> dict[str, Any]:
    old = dict(current) if current else {}
    data = {
        "name": str(payload.get("name", old.get("name", ""))).strip(),
        "platform": str(payload.get("platform", old.get("platform", "Other"))).strip(),
        "asset_type": str(payload.get("asset_type", old.get("asset_type", "Other"))).strip(),
        "asset_count": int(payload.get("asset_count", old.get("asset_count", 0))),
        "criticality": int(payload.get("criticality", old.get("criticality", 3))),
        "owner": str(payload.get("owner", old.get("owner", ""))).strip(),
        "active": int(bool(payload.get("active", old.get("active", 1)))),
    }
    if not data["name"] or data["platform"] not in SCOPE_PLATFORMS or data["asset_type"] not in SCOPE_ASSET_TYPES:
        raise ValueError("Geçerli grup adı, platform ve varlık tipi gereklidir")
    if data["asset_count"] < 0 or not 1 <= data["criticality"] <= 5:
        raise ValueError("Varlık sayısı negatif olamaz; kritiklik 1-5 arasında olmalıdır")
    return data


@app.route("/api/scope-registry", methods=["GET"])
@role_required("viewer")
def scope_registry_api():
    db = get_db()
    environments = []
    for environment in db.execute("SELECT * FROM environments ORDER BY active DESC,name").fetchall():
        env = dict(environment)
        env["groups"] = []
        for group in db.execute(
            "SELECT * FROM asset_groups WHERE environment_id=? ORDER BY active DESC,name", (environment["id"],)
        ).fetchall():
            item = dict(group)
            item["deployments"] = [dict(row) for row in db.execute(
                """
                SELECT pd.*,p.name AS product_name,p.color AS product_color,c.name AS connector_name,
                       (SELECT COUNT(*) FROM rule_external_refs rer WHERE rer.connector_id=pd.connector_id) AS connector_detection_count
                FROM product_deployments pd JOIN products p ON p.id=pd.product_id
                LEFT JOIN connectors c ON c.id=pd.connector_id
                WHERE pd.asset_group_id=? ORDER BY p.name
                """,
                (group["id"],),
            ).fetchall()]
            env["groups"].append(item)
        environments.append(env)
    connectors = [dict(row) for row in db.execute(
        "SELECT id,name,product_name,last_status,last_sync_at,enabled FROM connectors ORDER BY name"
    ).fetchall()]
    summary = {
        "environment_count": sum(1 for env in environments if env["active"]),
        "group_count": sum(1 for env in environments for group in env["groups"] if group["active"]),
        "asset_count": sum(group["asset_count"] for env in environments for group in env["groups"] if group["active"]),
        "reviewed_deployments": db.execute("SELECT COUNT(*) FROM product_deployments WHERE monitoring_status!='unknown'").fetchone()[0],
    }
    return jsonify({"environments": environments, "products": [dict(row) for row in db.execute("SELECT id,name,color FROM products ORDER BY name").fetchall()], "connectors": connectors, "summary": summary})


@app.route("/api/environments", methods=["POST"])
@role_required("admin")
def environments_api():
    db = get_db()
    try:
        data = _environment_payload(request.get_json(silent=True) or {})
        columns = list(data)
        cursor = db.execute(
            f"INSERT INTO environments ({','.join(columns)}) VALUES ({','.join('?' for _ in columns)})",
            [data[column] for column in columns],
        )
    except (ValueError, TypeError) as exc:
        return jsonify({"error": str(exc)}), 400
    except sqlite3.IntegrityError:
        return jsonify({"error": "Ortam adı veya kodu zaten kullanılıyor"}), 409
    write_audit_log(db, "create", "environment", str(cursor.lastrowid), after=data)
    db.commit()
    return jsonify({"id": cursor.lastrowid}), 201


@app.route("/api/environments/<int:environment_id>", methods=["PUT"])
@role_required("admin")
def environment_api(environment_id: int):
    db = get_db()
    current = db.execute("SELECT * FROM environments WHERE id=?", (environment_id,)).fetchone()
    if not current:
        return jsonify({"error": "Ortam bulunamadı"}), 404
    try:
        data = _environment_payload(request.get_json(silent=True) or {}, current)
        db.execute(
            "UPDATE environments SET name=?,code=?,description=?,criticality=?,owner=?,active=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",
            (*data.values(), environment_id),
        )
    except (ValueError, TypeError) as exc:
        return jsonify({"error": str(exc)}), 400
    except sqlite3.IntegrityError:
        return jsonify({"error": "Ortam adı veya kodu zaten kullanılıyor"}), 409
    write_audit_log(db, "update", "environment", str(environment_id), before=dict(current), after=data)
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/environments/<int:environment_id>/asset-groups", methods=["POST"])
@role_required("admin")
def asset_groups_api(environment_id: int):
    db = get_db()
    if not db.execute("SELECT 1 FROM environments WHERE id=?", (environment_id,)).fetchone():
        return jsonify({"error": "Ortam bulunamadı"}), 404
    try:
        data = _asset_group_payload(request.get_json(silent=True) or {})
        columns = ["environment_id", *data]
        cursor = db.execute(
            f"INSERT INTO asset_groups ({','.join(columns)}) VALUES ({','.join('?' for _ in columns)})",
            [environment_id, *data.values()],
        )
    except (ValueError, TypeError) as exc:
        return jsonify({"error": str(exc)}), 400
    except sqlite3.IntegrityError:
        return jsonify({"error": "Bu ortamda aynı adlı varlık grubu zaten var"}), 409
    write_audit_log(db, "create", "asset_group", str(cursor.lastrowid), f"environment={environment_id}", after={"environment_id": environment_id, **data})
    db.commit()
    return jsonify({"id": cursor.lastrowid}), 201


@app.route("/api/asset-groups/<int:group_id>", methods=["PUT"])
@role_required("admin")
def asset_group_api(group_id: int):
    db = get_db()
    current = db.execute("SELECT * FROM asset_groups WHERE id=?", (group_id,)).fetchone()
    if not current:
        return jsonify({"error": "Varlık grubu bulunamadı"}), 404
    try:
        data = _asset_group_payload(request.get_json(silent=True) or {}, current)
        db.execute(
            "UPDATE asset_groups SET name=?,platform=?,asset_type=?,asset_count=?,criticality=?,owner=?,active=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",
            (*data.values(), group_id),
        )
    except (ValueError, TypeError) as exc:
        return jsonify({"error": str(exc)}), 400
    except sqlite3.IntegrityError:
        return jsonify({"error": "Bu ortamda aynı adlı varlık grubu zaten var"}), 409
    write_audit_log(db, "update", "asset_group", str(group_id), before=dict(current), after=data)
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/asset-groups/<int:group_id>/monitoring", methods=["PUT"])
@role_required("editor")
def asset_group_monitoring_api(group_id: int):
    db = get_db()
    if not db.execute("SELECT 1 FROM asset_groups WHERE id=?", (group_id,)).fetchone():
        return jsonify({"error": "Varlık grubu bulunamadı"}), 404
    payload = request.get_json(silent=True) or {}
    rows = payload.get("deployments", [])
    if not isinstance(rows, list) or not rows:
        return jsonify({"error": "En az bir ürün değerlendirmesi gereklidir"}), 400
    before = [dict(row) for row in db.execute("SELECT * FROM product_deployments WHERE asset_group_id=? ORDER BY product_id", (group_id,)).fetchall()]
    now = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    try:
        for row in rows:
            product_id = int(row.get("product_id"))
            product = db.execute("SELECT name FROM products WHERE id=?", (product_id,)).fetchone()
            if not product:
                raise ValueError("Geçersiz ürün")
            status = str(row.get("monitoring_status", "unknown"))
            mode = str(row.get("monitoring_mode", "other"))
            percent = int(row.get("coverage_percent", 0))
            connector_id = int(row["connector_id"]) if row.get("connector_id") else None
            if status not in MONITORING_STATUSES or mode not in MONITORING_MODES:
                raise ValueError("Geçersiz izleme durumu veya yöntemi")
            if status in {"unknown", "none"}:
                percent = 0
            elif status == "full":
                percent = 100
            elif not 1 <= percent <= 99:
                raise ValueError("Kısmi kapsam yüzdesi 1-99 arasında olmalıdır")
            if status == "none":
                connector_id = None
            if connector_id:
                connector = db.execute("SELECT product_name FROM connectors WHERE id=?", (connector_id,)).fetchone()
                if not connector or connector["product_name"] != product["name"]:
                    raise ValueError(f"Connector ürün etiketi {product['name']} ile eşleşmiyor")
            db.execute(
                """
                INSERT INTO product_deployments (
                    asset_group_id,product_id,connector_id,monitoring_status,coverage_percent,
                    monitoring_mode,owner,notes,reviewed_by,reviewed_at
                ) VALUES (?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(asset_group_id,product_id) DO UPDATE SET
                    connector_id=excluded.connector_id,monitoring_status=excluded.monitoring_status,
                    coverage_percent=excluded.coverage_percent,monitoring_mode=excluded.monitoring_mode,
                    owner=excluded.owner,notes=excluded.notes,reviewed_by=excluded.reviewed_by,
                    reviewed_at=excluded.reviewed_at,updated_at=CURRENT_TIMESTAMP
                """,
                (
                    group_id, product_id, connector_id, status, percent, mode,
                    str(row.get("owner", "")).strip(), str(row.get("notes", "")).strip(),
                    g.current_user["username"], now,
                ),
            )
    except (ValueError, TypeError) as exc:
        db.rollback()
        return jsonify({"error": str(exc)}), 400
    after = [dict(row) for row in db.execute("SELECT * FROM product_deployments WHERE asset_group_id=? ORDER BY product_id", (group_id,)).fetchall()]
    write_audit_log(db, "assess", "asset_group_monitoring", str(group_id), f"products={len(rows)}", before=before, after=after)
    db.commit()
    return jsonify({"ok": True, "reviewed_at": now})


def _mitre_catalog() -> dict[str, Any]:
    mitre = get_minified_mitre()
    technique_ids: set[str] = set()
    technique_names: dict[str, str] = {}
    mitigation_ids: set[str] = set()
    tactics: set[str] = set()
    for obj in mitre.get("objects", []):
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        if obj.get("type") == "attack-pattern":
            external_id = next(
                (
                    ref.get("external_id", "")
                    for ref in obj.get("external_references", [])
                    if ref.get("source_name") == "mitre-attack"
                ),
                "",
            )
            if external_id.startswith("T"):
                technique_ids.add(external_id.upper())
                technique_names[obj.get("name", "").strip().casefold()] = external_id.upper()
            for phase in obj.get("kill_chain_phases", []):
                if phase.get("kill_chain_name") == "mitre-attack":
                    tactics.add(phase.get("phase_name", ""))
        elif obj.get("type") == "course-of-action":
            external_id = next(
                (
                    ref.get("external_id", "")
                    for ref in obj.get("external_references", [])
                    if ref.get("source_name") == "mitre-attack"
                ),
                "",
            )
            if external_id.startswith("M"):
                mitigation_ids.add(external_id.upper())
    for legacy_name, technique_id in TECHNIQUE_NAME_ALIASES.items():
        if technique_id in technique_ids:
            technique_names[legacy_name] = technique_id
    return {
        "technique_ids": technique_ids,
        "technique_names": technique_names,
        "mitigation_ids": mitigation_ids,
        "tactics": tactics,
    }


def _compute_data_quality(db: sqlite3.Connection) -> dict[str, Any]:
    catalog = _mitre_catalog()
    valid_ids = catalog["technique_ids"]
    name_to_id = catalog["technique_names"]
    valid_tactics = catalog["tactics"]
    tactic_aliases = {label.casefold(): slug for slug, label in _TACTIC_LABEL_MAP.items()}
    products = {r["name"] for r in db.execute("SELECT name FROM products").fetchall()}
    rules = db.execute(
        "SELECT id, name, tactic, source, coverage_level FROM rules ORDER BY id"
    ).fetchall()
    relations = db.execute(
        """
        SELECT rt.rule_id, rt.tech_id, r.name AS rule_name
        FROM rule_techniques rt
        LEFT JOIN rules r ON r.id = rt.rule_id
        ORDER BY rt.rule_id, rt.tech_id
        """
    ).fetchall()
    mapped_by_rule: dict[int, int] = {}
    issues: list[dict[str, Any]] = []
    invalid_mappings = 0
    legacy_mappings = 0
    orphan_relations = 0

    for relation in relations:
        tech_value = (relation["tech_id"] or "").strip()
        if relation["rule_name"] is None:
            orphan_relations += 1
            issues.append({
                "severity": "critical", "type": "orphan_mapping",
                "entity_id": relation["rule_id"], "value": tech_value,
                "message": "Silinmiş bir tespite bağlı teknik eşlemesi.",
            })
            continue
        normalized = tech_value.upper()
        if normalized in valid_ids:
            mapped_by_rule[relation["rule_id"]] = mapped_by_rule.get(relation["rule_id"], 0) + 1
        elif tech_value.casefold() in name_to_id:
            legacy_mappings += 1
            issues.append({
                "severity": "warning", "type": "legacy_mapping",
                "entity_id": relation["rule_id"], "value": tech_value,
                "suggested_value": name_to_id[tech_value.casefold()],
                "message": "Teknik adı kullanılmış; standart MITRE ID'ye dönüştürülmeli.",
            })
        else:
            invalid_mappings += 1
            issues.append({
                "severity": "critical", "type": "invalid_mapping",
                "entity_id": relation["rule_id"], "value": tech_value,
                "message": "MITRE veri setinde bulunmayan teknik eşlemesi.",
            })

    unmapped = 0
    unknown_products = 0
    invalid_tactics = 0
    invalid_coverage = 0
    for rule in rules:
        if mapped_by_rule.get(rule["id"], 0) == 0:
            unmapped += 1
            issues.append({
                "severity": "critical", "type": "unmapped_rule",
                "entity_id": rule["id"], "value": rule["name"],
                "message": "Tespit geçerli bir MITRE tekniğine bağlı değil.",
            })
        if rule["source"] not in products:
            unknown_products += 1
            issues.append({
                "severity": "warning", "type": "unknown_product",
                "entity_id": rule["id"], "value": rule["source"],
                "message": "Tespitin veri kaynağı ürün kataloğunda bulunmuyor.",
            })
        tactic = (rule["tactic"] or "").strip()
        tactic_key = tactic.casefold()
        if tactic_key not in valid_tactics and tactic_key not in tactic_aliases and tactic_key != "none":
            invalid_tactics += 1
            issues.append({
                "severity": "warning", "type": "invalid_tactic",
                "entity_id": rule["id"], "value": tactic,
                "message": "Taktik alanı MITRE Enterprise taktikleriyle eşleşmiyor.",
            })
        if rule["coverage_level"] not in ("low", "partial", "full"):
            invalid_coverage += 1
            issues.append({
                "severity": "warning", "type": "invalid_coverage",
                "entity_id": rule["id"], "value": rule["coverage_level"],
                "message": "Geçersiz tespit güven seviyesi.",
            })

    total_rules = len(rules)
    relation_count = len(relations)
    deductions = (
        (unmapped / max(total_rules, 1)) * 45
        + ((invalid_mappings + orphan_relations) / max(relation_count, 1)) * 30
        + (unknown_products / max(total_rules, 1)) * 10
        + (invalid_tactics / max(total_rules, 1)) * 10
        + (invalid_coverage / max(total_rules, 1)) * 5
    )
    quality_score = round(max(0.0, 100.0 - deductions), 1)
    mitre_stat = MITRE_PATH.stat()
    return {
        "summary": {
            "quality_score": quality_score,
            "total_rules": total_rules,
            "validly_mapped_rules": total_rules - unmapped,
            "unmapped_rules": unmapped,
            "relation_count": relation_count,
            "invalid_mappings": invalid_mappings,
            "legacy_mappings": legacy_mappings,
            "orphan_relations": orphan_relations,
            "unknown_products": unknown_products,
            "invalid_tactics": invalid_tactics,
            "invalid_coverage_levels": invalid_coverage,
            "critical_issue_count": sum(1 for issue in issues if issue["severity"] == "critical"),
            "warning_count": sum(1 for issue in issues if issue["severity"] == "warning"),
        },
        "dataset": {
            "path": "data/mitre.json",
            "size_bytes": mitre_stat.st_size,
            "modified_at": datetime.fromtimestamp(mitre_stat.st_mtime, timezone.utc).isoformat(),
            "technique_count": len(valid_ids),
            "mitigation_count": len(catalog["mitigation_ids"]),
        },
        "issues": issues[:500],
        "issue_count": len(issues),
    }


@app.route("/api/data-quality", methods=["GET"])
@role_required("viewer")
def data_quality_api():
    if not MITRE_PATH.exists():
        return jsonify({"error": "MITRE data not found"}), 500
    return jsonify(_compute_data_quality(get_db()))


@app.route("/api/data-quality/repair", methods=["POST"])
@role_required("admin")
def data_quality_repair_api():
    db = get_db()
    before = _compute_data_quality(db)["summary"]
    catalog = _mitre_catalog()
    name_to_id = catalog["technique_names"]
    repaired = {
        "legacy_mappings": 0, "placeholder_mappings": 0,
        "orphan_relations": 0, "tactics": 0,
    }

    for row in db.execute("SELECT rule_id, tech_id FROM rule_techniques").fetchall():
        canonical = name_to_id.get((row["tech_id"] or "").strip().casefold())
        if canonical:
            db.execute(
                "INSERT OR IGNORE INTO rule_techniques(rule_id, tech_id) VALUES (?, ?)",
                (row["rule_id"], canonical),
            )
            db.execute(
                "DELETE FROM rule_techniques WHERE rule_id=? AND tech_id=?",
                (row["rule_id"], row["tech_id"]),
            )
            repaired["legacy_mappings"] += 1
        elif (row["tech_id"] or "").strip().casefold() in ("", "none", "null", "-"):
            db.execute(
                "DELETE FROM rule_techniques WHERE rule_id=? AND tech_id=?",
                (row["rule_id"], row["tech_id"]),
            )
            repaired["placeholder_mappings"] += 1
    cur = db.execute(
        "DELETE FROM rule_techniques WHERE rule_id NOT IN (SELECT id FROM rules)"
    )
    repaired["orphan_relations"] = cur.rowcount
    tactic_aliases = {label.casefold(): slug for slug, label in _TACTIC_LABEL_MAP.items()}
    for row in db.execute("SELECT id, tactic FROM rules").fetchall():
        canonical = tactic_aliases.get((row["tactic"] or "").strip().casefold())
        if canonical and row["tactic"] != canonical:
            db.execute("UPDATE rules SET tactic=? WHERE id=?", (canonical, row["id"]))
            repaired["tactics"] += 1
    _invalidate_ttp_cache()
    after = _compute_data_quality(db)["summary"]
    write_audit_log(
        db, action="repair", target_type="data_quality",
        detail=_json_text(repaired), before=before, after=after,
    )
    db.commit()
    return jsonify({"ok": True, "repaired": repaired, "before": before, "after": after})

_TACTIC_ORDER = [
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
]


def _invalidate_ttp_cache():
    TTP_LIST_CACHE["dirty"] = True


@app.route("/api/ttp-list")
@role_required("viewer")
def ttp_list():
    if not TTP_LIST_CACHE["dirty"] and TTP_LIST_CACHE["data"] is not None:
        return jsonify(TTP_LIST_CACHE["data"])
    if not MITRE_PATH.exists():
        return jsonify({"error": "MITRE data not found"}), 500
    try:
        mitre = get_minified_mitre()
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500

    db = get_db()

    # Build lookup structures from minified MITRE data
    tech_by_stix: dict[str, dict] = {}
    mitigation_stix_to_ext: dict[str, str] = {}
    tech_to_mitigations: dict[str, set] = {}

    for obj in mitre["objects"]:
        t = obj.get("type")
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        if t == "attack-pattern":
            ext_id = next(
                (
                    ref["external_id"]
                    for ref in obj.get("external_references", [])
                    if ref.get("source_name") == "mitre-attack"
                    and ref.get("external_id", "").startswith("T")
                ),
                None,
            )
            if not ext_id:
                continue
            tactics = [
                ph["phase_name"]
                for ph in obj.get("kill_chain_phases", [])
                if ph.get("kill_chain_name") == "mitre-attack"
            ]
            is_sub = obj.get("x_mitre_is_subtechnique", False)
            parent_id = ext_id.split(".")[0] if is_sub and "." in ext_id else None
            tech_by_stix[obj["id"]] = {
                "external_id": ext_id,
                "name": obj.get("name", ""),
                "is_subtechnique": is_sub,
                "parent_id": parent_id,
                "tactics": tactics,
            }
        elif t == "course-of-action":
            ext_id = next(
                (
                    ref["external_id"]
                    for ref in obj.get("external_references", [])
                    if ref.get("source_name") == "mitre-attack"
                    and ref.get("external_id", "").startswith("M")
                ),
                None,
            )
            if ext_id:
                mitigation_stix_to_ext[obj["id"]] = ext_id
        elif t == "relationship" and obj.get("relationship_type") == "mitigates":
            mit_ext = mitigation_stix_to_ext.get(obj.get("source_ref", ""))
            tech_info = tech_by_stix.get(obj.get("target_ref", ""))
            if mit_ext and tech_info:
                tech_to_mitigations.setdefault(tech_info["external_id"], set()).add(mit_ext)

    # Rule counts per tech_id
    rule_rows = db.execute(
        "SELECT tech_id, COUNT(DISTINCT rule_id) AS cnt FROM rule_techniques GROUP BY tech_id"
    ).fetchall()
    rule_count_by_tech = {r["tech_id"]: r["cnt"] for r in rule_rows}

    # Covered mitigations (has entries or globally checked)
    covered_mits = set(
        r["mitigation_id"]
        for r in db.execute(
            "SELECT DISTINCT mitigation_id FROM mitigation_entries"
        ).fetchall()
    )
    covered_mits |= set(
        r["mitigation_id"]
        for r in db.execute(
            "SELECT mitigation_id FROM mitigation_global WHERE checked=1"
        ).fetchall()
    )

    # Technique config
    tc_rows = db.execute(
        "SELECT tech_id, importance, rule_threshold FROM technique_config"
    ).fetchall()
    technique_config_map = {
        r["tech_id"]: {"importance": r["importance"], "rule_threshold": r["rule_threshold"]}
        for r in tc_rows
    }

    # Build tactic groups
    tactic_techs: dict[str, list] = {}
    for _stix_id, info in tech_by_stix.items():
        teid = info["external_id"]
        tc = technique_config_map.get(teid, {})
        importance = tc.get("importance", 0.5)
        rule_threshold = tc.get("rule_threshold", 3)
        mits_for_tech = tech_to_mitigations.get(teid, set())
        tech_data = {
            "tech_id": teid,
            "name": info["name"],
            "is_subtechnique": info["is_subtechnique"],
            "parent_id": info["parent_id"],
            "rule_count": rule_count_by_tech.get(teid, 0),
            "mitigation_entry_count": len(mits_for_tech & covered_mits),
            "total_mitigations": len(mits_for_tech),
            "importance": importance,
            "rule_threshold": rule_threshold,
        }
        for tactic in info["tactics"]:
            tactic_techs.setdefault(tactic, []).append(tech_data)

    result = []
    for tactic in _TACTIC_ORDER:
        if tactic in tactic_techs:
            result.append({
                "tactic": tactic,
                "techniques": sorted(tactic_techs[tactic], key=lambda x: x["tech_id"]),
            })
    for tactic, techs in tactic_techs.items():
        if tactic not in _TACTIC_ORDER:
            result.append({
                "tactic": tactic,
                "techniques": sorted(techs, key=lambda x: x["tech_id"]),
            })
    TTP_LIST_CACHE["data"] = result
    TTP_LIST_CACHE["dirty"] = False
    return jsonify(result)


def _importance_to_level(imp: float) -> int:
    if imp >= 0.91:
        return 5
    if imp >= 0.73:
        return 4
    if imp >= 0.57:
        return 3
    if imp >= 0.39:
        return 2
    return 1


@app.route("/api/technique-detail/<tech_id>")
@role_required("viewer")
def technique_detail(tech_id: str):
    tech_id = tech_id.upper()
    if not MITRE_PATH.exists():
        return jsonify({"error": "MITRE data not found"}), 500
    try:
        mitre = get_minified_mitre()
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500

    db = get_db()

    tech_obj: dict | None = None
    mitigation_stix_to_info: dict[str, dict] = {}
    tech_mitigations: list[str] = []

    for obj in mitre["objects"]:
        t = obj.get("type")
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        if t == "attack-pattern":
            for ref in obj.get("external_references", []):
                if (
                    ref.get("source_name") == "mitre-attack"
                    and ref.get("external_id", "").upper() == tech_id
                ):
                    tech_obj = obj
                    break
        elif t == "course-of-action":
            ext_id = next(
                (
                    ref["external_id"]
                    for ref in obj.get("external_references", [])
                    if ref.get("source_name") == "mitre-attack"
                    and ref.get("external_id", "").startswith("M")
                ),
                None,
            )
            if ext_id:
                mitigation_stix_to_info[obj["id"]] = {
                    "mitigation_id": ext_id,
                    "name": obj.get("name", ""),
                    "description": (obj.get("description") or "")[:200],
                }

    if not tech_obj:
        return jsonify({"error": f"Technique {tech_id} not found"}), 404

    tech_stix_id = tech_obj["id"]
    for obj in mitre["objects"]:
        if (
            obj.get("type") == "relationship"
            and obj.get("relationship_type") == "mitigates"
            and obj.get("target_ref") == tech_stix_id
        ):
            mit_stix = obj.get("source_ref", "")
            if mit_stix in mitigation_stix_to_info:
                tech_mitigations.append(mit_stix)

    # MITRE URL
    mitre_url = next(
        (
            ref.get("url", "")
            for ref in tech_obj.get("external_references", [])
            if ref.get("source_name") == "mitre-attack"
        ),
        "",
    )

    # Linked rules
    rule_rows = db.execute(
        """
        SELECT r.name, r.source
        FROM rules r
        JOIN rule_techniques rt ON rt.rule_id = r.id
        WHERE rt.tech_id = ?
        ORDER BY r.name ASC
        """,
        (tech_id,),
    ).fetchall()
    linked_rules = [{"name": r["name"], "source": r["source"]} for r in rule_rows]

    # Mitigation details with entries
    mitigation_data = []
    for mit_stix in tech_mitigations:
        mit_info = mitigation_stix_to_info[mit_stix]
        mid = mit_info["mitigation_id"]
        entries = db.execute(
            "SELECT id, team, comment FROM mitigation_entries WHERE mitigation_id = ? ORDER BY id ASC",
            (mid,),
        ).fetchall()
        global_row = db.execute(
            "SELECT checked, comment, team FROM mitigation_global WHERE mitigation_id = ?",
            (mid,),
        ).fetchone()
        mitigation_data.append({
            "mitigation_id": mid,
            "name": mit_info["name"],
            "description": mit_info["description"],
            "entries": [{"id": e["id"], "team": e["team"], "comment": e["comment"]} for e in entries],
            "global_checked": bool(global_row["checked"]) if global_row else False,
        })

    # Technique config
    tc = db.execute(
        "SELECT importance, rule_threshold FROM technique_config WHERE tech_id = ?",
        (tech_id,),
    ).fetchone()
    importance = tc["importance"] if tc else 0.5
    rule_threshold = tc["rule_threshold"] if tc else 3

    return jsonify({
        "tech_id": tech_id,
        "name": tech_obj.get("name", ""),
        "description": (tech_obj.get("description") or "")[:500],
        "platforms": tech_obj.get("x_mitre_platforms", []),
        "mitre_url": mitre_url,
        "importance": importance,
        "importance_level": _importance_to_level(importance),
        "rule_threshold": rule_threshold,
        "linked_rules": linked_rules,
        "mitigations": mitigation_data,
    })


@app.route("/api/admin/reset", methods=["POST"])
@role_required("admin")
def admin_reset():
    payload = request.get_json(silent=True) or {}
    confirm = (payload.get("confirm") or "").strip()
    reseed = bool(payload.get("reseed"))
    if confirm != "RESET":
        return jsonify({"error": "Confirmation required. Send confirm=RESET."}), 400

    db = get_db()
    db.execute("DELETE FROM mitigation_notes")
    db.execute("DELETE FROM mitigation_global")
    db.execute("DELETE FROM mitigation_entries")
    db.execute("DELETE FROM rule_techniques")
    db.execute("DELETE FROM rules")
    _invalidate_ttp_cache()
    db.commit()

    inserted = 0
    if reseed:
        inserted = _reseed_rules(db)

    write_audit_log(
        db,
        action="reset",
        target_type="admin",
        detail=f"reseed={reseed};inserted={inserted}",
    )
    db.commit()

    return jsonify({"ok": True, "reseeded": reseed, "inserted": inserted})


@app.route("/api/technique-config", methods=["GET"])
@login_required
def get_technique_config():
    """Tüm teknikler için importance + rule_threshold değerlerini döner.
    Viewer dahil tüm giriş yapmış kullanıcılar okuyabilir."""
    db = get_db()
    rows = db.execute(
        "SELECT tech_id, importance, rule_threshold, source, group_count, tool_count "
        "FROM technique_config"
    ).fetchall()
    return jsonify({r["tech_id"]: dict(r) for r in rows})


_LEVEL_TO_FLOAT = {1: 0.30, 2: 0.48, 3: 0.65, 4: 0.82, 5: 1.00}

KPI_FORMULA_VERSION = "soc-cmm-1.0"
QUALITY_FIELDS = (
    "device_completeness", "field_completeness", "timeliness",
    "consistency", "retention",
)


def _iso_date_has_expired(value: str | None) -> bool:
    if not value:
        return False
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).date() < datetime.now(timezone.utc).date()
    except ValueError:
        return True


def _profile_row(db: sqlite3.Connection, profile_id: int | None = None) -> sqlite3.Row | None:
    if profile_id is not None:
        return db.execute("SELECT * FROM soc_profiles WHERE id=?", (profile_id,)).fetchone()
    return db.execute(
        "SELECT * FROM soc_profiles ORDER BY is_active DESC, id DESC LIMIT 1"
    ).fetchone()


def _compute_soc_kpis(db: sqlite3.Connection, profile_id: int | None = None) -> dict[str, Any]:
    profile = _profile_row(db, profile_id)
    if not profile:
        raise ValueError("SOC-CMM profile not found")
    catalog = _attack_catalog()
    profile_rows = db.execute(
        """
        SELECT tech_id, weight, rationale FROM soc_profile_techniques
        WHERE profile_id=? AND included=1 ORDER BY tech_id
        """,
        (profile["id"],),
    ).fetchall()
    profile_techniques = {row["tech_id"]: dict(row) for row in profile_rows}

    detection_rows = db.execute(
        """
        SELECT rt.tech_id, r.id AS rule_id, r.name, da.lifecycle_status,
               da.validation_status, da.detection_score, da.owner,
               da.validation_method, da.evidence_ref, da.last_validated_at,
               da.expires_at, da.applicable_scope
        FROM rule_techniques rt
        JOIN rules r ON r.id=rt.rule_id
        LEFT JOIN detection_assessments da ON da.rule_id=r.id
        WHERE rt.tech_id IN (
            SELECT tech_id FROM soc_profile_techniques WHERE profile_id=? AND included=1
        )
        """,
        (profile["id"],),
    ).fetchall()
    detections_by_tech: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in detection_rows:
        item = dict(row)
        if item.get("validation_status") == "validated" and _iso_date_has_expired(item.get("expires_at")):
            item["validation_status"] = "expired"
        detections_by_tech[row["tech_id"]].append(item)

    source_rows = db.execute(
        """
        SELECT ts.*, tc.component_id FROM telemetry_sources ts
        JOIN telemetry_components tc ON tc.source_id=ts.id
        WHERE ts.active=1 AND ts.analytics_ready=1
        """
    ).fetchall()
    component_scores: dict[str, float] = {}
    component_sources: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in source_rows:
        if profile["scope"].casefold() != "kurum geneli" and row["scope"].casefold() not in {"kurum geneli", profile["scope"].casefold()}:
            continue
        quality = sum(int(row[field]) for field in QUALITY_FIELDS) / (len(QUALITY_FIELDS) * 5)
        score = round(quality * 4, 2)
        component_scores[row["component_id"]] = max(component_scores.get(row["component_id"], 0), score)
        component_sources[row["component_id"]].append({
            "id": row["id"], "name": row["name"], "score": score,
            "scope": row["scope"], "last_event_at": row["last_event_at"],
        })
    overrides = {
        row["tech_id"]: dict(row)
        for row in db.execute(
            "SELECT tech_id, score, reason, approved_by, updated_at FROM visibility_overrides WHERE profile_id=?",
            (profile["id"],),
        ).fetchall()
    }

    details: list[dict[str, Any]] = []
    mapped_count = validated_count = visible_count = 0
    detection_weighted_sum = visibility_weighted_sum = total_weight = 0.0
    for tech_id, profile_item in profile_techniques.items():
        tech = catalog["techniques"].get(tech_id, {"id": tech_id, "name": "Unknown technique", "tactics": []})
        detections = detections_by_tech.get(tech_id, [])
        active = [
            item for item in detections
            if item.get("lifecycle_status", "active") == "active"
            and (
                profile["scope"].casefold() == "kurum geneli"
                or str(item.get("applicable_scope") or "Kurum geneli").casefold() in {"kurum geneli", profile["scope"].casefold()}
            )
        ]
        validated = [
            item for item in active
            if item.get("validation_status") == "validated" and int(item.get("detection_score") or 0) >= 1
        ]
        detection_score = max((int(item.get("detection_score") or 0) for item in validated), default=0)
        mapped = bool(active)
        is_validated = bool(validated)
        mapped_count += int(mapped)
        validated_count += int(is_validated)

        required_components = catalog["tech_components"].get(tech_id, [])
        available_scores = [component_scores.get(component_id, 0) for component_id in required_components]
        derived_visibility = round(sum(available_scores) / len(available_scores), 2) if available_scores else 0.0
        override = overrides.get(tech_id)
        visibility_score = float(override["score"]) if override else derived_visibility
        visible = visibility_score >= 2
        visible_count += int(visible)
        weight = int(profile_item["weight"])
        total_weight += weight
        detection_weighted_sum += weight * (detection_score / 5)
        visibility_weighted_sum += weight * (visibility_score / 4)
        if is_validated and visible:
            gap_state = "controlled"
        elif visible:
            gap_state = "detection_gap"
        elif is_validated:
            gap_state = "visibility_risk"
        else:
            gap_state = "blind_spot"
        details.append({
            "tech_id": tech_id,
            "name": tech.get("name", ""),
            "tactics": tech.get("tactics", []),
            "platforms": tech.get("platforms", []),
            "weight": weight,
            "rationale": profile_item["rationale"],
            "mapped": mapped,
            "validated": is_validated,
            "detection_score": detection_score,
            "detection_count": len(active),
            "validated_detection_count": len(validated),
            "visibility_score": round(visibility_score, 2),
            "visibility_source": "override" if override else "derived",
            "visibility_reason": override["reason"] if override else "",
            "required_components": required_components,
            "available_components": [component_id for component_id in required_components if component_scores.get(component_id, 0) > 0],
            "gap_state": gap_state,
        })

    denominator = len(details)
    pct = lambda count: round(count / denominator * 100, 1) if denominator else 0.0
    metrics = {
        "mapped_coverage": pct(mapped_count),
        "validated_coverage": pct(validated_count),
        "weighted_detection": round(detection_weighted_sum / total_weight * 100, 1) if total_weight else 0.0,
        "visibility": round(visibility_weighted_sum / total_weight * 100, 1) if total_weight else 0.0,
        "visible_threshold_coverage": pct(visible_count),
        "mapped_techniques": mapped_count,
        "validated_techniques": validated_count,
        "visible_techniques": visible_count,
        "denominator": denominator,
    }
    snapshots = [
        dict(row) for row in db.execute(
            """
            SELECT id, mapped_coverage, validated_coverage, weighted_detection,
                   visibility, visible_threshold_coverage, profile_version,
                   formula_version, created_by, created_at
            FROM kpi_snapshots WHERE profile_id=? ORDER BY created_at ASC, id ASC LIMIT 60
            """,
            (profile["id"],),
        ).fetchall()
    ]
    return {
        "profile": dict(profile), "formula_version": KPI_FORMULA_VERSION,
        "metrics": metrics, "techniques": details, "snapshots": snapshots,
        "catalog": {"technique_count": len(catalog["techniques"]), "component_count": len(catalog["components"]), "attack_spec_version": catalog["version"]},
    }


@app.route("/api/soc-profiles", methods=["GET", "POST"])
@role_required("viewer")
def soc_profiles_api():
    db = get_db()
    if request.method == "GET":
        rows = db.execute(
            """
            SELECT p.*, COUNT(CASE WHEN pt.included=1 THEN 1 END) AS technique_count
            FROM soc_profiles p LEFT JOIN soc_profile_techniques pt ON pt.profile_id=p.id
            GROUP BY p.id ORDER BY p.is_active DESC, p.id DESC
            """
        ).fetchall()
        return jsonify([dict(row) for row in rows])
    if ROLE_LEVELS[g.current_user["role"]] < ROLE_LEVELS["admin"]:
        return jsonify({"error": "Admin role required"}), 403
    payload = request.get_json(silent=True) or {}
    name = str(payload.get("name", "")).strip()
    if not name:
        return jsonify({"error": "Profile name is required"}), 400
    catalog = _attack_catalog()
    cursor = db.execute(
        "INSERT INTO soc_profiles (name, description, scope, attack_version) VALUES (?, ?, ?, ?)",
        (name, str(payload.get("description", "")).strip(), str(payload.get("scope", "Kurum geneli")).strip(), catalog["version"]),
    )
    profile_id = cursor.lastrowid
    db.executemany(
        "INSERT INTO soc_profile_techniques (profile_id, tech_id) VALUES (?, ?)",
        [(profile_id, tech_id) for tech_id in catalog["techniques"]],
    )
    write_audit_log(db, "create", "soc_profile", str(profile_id), f"name={name}", after=payload)
    db.commit()
    return jsonify({"id": profile_id}), 201


@app.route("/api/soc-profiles/<int:profile_id>", methods=["GET", "PUT"])
@role_required("viewer")
def soc_profile_api(profile_id: int):
    db = get_db()
    profile = _profile_row(db, profile_id)
    if not profile:
        return jsonify({"error": "Profile not found"}), 404
    if request.method == "GET":
        catalog = _attack_catalog()
        rows = db.execute(
            "SELECT tech_id, included, weight, rationale FROM soc_profile_techniques WHERE profile_id=?",
            (profile_id,),
        ).fetchall()
        techniques = []
        for row in rows:
            item = dict(row)
            item.update(catalog["techniques"].get(row["tech_id"], {"name": "Unknown technique", "tactics": [], "platforms": []}))
            techniques.append(item)
        return jsonify({"profile": dict(profile), "techniques": techniques})
    if ROLE_LEVELS[g.current_user["role"]] < ROLE_LEVELS["admin"]:
        return jsonify({"error": "Admin role required"}), 403
    payload = request.get_json(silent=True) or {}
    before = dict(profile)
    name = str(payload.get("name", profile["name"])).strip()
    scope = str(payload.get("scope", profile["scope"])).strip()
    description = str(payload.get("description", profile["description"])).strip()
    if not name or not scope:
        return jsonify({"error": "Name and scope are required"}), 400
    make_active = bool(payload.get("is_active", profile["is_active"]))
    if make_active:
        db.execute("UPDATE soc_profiles SET is_active=0")
    db.execute(
        """
        UPDATE soc_profiles SET name=?, description=?, scope=?, is_active=?,
        status='draft', approved_by='', approved_at=NULL, version=version+1,
        updated_at=CURRENT_TIMESTAMP WHERE id=?
        """,
        (name, description, scope, int(make_active), profile_id),
    )
    after = dict(_profile_row(db, profile_id))
    write_audit_log(db, "update", "soc_profile", str(profile_id), "Profile metadata changed; approval reset", before=before, after=after)
    db.commit()
    return jsonify(after)


@app.route("/api/soc-profiles/<int:profile_id>/techniques", methods=["PUT"])
@role_required("admin")
def soc_profile_techniques_api(profile_id: int):
    db = get_db()
    profile = _profile_row(db, profile_id)
    if not profile:
        return jsonify({"error": "Profile not found"}), 404
    payload = request.get_json(silent=True) or {}
    items = payload.get("techniques", [])
    if not isinstance(items, list) or not items:
        return jsonify({"error": "techniques must be a non-empty list"}), 400
    valid_ids = set(_attack_catalog()["techniques"])
    changed = 0
    for item in items:
        tech_id = str(item.get("tech_id", "")).upper()
        if tech_id not in valid_ids:
            return jsonify({"error": f"Unknown technique: {tech_id}"}), 400
        weight = max(1, min(5, int(item.get("weight", 3))))
        db.execute(
            """
            INSERT INTO soc_profile_techniques (profile_id, tech_id, included, weight, rationale)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(profile_id, tech_id) DO UPDATE SET
                included=excluded.included, weight=excluded.weight, rationale=excluded.rationale
            """,
            (profile_id, tech_id, int(bool(item.get("included", True))), weight, str(item.get("rationale", "")).strip()),
        )
        changed += 1
    db.execute(
        "UPDATE soc_profiles SET status='draft', approved_by='', approved_at=NULL, version=version+1, updated_at=CURRENT_TIMESTAMP WHERE id=?",
        (profile_id,),
    )
    write_audit_log(db, "update", "soc_profile_techniques", str(profile_id), f"changed={changed};approval reset", after=items)
    db.commit()
    return jsonify({"ok": True, "changed": changed})


@app.route("/api/soc-profiles/<int:profile_id>/approve", methods=["POST"])
@role_required("admin")
def approve_soc_profile_api(profile_id: int):
    db = get_db()
    profile = _profile_row(db, profile_id)
    if not profile:
        return jsonify({"error": "Profile not found"}), 404
    included = db.execute(
        "SELECT COUNT(*) FROM soc_profile_techniques WHERE profile_id=? AND included=1", (profile_id,)
    ).fetchone()[0]
    if not included:
        return jsonify({"error": "Profile must include at least one technique"}), 409
    if not profile["description"].strip() or not profile["scope"].strip():
        return jsonify({"error": "Profile scope and decision description are required for approval"}), 409
    now = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    db.execute(
        "UPDATE soc_profiles SET status='approved', approved_by=?, approved_at=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
        (g.current_user["username"], now, profile_id),
    )
    write_audit_log(db, "approve", "soc_profile", str(profile_id), f"included={included};version={profile['version']}", before=dict(profile), after=dict(_profile_row(db, profile_id)))
    db.commit()
    return jsonify(dict(_profile_row(db, profile_id)))


@app.route("/api/detection-assessments", methods=["GET"])
@role_required("viewer")
def detection_assessments_api():
    db = get_db()
    rows = db.execute(
        """
        SELECT r.id AS rule_id, r.name, r.source, GROUP_CONCAT(rt.tech_id) AS tech_ids,
               da.lifecycle_status, da.validation_status, da.detection_score,
               da.applicable_scope, da.owner, da.validation_method, da.evidence_ref,
               da.data_dependencies, da.last_validated_at, da.expires_at, da.updated_at
        FROM rules r LEFT JOIN rule_techniques rt ON rt.rule_id=r.id
        LEFT JOIN detection_assessments da ON da.rule_id=r.id
        GROUP BY r.id ORDER BY r.name
        """
    ).fetchall()
    return jsonify([dict(row) for row in rows])


@app.route("/api/detection-assessments/<int:rule_id>", methods=["PUT"])
@role_required("editor")
def detection_assessment_api(rule_id: int):
    db = get_db()
    if not db.execute("SELECT 1 FROM rules WHERE id=?", (rule_id,)).fetchone():
        return jsonify({"error": "Detection not found"}), 404
    payload = request.get_json(silent=True) or {}
    lifecycle = str(payload.get("lifecycle_status", "active"))
    validation = str(payload.get("validation_status", "untested"))
    score = int(payload.get("detection_score", 0))
    if lifecycle not in {"draft", "active", "disabled"} or validation not in {"untested", "validated", "failed", "expired"} or score < -1 or score > 5:
        return jsonify({"error": "Invalid lifecycle, validation status or score"}), 400
    method = str(payload.get("validation_method", "")).strip()
    evidence = str(payload.get("evidence_ref", "")).strip()
    last_validated = payload.get("last_validated_at") or None
    if validation == "validated" and (score < 1 or not method or not evidence or not last_validated):
        return jsonify({"error": "Validated detections require score, method, evidence and validation date"}), 400
    before_row = db.execute("SELECT * FROM detection_assessments WHERE rule_id=?", (rule_id,)).fetchone()
    values = (
        lifecycle, validation, score, str(payload.get("applicable_scope", "Kurum geneli")).strip(),
        str(payload.get("owner", "")).strip(), method, evidence,
        str(payload.get("data_dependencies", "")).strip(), last_validated,
        payload.get("expires_at") or None, g.current_user["username"], rule_id,
    )
    db.execute(
        """
        INSERT INTO detection_assessments (
            lifecycle_status, validation_status, detection_score, applicable_scope,
            owner, validation_method, evidence_ref, data_dependencies,
            last_validated_at, expires_at, updated_by, rule_id, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(rule_id) DO UPDATE SET lifecycle_status=excluded.lifecycle_status,
            validation_status=excluded.validation_status, detection_score=excluded.detection_score,
            applicable_scope=excluded.applicable_scope, owner=excluded.owner,
            validation_method=excluded.validation_method, evidence_ref=excluded.evidence_ref,
            data_dependencies=excluded.data_dependencies, last_validated_at=excluded.last_validated_at,
            expires_at=excluded.expires_at, updated_by=excluded.updated_by, updated_at=CURRENT_TIMESTAMP
        """,
        values,
    )
    after = dict(db.execute("SELECT * FROM detection_assessments WHERE rule_id=?", (rule_id,)).fetchone())
    write_audit_log(db, "assess", "detection", str(rule_id), f"validation={validation};score={score}", before=dict(before_row) if before_row else None, after=after)
    db.commit()
    return jsonify(after)


@app.route("/api/attack-data-components")
@role_required("viewer")
def attack_data_components_api():
    catalog = _attack_catalog()
    components = sorted(catalog["components"].values(), key=lambda item: item["name"])
    return jsonify({
        "attack_spec_version": catalog["version"],
        "components": components,
        "technique_components": catalog["tech_components"],
    })


def _telemetry_payload(payload: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    data: dict[str, Any] = {
        "name": str(payload.get("name", "")).strip(),
        "producer": str(payload.get("producer", "")).strip(),
        "destination": str(payload.get("destination", "")).strip(),
        "scope": str(payload.get("scope", "Kurum geneli")).strip(),
        "owner": str(payload.get("owner", "")).strip(),
        "connected_at": payload.get("connected_at") or None,
        "last_event_at": payload.get("last_event_at") or None,
        "active": int(bool(payload.get("active", True))),
        "analytics_ready": int(bool(payload.get("analytics_ready", False))),
        "notes": str(payload.get("notes", "")).strip(),
    }
    for field in QUALITY_FIELDS:
        data[field] = int(payload.get(field, 0))
        if data[field] < 0 or data[field] > 5:
            raise ValueError(f"{field} must be between 0 and 5")
    components = sorted({str(item).upper().strip() for item in payload.get("components", []) if str(item).strip()})
    if not data["name"] or not data["scope"]:
        raise ValueError("Name and scope are required")
    valid_components = set(_attack_catalog()["components"])
    unknown = [item for item in components if item not in valid_components]
    if unknown:
        raise ValueError(f"Unknown data component: {unknown[0]}")
    if data["analytics_ready"] and not components:
        raise ValueError("Analytics-ready telemetry requires at least one data component")
    return data, components


@app.route("/api/telemetry-sources", methods=["GET", "POST"])
@role_required("viewer")
def telemetry_sources_api():
    db = get_db()
    if request.method == "GET":
        rows = db.execute("SELECT * FROM telemetry_sources ORDER BY name").fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["components"] = [
                component["component_id"] for component in db.execute(
                    "SELECT component_id FROM telemetry_components WHERE source_id=? ORDER BY component_id", (row["id"],)
                ).fetchall()
            ]
            item["quality_score"] = round(sum(int(item[field]) for field in QUALITY_FIELDS) / (len(QUALITY_FIELDS) * 5) * 100, 1)
            result.append(item)
        return jsonify(result)
    if ROLE_LEVELS[g.current_user["role"]] < ROLE_LEVELS["editor"]:
        return jsonify({"error": "Editor role required"}), 403
    try:
        data, components = _telemetry_payload(request.get_json(silent=True) or {})
    except (ValueError, TypeError) as exc:
        return jsonify({"error": str(exc)}), 400
    columns = list(data)
    cursor = db.execute(
        f"INSERT INTO telemetry_sources ({','.join(columns)}) VALUES ({','.join('?' for _ in columns)})",
        [data[column] for column in columns],
    )
    source_id = cursor.lastrowid
    db.executemany(
        "INSERT INTO telemetry_components (source_id, component_id) VALUES (?, ?)",
        [(source_id, component_id) for component_id in components],
    )
    write_audit_log(db, "create", "telemetry_source", str(source_id), f"components={len(components)}", after={**data, "components": components})
    db.commit()
    return jsonify({"id": source_id}), 201


@app.route("/api/telemetry-sources/<int:source_id>", methods=["PUT", "DELETE"])
@role_required("editor")
def telemetry_source_api(source_id: int):
    db = get_db()
    existing = db.execute("SELECT * FROM telemetry_sources WHERE id=?", (source_id,)).fetchone()
    if not existing:
        return jsonify({"error": "Telemetry source not found"}), 404
    before = dict(existing)
    before["components"] = [row["component_id"] for row in db.execute("SELECT component_id FROM telemetry_components WHERE source_id=?", (source_id,)).fetchall()]
    if request.method == "DELETE":
        db.execute("DELETE FROM telemetry_components WHERE source_id=?", (source_id,))
        db.execute("DELETE FROM telemetry_sources WHERE id=?", (source_id,))
        write_audit_log(db, "delete", "telemetry_source", str(source_id), before=before)
        db.commit()
        return jsonify({"ok": True})
    merged = {**before, **(request.get_json(silent=True) or {})}
    try:
        data, components = _telemetry_payload(merged)
    except (ValueError, TypeError) as exc:
        return jsonify({"error": str(exc)}), 400
    assignments = ",".join(f"{column}=?" for column in data)
    db.execute(
        f"UPDATE telemetry_sources SET {assignments}, updated_at=CURRENT_TIMESTAMP WHERE id=?",
        [data[column] for column in data] + [source_id],
    )
    db.execute("DELETE FROM telemetry_components WHERE source_id=?", (source_id,))
    db.executemany(
        "INSERT INTO telemetry_components (source_id, component_id) VALUES (?, ?)",
        [(source_id, component_id) for component_id in components],
    )
    after = {**data, "components": components}
    write_audit_log(db, "update", "telemetry_source", str(source_id), f"components={len(components)}", before=before, after=after)
    db.commit()
    return jsonify({"id": source_id})


@app.route("/api/soc-profiles/<int:profile_id>/visibility/<tech_id>", methods=["PUT", "DELETE"])
@role_required("admin")
def visibility_override_api(profile_id: int, tech_id: str):
    db = get_db()
    tech_id = tech_id.upper()
    if not db.execute("SELECT 1 FROM soc_profile_techniques WHERE profile_id=? AND tech_id=?", (profile_id, tech_id)).fetchone():
        return jsonify({"error": "Technique is not in the profile"}), 404
    before_row = db.execute("SELECT * FROM visibility_overrides WHERE profile_id=? AND tech_id=?", (profile_id, tech_id)).fetchone()
    if request.method == "DELETE":
        db.execute("DELETE FROM visibility_overrides WHERE profile_id=? AND tech_id=?", (profile_id, tech_id))
        write_audit_log(db, "delete", "visibility_override", f"{profile_id}:{tech_id}", before=dict(before_row) if before_row else None)
        db.commit()
        return jsonify({"ok": True})
    payload = request.get_json(silent=True) or {}
    score = int(payload.get("score", -1))
    reason = str(payload.get("reason", "")).strip()
    if score < 0 or score > 4 or not reason:
        return jsonify({"error": "Score 0-4 and an approval reason are required"}), 400
    db.execute(
        """
        INSERT INTO visibility_overrides (profile_id, tech_id, score, reason, approved_by, updated_at)
        VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(profile_id, tech_id) DO UPDATE SET score=excluded.score,
            reason=excluded.reason, approved_by=excluded.approved_by, updated_at=CURRENT_TIMESTAMP
        """,
        (profile_id, tech_id, score, reason, g.current_user["username"]),
    )
    after = dict(db.execute("SELECT * FROM visibility_overrides WHERE profile_id=? AND tech_id=?", (profile_id, tech_id)).fetchone())
    write_audit_log(db, "override", "visibility", f"{profile_id}:{tech_id}", f"score={score}", before=dict(before_row) if before_row else None, after=after)
    db.commit()
    return jsonify(after)


@app.route("/api/soc-kpi")
@role_required("viewer")
def soc_kpi_api():
    profile_id = request.args.get("profile_id", type=int)
    try:
        return jsonify(_compute_soc_kpis(get_db(), profile_id))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 404


@app.route("/api/soc-kpi/snapshots", methods=["POST"])
@role_required("admin")
def soc_kpi_snapshot_api():
    db = get_db()
    payload = request.get_json(silent=True) or {}
    profile_id = payload.get("profile_id")
    result = _compute_soc_kpis(db, int(profile_id) if profile_id else None)
    profile = result["profile"]
    if profile["status"] != "approved":
        return jsonify({"error": "Only an approved profile can produce an official snapshot"}), 409
    metrics = result["metrics"]
    created_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    snapshot_payload = {
        "profile": profile, "formula_version": KPI_FORMULA_VERSION,
        "metrics": metrics, "techniques": result["techniques"], "created_at": created_at,
    }
    payload_json = json.dumps(snapshot_payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    payload_hash = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()
    numerator = {
        "mapped": metrics["mapped_techniques"], "validated": metrics["validated_techniques"],
        "visible": metrics["visible_techniques"],
    }
    cursor = db.execute(
        """
        INSERT INTO kpi_snapshots (
            profile_id, profile_version, formula_version, attack_version, scope,
            mapped_coverage, validated_coverage, weighted_detection, visibility,
            visible_threshold_coverage, numerator_json, denominator, payload_json,
            payload_hash, created_by, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            profile["id"], profile["version"], KPI_FORMULA_VERSION, profile["attack_version"], profile["scope"],
            metrics["mapped_coverage"], metrics["validated_coverage"], metrics["weighted_detection"], metrics["visibility"],
            metrics["visible_threshold_coverage"], json.dumps(numerator), metrics["denominator"], payload_json,
            payload_hash, g.current_user["username"], created_at,
        ),
    )
    write_audit_log(db, "snapshot", "soc_kpi", str(cursor.lastrowid), f"profile={profile['id']};hash={payload_hash}", after={"metrics": metrics, "payload_hash": payload_hash})
    db.commit()
    return jsonify({"id": cursor.lastrowid, "payload_hash": payload_hash, "metrics": metrics}), 201


@app.route("/api/soc-kpi/snapshots/<int:snapshot_id>")
@role_required("viewer")
def soc_kpi_snapshot_detail_api(snapshot_id: int):
    row = get_db().execute("SELECT * FROM kpi_snapshots WHERE id=?", (snapshot_id,)).fetchone()
    if not row:
        return jsonify({"error": "Snapshot not found"}), 404
    item = dict(row)
    calculated_hash = hashlib.sha256(item["payload_json"].encode("utf-8")).hexdigest()
    item["integrity"] = {"valid": calculated_hash == item["payload_hash"], "calculated_hash": calculated_hash}
    item["payload"] = json.loads(item.pop("payload_json"))
    item["numerator"] = json.loads(item.pop("numerator_json"))
    return jsonify(item)


@app.route("/api/soc-kpi/layer")
@role_required("viewer")
def soc_kpi_layer_api():
    mode = request.args.get("mode", "combined")
    if mode not in {"combined", "detection", "visibility"}:
        return jsonify({"error": "mode must be combined, detection or visibility"}), 400
    profile_id = request.args.get("profile_id", type=int)
    result = _compute_soc_kpis(get_db(), profile_id)
    techniques = []
    colors = {
        "controlled": "#376b18", "detection_gap": "#9a5b00",
        "visibility_risk": "#a4262c", "blind_spot": "#3b3a39",
    }
    for item in result["techniques"]:
        if mode == "detection":
            score = item["detection_score"] * 20
            color = ""
        elif mode == "visibility":
            score = item["visibility_score"] * 25
            color = ""
        else:
            score = round((item["detection_score"] / 5 + item["visibility_score"] / 4) * 50, 1)
            color = colors[item["gap_state"]]
        technique = {
            "techniqueID": item["tech_id"], "score": score,
            "comment": f"Detection {item['detection_score']}/5; Visibility {item['visibility_score']}/4; {item['gap_state']}",
            "enabled": True,
        }
        if color:
            technique["color"] = color
        techniques.append(technique)
    layer = {
        "name": f"{result['profile']['name']} - {mode}",
        "versions": {"navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": f"SOC-CMM {mode} KPI; formula {KPI_FORMULA_VERSION}; profile v{result['profile']['version']}",
        "techniques": techniques,
        "gradient": {"colors": ["#3b3a39", "#9a5b00", "#107c10"], "minValue": 0, "maxValue": 100},
        "metadata": [
            {"name": "profile_id", "value": str(result["profile"]["id"])},
            {"name": "formula_version", "value": KPI_FORMULA_VERSION},
            {"name": "attack_version", "value": result["profile"]["attack_version"]},
        ],
    }
    return jsonify(layer)


@app.route("/api/technique-config/<tech_id>", methods=["PUT"])
@role_required("admin")
def update_technique_config(tech_id: str):
    """Admin'in bir teknik için importance ve rule_threshold'u el ile ayarlamasına izin verir.
    importance_level (1-5 INT) kabul eder ve float'a çevirir."""
    payload = request.get_json(silent=True) or {}
    if "importance_level" in payload:
        level = max(1, min(5, int(payload["importance_level"])))
        importance = _LEVEL_TO_FLOAT[level]
    else:
        importance = float(payload.get("importance", 0.5))
    rule_threshold = int(payload.get("rule_threshold", 3))
    importance = max(0.1, min(1.0, importance))
    rule_threshold = max(1, min(10, rule_threshold))
    db = get_db()
    db.execute(
        "UPDATE technique_config SET importance=?, rule_threshold=?, source='admin' WHERE tech_id=?",
        (importance, rule_threshold, tech_id.upper()),
    )
    # teknik henüz tabloda yoksa INSERT
    db.execute(
        "INSERT OR IGNORE INTO technique_config "
        "(tech_id, importance, rule_threshold, source) VALUES (?,?,?,'admin')",
        (tech_id.upper(), importance, rule_threshold),
    )
    write_audit_log(
        db,
        action="update",
        target_type="technique_config",
        target_id=tech_id.upper(),
        detail=f"importance={importance};rule_threshold={rule_threshold}",
    )
    _invalidate_ttp_cache()
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/gap-analysis")
@role_required("viewer")
def gap_analysis_api():
    if not MITRE_PATH.exists():
        return jsonify({"error": "MITRE data not found"}), 500
    try:
        mitre = get_minified_mitre()
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500
    db = get_db()
    try:
        result = _compute_gap_analysis(mitre, db)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500
    return jsonify(result)


@app.route("/api/threat-actors")
@role_required("viewer")
def threat_actors_api():
    if not MITRE_PATH.exists():
        return jsonify({"error": "MITRE data not found"}), 500
    try:
        actors = _get_threat_actors()
        return jsonify(actors)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/action-items", methods=["GET", "POST"])
@role_required("viewer")
def action_items_api():
    db = get_db()
    if request.method == "GET":
        status_filter = request.args.get("status", "").strip()
        tech_id_filter = request.args.get("tech_id", "").strip()
        query = """
            SELECT ai.id, ai.tech_id, ai.title, ai.description, ai.priority,
                   ai.status, ai.assigned_team_id, ai.due_date,
                   ai.created_by_username, ai.created_at, ai.updated_at,
                   t.name AS assigned_team_name
            FROM action_items ai
            LEFT JOIN teams t ON t.id = ai.assigned_team_id
            WHERE 1=1
        """
        params: list = []
        if status_filter:
            query += " AND ai.status = ?"
            params.append(status_filter)
        if tech_id_filter:
            query += " AND ai.tech_id = ?"
            params.append(tech_id_filter.upper())
        query += " ORDER BY ai.priority DESC, ai.created_at DESC"
        rows = db.execute(query, params).fetchall()
        return jsonify([dict(r) for r in rows])

    # POST — create
    if ROLE_LEVELS[g.current_user["role"]] < ROLE_LEVELS["editor"]:
        return jsonify({"error": "Forbidden"}), 403

    payload = request.get_json(silent=True) or {}
    title = (payload.get("title") or "").strip()
    if not title:
        return jsonify({"error": "Missing fields: title"}), 400

    tech_id = (payload.get("tech_id") or "").strip().upper()
    description = (payload.get("description") or "").strip()
    try:
        priority = max(1, min(4, int(payload.get("priority", 2))))
    except (ValueError, TypeError):
        priority = 2
    status = payload.get("status", "open")
    if status not in ("open", "in_progress", "done", "cancelled"):
        status = "open"
    assigned_team_id = payload.get("assigned_team_id")
    if assigned_team_id is not None:
        try:
            assigned_team_id = int(assigned_team_id)
        except (ValueError, TypeError):
            assigned_team_id = None
    due_date = (payload.get("due_date") or "").strip() or None

    cur = db.execute(
        """INSERT INTO action_items
           (tech_id, title, description, priority, status, assigned_team_id, due_date, created_by_username)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (tech_id, title, description, priority, status, assigned_team_id, due_date,
         g.current_user["username"]),
    )
    write_audit_log(
        db, action="create", target_type="action_item",
        target_id=str(cur.lastrowid),
        detail=f"title={title};tech_id={tech_id};priority={priority}",
        after={
            "tech_id": tech_id, "title": title, "description": description,
            "priority": priority, "status": status,
            "assigned_team_id": assigned_team_id, "due_date": due_date,
        },
    )
    db.commit()

    item = db.execute(
        """SELECT ai.id, ai.tech_id, ai.title, ai.description, ai.priority,
                  ai.status, ai.assigned_team_id, ai.due_date,
                  ai.created_by_username, ai.created_at, ai.updated_at,
                  t.name AS assigned_team_name
           FROM action_items ai
           LEFT JOIN teams t ON t.id = ai.assigned_team_id
           WHERE ai.id = ?""",
        (cur.lastrowid,),
    ).fetchone()
    return jsonify(dict(item)), 201


@app.route("/api/action-items/<int:item_id>", methods=["PUT", "DELETE"])
@role_required("editor")
def action_item_detail(item_id: int):
    db = get_db()
    row = db.execute("SELECT * FROM action_items WHERE id = ?", (item_id,)).fetchone()
    if not row:
        return jsonify({"error": "Not found"}), 404

    if request.method == "DELETE":
        db.execute("DELETE FROM action_items WHERE id = ?", (item_id,))
        write_audit_log(
            db, action="delete", target_type="action_item",
            target_id=str(item_id), before=dict(row),
        )
        db.commit()
        return jsonify({"ok": True})

    # PUT — update
    payload = request.get_json(silent=True) or {}
    title = (payload.get("title") or row["title"]).strip()
    tech_id = (payload["tech_id"] if "tech_id" in payload else row["tech_id"] or "").strip().upper()
    description = payload.get("description") if "description" in payload else (row["description"] or "")
    try:
        priority = max(1, min(4, int(payload.get("priority", row["priority"]))))
    except (ValueError, TypeError):
        priority = row["priority"]
    status = payload.get("status", row["status"])
    if status not in ("open", "in_progress", "done", "cancelled"):
        status = row["status"]
    assigned_team_id = payload.get("assigned_team_id", row["assigned_team_id"])
    if assigned_team_id is not None:
        try:
            assigned_team_id = int(assigned_team_id)
        except (ValueError, TypeError):
            assigned_team_id = None
    due_date = payload.get("due_date", row["due_date"]) or None

    db.execute(
        """UPDATE action_items SET tech_id=?, title=?, description=?, priority=?,
           status=?, assigned_team_id=?, due_date=?,
           updated_at=CURRENT_TIMESTAMP WHERE id=?""",
        (tech_id, title, description, priority, status, assigned_team_id, due_date, item_id),
    )
    write_audit_log(
        db, action="update", target_type="action_item",
        target_id=str(item_id),
        detail=f"status={status};priority={priority}",
        before=dict(row),
        after={
            "id": item_id, "tech_id": tech_id, "title": title,
            "description": description, "priority": priority, "status": status,
            "assigned_team_id": assigned_team_id, "due_date": due_date,
        },
    )
    db.commit()
    return jsonify({"ok": True})


@app.route("/report")
@login_required
def report_page():
    """Yönetici raporu — GAP verileri ve aksiyon planı."""
    from datetime import datetime

    gap_data: dict = {"overview": {}, "by_tactic": [], "critical_gaps": []}
    action_items_data: list = []

    try:
        if MITRE_PATH.exists():
            mitre = get_minified_mitre()
            db = get_db()
            gap_data = _compute_gap_analysis(mitre, db)
            rows = db.execute(
                """SELECT ai.id, ai.tech_id, ai.title, ai.priority, ai.status,
                          ai.due_date, t.name AS team_name
                   FROM action_items ai
                   LEFT JOIN teams t ON t.id = ai.assigned_team_id
                   WHERE ai.status IN ('open', 'in_progress')
                   ORDER BY ai.priority DESC, ai.created_at DESC"""
            ).fetchall()
            action_items_data = [dict(r) for r in rows]
    except Exception:
        pass

    priority_labels = {1: "Düşük", 2: "Orta", 3: "Yüksek", 4: "Kritik"}
    status_labels = {"open": "Açık", "in_progress": "Devam", "done": "Tamamlandı", "cancelled": "İptal"}

    return render_template(
        "report.html",
        gap=gap_data,
        action_items=action_items_data,
        priority_labels=priority_labels,
        status_labels=status_labels,
        generated_at=datetime.utcnow().strftime("%d.%m.%Y %H:%M UTC"),
        current_user=g.current_user,
    )


if __name__ == "__main__":
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    init_db()
    host = os.environ.get("SOC_HOST", "0.0.0.0")
    port = int(os.environ.get("SOC_PORT", "8000"))
    app.run(host=host, port=port, debug=True)
