from __future__ import annotations

import json
import os
import sqlite3
from functools import wraps
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, request, render_template, g, session, redirect, url_for
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = BASE_DIR / "soc.db"
MITRE_PATH = DATA_DIR / "mitre.json"
SEED_RULES_PATH = DATA_DIR / "rules_seed.json"
LEGACY_SOC_HTML = BASE_DIR / "SOC.html"

app = Flask(__name__)
app.config["JSON_AS_ASCII"] = False
app.config["JSONIFY_MIMETYPE"] = "application/json; charset=utf-8"
app.secret_key = os.environ.get("SOC_SECRET_KEY", "change-this-in-production")


MITRE_CACHE = {"mtime": None, "data": None}
THREAT_ACTOR_CACHE: dict[str, Any] = {"mtime": None, "data": None}
TTP_LIST_CACHE: dict[str, Any] = {"data": None, "dirty": True}
ROLE_LEVELS = {"viewer": 1, "editor": 2, "admin": 3}

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
        migrate_rule_techniques(db)
        migrate_consolidate_rules(db)
        build_technique_config(db)
    finally:
        db.close()


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
) -> None:
    actor = user or getattr(g, "current_user", None)
    user_id = actor["id"] if actor else None
    username = actor["username"] if actor else ""
    db.execute(
        """
        INSERT INTO audit_logs (user_id, username, action, target_type, target_id, detail)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (user_id, username, action, target_type, target_id, detail),
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

    rule_count_by_tech = {
        r["tech_id"]: r["cnt"]
        for r in db.execute(
            "SELECT tech_id, COUNT(DISTINCT rule_id) AS cnt FROM rule_techniques GROUP BY tech_id"
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
        rule_count = rule_count_by_tech.get(teid, 0)
        mits_for_tech = tech_to_mitigations.get(teid, set())
        mitigation_checked = bool(mits_for_tech & covered_mits)
        # Detection (kural) zorunlu — yalnızca mitigation kapsama saymaz
        covered = rule_count > 0
        tc = tech_config.get(teid, {})
        importance = tc.get("importance", 0.5)
        imp_level = _importance_to_level(importance)
        all_techs.append({
            "tech_id": teid,
            "name": info["name"],
            "is_subtechnique": info["is_subtechnique"],
            "tactics": info["tactics"],
            "rule_count": rule_count,
            "mitigation_checked": mitigation_checked,
            "covered": covered,
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
    # Kritik boşluklar: parent + alt teknikler, önem ≥ 4, kapsanmamış
    critical_gaps_list = [t for t in all_techs if t["importance_level"] >= 4 and not t["covered"]]
    # Genel kapsama % — tüm teknikler (parent + alt)
    coverage_pct = round(covered_all / total_all * 100, 1) if total_all else 0.0

    # Taktik bazlı: parent + alt teknikler birlikte
    by_tactic_map: dict[str, dict] = {}
    for t in all_techs:
        for tactic in t["tactics"]:
            entry = by_tactic_map.setdefault(tactic, {"total": 0, "covered": 0})
            entry["total"] += 1
            if t["covered"]:
                entry["covered"] += 1

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
    row = db.execute(
        "SELECT id, username, password_hash, role, is_active FROM users WHERE username = ?",
        (username,),
    ).fetchone()
    if not row or not row["is_active"] or not check_password_hash(row["password_hash"], password):
        return jsonify({"error": "Invalid credentials"}), 401
    session.clear()
    session["user_id"] = row["id"]
    write_audit_log(
        db,
        action="login",
        target_type="session",
        target_id=str(row["id"]),
        detail="Login successful",
        user={"id": row["id"], "username": row["username"]},
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
            SELECT r.id, r.name, r.tactic, r.tech, r.source,
                   GROUP_CONCAT(rt.tech_id) as techs
            FROM rules r
            LEFT JOIN rule_techniques rt ON rt.rule_id = r.id
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
    write_audit_log(
        db,
        action="create",
        target_type="rule",
        target_id=str(cur.lastrowid),
        detail=f"name={name};tech={tech or '-'};source={source}",
    )
    _invalidate_ttp_cache()
    db.commit()
    return jsonify({"id": cur.lastrowid, "name": name, "tactic": tactic, "tech": tech, "source": source, "techniques": [tech] if tech else []}), 201




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


@app.route("/api/rules/<int:rule_id>", methods=["DELETE"])
@role_required("editor")
def delete_rule(rule_id: int):
    db = get_db()
    db.execute("DELETE FROM rule_techniques WHERE rule_id = ?", (rule_id,))
    db.execute("DELETE FROM rules WHERE id = ?", (rule_id,))
    write_audit_log(db, action="delete", target_type="rule", target_id=str(rule_id))
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
    db.execute("DELETE FROM products WHERE id = ?", (product_id,))
    write_audit_log(db, action="delete", target_type="product", target_id=str(product_id))
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
    db.execute("UPDATE products SET color = ? WHERE id = ?", (color, product_id))
    write_audit_log(
        db,
        action="update",
        target_type="product",
        target_id=str(product_id),
        detail=f"color={color}",
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
    db.execute("DELETE FROM teams WHERE id = ?", (team_id,))
    write_audit_log(
        db, action="delete", target_type="team", target_id=str(team_id)
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
    )
    _invalidate_ttp_cache()
    db.commit()
    return jsonify({"id": cur.lastrowid, "mitigation_id": mitigation_id, "team": team, "comment": comment}), 201


@app.route("/api/mitigation-entries/<int:entry_id>", methods=["DELETE"])
@role_required("editor")
def delete_mitigation_entry(entry_id: int):
    db = get_db()
    db.execute("DELETE FROM mitigation_entries WHERE id = ?", (entry_id,))
    write_audit_log(
        db,
        action="delete",
        target_type="mitigation_entry",
        target_id=str(entry_id),
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
    )
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/audit-logs", methods=["GET"])
@role_required("admin")
def audit_logs_api():
    db = get_db()
    limit_raw = request.args.get("limit", "200")
    try:
        limit = max(1, min(1000, int(limit_raw)))
    except ValueError:
        limit = 200

    rows = db.execute(
        """
        SELECT id, user_id, username, action, target_type, target_id, detail, created_at
        FROM audit_logs
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    return jsonify([dict(r) for r in rows])

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

    if request.method == "DELETE":
        db.execute("DELETE FROM action_items WHERE id = ?", (item_id,))
        write_audit_log(db, action="delete", target_type="action_item", target_id=str(item_id))
        db.commit()
        return jsonify({"ok": True})

    # PUT — update
    row = db.execute("SELECT * FROM action_items WHERE id = ?", (item_id,)).fetchone()
    if not row:
        return jsonify({"error": "Not found"}), 404

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
